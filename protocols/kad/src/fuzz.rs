//! Action-sequence fuzz driver for Kademlia [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Injects swarm / handler events and keeps
//! live [`Handler`]s with mock streams so libFuzzer reaches k-buckets, record
//! store, query logic, jobs, codec framing, **and** ConnectionHandler poll.

use std::{
    collections::HashMap,
    num::NonZeroUsize,
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::{Decoder, Encoder};
use bytes::BytesMut;
use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionId, NetworkBehaviour, StreamProtocol, ToSwarm,
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
};
use prost::Message as _;

use crate::{
    Behaviour, Caching, Config, ConnectionType, KadPeer, QueryId, Quorum, Record, RecordKey,
    RoutingUpdate,
    fuzz_handler::{ChunkFeed, WriteFault, attach_live_inbound_ex, pump_handler},
    handler::{Handler, HandlerEvent, HandlerQueryErr, RequestId},
    protocol::{Codec, KadRequestMsg, KadResponseMsg},
    proto,
    record::store::{MemoryStore, MemoryStoreConfig, RecordStore},
};

/// Cap how many actions one fuzz input may drive.
pub const MAX_ACTIONS: usize = 64;
/// Cap inbound protobuf message size.
pub const MAX_MSG_BYTES: usize = 4 * 1024;
/// Cap record value / key material size.
pub const MAX_DATA_BYTES: usize = 512;
/// Fixed peer pool so connect / inject / disconnect correlate.
pub const PEER_POOL: usize = 8;
/// Bound polls drained after each action.
const MAX_POLL_DRAIN: usize = 256;

/// Well-formed DHT request kinds for coverage of cold inbound handler arms.
#[derive(Clone, Copy, Debug)]
pub enum StructuredInboundKind {
    FindNode,
    GetProviders,
    GetValue,
    PutValue,
    AddProvider,
}

/// Outbound-query response kinds injected after a local query is started.
#[derive(Clone, Copy, Debug)]
pub enum StructuredResponseKind {
    FindNodeRes,
    GetProvidersRes,
    /// Record found at peer.
    GetRecordRes,
    /// Empty record response — drives GetRecord toward [`crate::GetRecordError::NotFound`].
    GetRecordEmpty,
    PutRecordRes,
    QueryError,
}

/// Encode a minimal valid DHT protobuf [`Message`] for `kind`.
///
/// `provider` is required for [`StructuredInboundKind::AddProvider`] (must be a
/// valid peer id); ignored otherwise.
pub fn encode_structured_inbound(
    kind: StructuredInboundKind,
    key_slot: u8,
    provider: Option<PeerId>,
) -> Vec<u8> {
    let key = key_bytes(key_slot);
    let msg = match kind {
        StructuredInboundKind::FindNode => proto::Message {
            r#type: proto::MessageType::FindNode as i32,
            key,
            cluster_level_raw: 10,
            ..Default::default()
        },
        StructuredInboundKind::GetProviders => proto::Message {
            r#type: proto::MessageType::GetProviders as i32,
            key,
            cluster_level_raw: 10,
            ..Default::default()
        },
        StructuredInboundKind::GetValue => proto::Message {
            r#type: proto::MessageType::GetValue as i32,
            key,
            cluster_level_raw: 10,
            ..Default::default()
        },
        StructuredInboundKind::PutValue => proto::Message {
            r#type: proto::MessageType::PutValue as i32,
            key: key.clone(),
            record: Some(proto::Record {
                key,
                value: vec![key_slot; 32],
                time_received: String::new(),
                publisher: Vec::new(),
                ttl: 60,
            }),
            ..Default::default()
        },
        StructuredInboundKind::AddProvider => {
            let peer = provider.unwrap_or_else(|| PeerId::from(Keypair::generate_ed25519().public()));
            proto::Message {
                r#type: proto::MessageType::AddProvider as i32,
                key,
                cluster_level_raw: 10,
                provider_peers: vec![proto::Peer {
                    id: peer.to_bytes(),
                    addrs: vec![peer_addr(key_slot).to_vec()],
                    connection: proto::ConnectionType::Connected as i32,
                }],
                ..Default::default()
            }
        }
    };
    msg.encode_to_vec()
}

/// Encode `kind` as an unsigned-varint length-prefixed wire frame via [`Codec`].
pub fn encode_structured_wire(
    kind: StructuredInboundKind,
    key_slot: u8,
    provider: Option<PeerId>,
) -> Vec<u8> {
    let inner = encode_structured_inbound(kind, key_slot, provider);
    let Ok(msg) = proto::Message::decode(inner.as_slice()) else {
        return Vec::new();
    };
    let Ok(req) = KadRequestMsg::try_from(msg) else {
        return Vec::new();
    };
    let mut codec = Codec::<KadRequestMsg, KadResponseMsg>::new(MAX_MSG_BYTES);
    let mut buf = BytesMut::new();
    if codec.encode(req, &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

/// Structured action produced by the cargo-fuzz harness (via `arbitrary`).
#[derive(Clone, Debug)]
pub enum FuzzAction {
    /// Establish inbound/outbound connection for `peer_slot % PEER_POOL`.
    Connect { peer_slot: u8, outbound: bool },
    /// Close all tracked connections for a peer slot.
    Disconnect { peer_slot: u8 },
    /// Confirm Kad protocol support (adds peer to routing table when dialer).
    ProtocolConfirmed { peer_slot: u8 },
    /// Inject an inbound Kad RPC decoded from protobuf bytes.
    InjectInbound { peer_slot: u8, msg_bytes: Vec<u8> },
    /// Inject a well-formed inbound request (provider id = source peer for AddProvider).
    InjectStructured {
        peer_slot: u8,
        kind: StructuredInboundKind,
        key_slot: u8,
    },
    /// Length-prefixed wire bytes → [`Codec`] decode → [`HandlerEvent`].
    InjectWire { peer_slot: u8, wire_bytes: Vec<u8> },
    /// Locally remember an address for a peer (routing-table seed).
    AddAddress { peer_slot: u8 },
    /// Start a get-closest-peers query for a key derived from `key_slot`.
    GetClosestPeers { key_slot: u8 },
    /// Put a local record (key/value slots). `quorum_all` selects [`Quorum::All`]
    /// (else [`Quorum::One`]) to exercise [`crate::PutRecordError::QuorumFailed`].
    PutRecord {
        key_slot: u8,
        value: Vec<u8>,
        quorum_all: bool,
    },
    /// Put a record to a fixed peer set via [`Behaviour::put_record_to`] (skips
    /// get-closest). Prefer with `quorum_all` + incomplete `PutRecordRes` /
    /// `QueryError` for QuorumFailed.
    PutRecordTo {
        key_slot: u8,
        value: Vec<u8>,
        quorum_all: bool,
        /// How many peer-pool slots (1..=PEER_POOL) to include as targets.
        peer_count: u8,
    },
    /// Look up a record by key slot.
    GetRecord { key_slot: u8 },
    /// Announce as provider for a key (cold path in prior coverage).
    StartProviding { key_slot: u8 },
    /// Start a get-providers query (pairs with [`StructuredResponseKind::GetProvidersRes`]).
    GetProviders { key_slot: u8 },
    /// Inject a response `HandlerEvent` for a previously started outbound query.
    ///
    /// Query attribution:
    /// - `query_slot == 0` → newest active query (prior `.last()` behaviour)
    /// - `query_slot > 0` → walk older entries in the ring (concurrent confusion)
    /// - `mismatch` → ghost [`QueryId`] never issued by the Behaviour
    InjectResponse {
        peer_slot: u8,
        kind: StructuredResponseKind,
        /// Peer-pool slot used to populate `closer_peers` / `provider_peers`.
        closer_slot: u8,
        /// Index from newest (`0`) toward older queries (`% active.len()`).
        query_slot: u8,
        /// If true, inject a never-issued [`QueryId`] (stale / confused attribution).
        mismatch: bool,
    },
    /// Cut short put/add-provider job delays; next poll runs `jobs.rs`.
    AdvanceJobs,
    /// Rewind in-flight query starts by `ms` so the next drain can emit Timeout.
    AdvanceQueryClock { ms: u16 },
    /// Trigger bootstrap (no-op if routing table empty).
    Bootstrap,
}

/// Pre-populated starting state so a fuzz input can skip the `Connect` / RT / store
/// warm-up preamble and jump straight into mid-protocol transitions (deep query
/// states, nearly-full kbuckets, pre-loaded records).
#[derive(Clone, Copy, Debug, Default)]
pub struct FuzzSeed {
    /// Pre-`add_address` this many peer-pool peers into the routing table.
    pub rt_peers: u8,
    /// Pre-`put` this many records into the local store (GetRecord hits vs NotFound).
    pub store_records: u8,
    /// Pre-establish this many outbound connections + ProtocolConfirmed handlers.
    pub live_peers: u8,
}

/// Drive [`Behaviour`] with a sequence of actions.
///
/// Invariants: never panics; always terminates (bounded actions + poll drain).
/// Soft budgets on connected peers / kbucket occupancy / query pool size.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    fuzz_behaviour_seeded(FuzzSeed::default(), actions);
}

/// [`fuzz_behaviour`] with a [`FuzzSeed`] pre-population step.
pub fn fuzz_behaviour_seeded(seed: FuzzSeed, actions: impl IntoIterator<Item = FuzzAction>) {
    let local_id = fuzz_local_peer_id();

    let mut config = Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
    config
        .set_kbucket_size(NonZeroUsize::new(4).expect("4 != 0"))
        .set_replication_factor(NonZeroUsize::new(3).expect("3 != 0"))
        // Parallelism ≥ 2 so ClosestDisjointPeersIter builds multiple paths.
        .set_parallelism(NonZeroUsize::new(3).expect("3 != 0"))
        .disjoint_query_paths(true)
        .set_max_packet_size(4 * 1024)
        // Long wall timeout; Timeout is driven by AdvanceQueryClock (deterministic).
        .set_query_timeout(Duration::from_secs(60))
        .set_substreams_timeout(Duration::from_secs(1))
        .set_record_ttl(Some(Duration::from_secs(60)))
        // Enable periodic jobs; delays are cut short via AdvanceJobs / fuzz_jobs_asap.
        .set_replication_interval(Some(Duration::from_secs(3600)))
        .set_publication_interval(Some(Duration::from_secs(7200)))
        .set_provider_publication_interval(Some(Duration::from_secs(3600)))
        .set_periodic_bootstrap_interval(None)
        .set_caching(Caching::Enabled { max_peers: 2 });

    let store = MemoryStore::with_config(
        local_id,
        MemoryStoreConfig {
            max_records: 64,
            max_value_bytes: MAX_DATA_BYTES,
            max_providers_per_key: 4,
            max_provided_keys: 32,
        },
    );

    let mut kad = Behaviour::with_config(local_id, store, config);
    let peers = peer_pool();
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>> = HashMap::new();
    let mut handlers: HashMap<PeerId, Handler> = HashMap::new();
    let mut inbound_feeds: HashMap<PeerId, ChunkFeed> = HashMap::new();
    let mut next_conn: usize = 1;
    let mut next_req: u64 = 1;
    // Outbound query ids for InjectResponse (ring buffer, newest last).
    let mut active_queries: Vec<QueryId> = Vec::new();
    // Peers successfully inserted into the RT via AddAddress (retention check).
    let mut routed_peers: std::collections::HashSet<PeerId> = std::collections::HashSet::new();

    // Seed pre-population: RT peers, store records, and pre-established live
    // connections/handlers so inputs skip the warm-up preamble.
    for slot in 0..(seed.rt_peers.min(PEER_POOL as u8)) {
        let peer = peers[slot as usize];
        if matches!(
            kad.add_address(&peer, peer_addr(slot)),
            RoutingUpdate::Success | RoutingUpdate::Pending
        ) {
            routed_peers.insert(peer);
        }
    }
    for slot in 0..(seed.store_records.min(64)) {
        let record = Record::new(RecordKey::new(&key_bytes(slot)), vec![slot; 32]);
        let _ = kad.store_mut().put(record);
    }
    for slot in 0..(seed.live_peers.min(PEER_POOL as u8)) {
        let peer = peers[slot as usize];
        let cid = ConnectionId::new_unchecked(next_conn);
        next_conn = next_conn.wrapping_add(1).max(1);
        let remote = peer_addr(slot);
        if let Ok(mut h) = kad.handle_established_outbound_connection(
            cid, peer, &remote, Endpoint::Dialer, PortUse::Reuse,
        ) {
            let endpoint = ConnectedPoint::Dialer {
                address: remote,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };
            let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
            kad.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: peer,
                connection_id: cid,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: other,
            }));
            conn_ids.entry(peer).or_default().push((cid, endpoint.clone()));
            let feed = attach_live_inbound_ex(&mut h, WriteFault::NONE);
            for ev in pump_handler(&mut h) {
                kad.on_connection_handler_event(peer, cid, ev);
            }
            // Confirm protocol so the peer enters the routing table (as the
            // Connect + ProtocolConfirmed preamble would).
            kad.on_connection_handler_event(
                peer,
                cid,
                HandlerEvent::ProtocolConfirmed { endpoint },
            );
            inbound_feeds.insert(peer, feed);
            handlers.insert(peer, h);
        }
    }

    for action in actions.into_iter().take(MAX_ACTIONS) {
        // Skip drain after starting an outbound query so InjectResponse can
        // still find the QueryId in the pool (drain would Timeout it first).
        let started_query = matches!(
            &action,
            FuzzAction::GetClosestPeers { .. }
                | FuzzAction::GetProviders { .. }
                | FuzzAction::GetRecord { .. }
                | FuzzAction::PutRecord { .. }
                | FuzzAction::PutRecordTo { .. }
                | FuzzAction::StartProviding { .. }
                | FuzzAction::Bootstrap
        );
        match action {
            FuzzAction::Connect {
                peer_slot,
                outbound,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let cid = ConnectionId::new_unchecked(next_conn);
                next_conn = next_conn.wrapping_add(1).max(1);
                let remote = peer_addr(peer_slot);

                let handler = if outbound {
                    kad.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    kad.handle_established_inbound_connection(
                        cid,
                        peer,
                        &Multiaddr::empty(),
                        &remote,
                    )
                };

                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: remote,
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::Reuse,
                    }
                } else {
                    ConnectedPoint::Listener {
                        local_addr: Multiaddr::empty(),
                        send_back_addr: remote,
                    }
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                kad.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids.entry(peer).or_default().push((cid, endpoint));

                if let Ok(mut h) = handler {
                    // ~20% of connects: write_cap=1 so Behaviour→Handler encode
                    // under backpressure is exercised on the live inbound duplex.
                    let write = if peer_slot % 5 == 0 {
                        WriteFault {
                            write_cap: 1,
                            stall_every: 0,
                            err_every: 0,
                            flush_stall_every: 2,
                            zero_progress_once: false,
                        }
                    } else {
                        WriteFault::NONE
                    };
                    let feed = attach_live_inbound_ex(&mut h, write);
                    for ev in pump_handler(&mut h) {
                        kad.on_connection_handler_event(peer, cid, ev);
                    }
                    inbound_feeds.insert(peer, feed);
                    handlers.insert(peer, h);
                }
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                handlers.remove(&peer);
                inbound_feeds.remove(&peer);
                let mut remaining = ids.len();
                for (cid, endpoint) in ids {
                    remaining = remaining.saturating_sub(1);
                    kad.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
                // Contract: ConnectionClosed does not purge AddAddress'd peers.
                if routed_peers.contains(&peer) {
                    assert!(
                        kad.fuzz_routing_table_contains(&peer),
                        "AddAddress'd peer purged from RT after ConnectionClosed: {peer}"
                    );
                }
            }
            FuzzAction::ProtocolConfirmed { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, endpoint)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                kad.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::ProtocolConfirmed { endpoint },
                );
            }
            FuzzAction::InjectInbound {
                peer_slot,
                msg_bytes,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let bytes = if msg_bytes.len() > MAX_MSG_BYTES {
                    &msg_bytes[..MAX_MSG_BYTES]
                } else {
                    &msg_bytes
                };
                if let (Some(feed), Some(h)) =
                    (inbound_feeds.get(&peer), handlers.get_mut(&peer))
                {
                    // Feed the raw protobuf through the handler's inbound codec
                    // as a length-prefixed frame so it creates a real inbound
                    // substream with a real RequestId (matches the InjectStructured
                    // fix; the direct path used a synthetic RequestId that had no
                    // substream, tripping `answer_pending_request`'s debug_assert).
                    if decode_inbound(bytes, RequestId::fuzz(0)).is_some() {
                        let mut wire = Vec::with_capacity(bytes.len() + 5);
                        push_varint(&mut wire, bytes.len() as u64);
                        wire.extend_from_slice(bytes);
                        feed.push(&wire);
                        for ev in pump_handler(h) {
                            kad.on_connection_handler_event(peer, cid, ev);
                        }
                    }
                } else {
                    let Some(event) = decode_inbound(bytes, RequestId::fuzz(next_req)) else {
                        continue;
                    };
                    next_req = next_req.wrapping_add(1);
                    kad.on_connection_handler_event(peer, cid, event);
                }
            }
            FuzzAction::InjectStructured {
                peer_slot,
                kind,
                key_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let wire = encode_structured_wire(kind, key_slot, Some(peer));
                if let (Some(feed), Some(h)) =
                    (inbound_feeds.get(&peer), handlers.get_mut(&peer))
                {
                    // Real path: feed the length-prefixed request through the
                    // handler's inbound codec so it creates an actual inbound
                    // substream with a real RequestId. The Behaviour's queued
                    // response can then be matched in `answer_pending_request`
                    // (previously the synthetic RequestId had no substream and
                    // tripped the handler's `debug_assert!`).
                    feed.push(&wire);
                    for ev in pump_handler(h) {
                        kad.on_connection_handler_event(peer, cid, ev);
                    }
                } else {
                    // No live handler for this peer — inject the decoded event
                    // directly. The queued response is dropped (no handler to
                    // deliver it to), so it cannot reach `answer_pending_request`.
                    let Some(event) = decode_wire(&wire, RequestId::fuzz(next_req)) else {
                        continue;
                    };
                    next_req = next_req.wrapping_add(1);
                    kad.on_connection_handler_event(peer, cid, event);
                }
            }
            FuzzAction::InjectWire {
                peer_slot,
                wire_bytes,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let bytes = if wire_bytes.len() > MAX_MSG_BYTES {
                    &wire_bytes[..MAX_MSG_BYTES]
                } else {
                    &wire_bytes
                };
                if let (Some(feed), Some(h)) =
                    (inbound_feeds.get(&peer), handlers.get_mut(&peer))
                {
                    feed.push(bytes);
                    for ev in pump_handler(h) {
                        kad.on_connection_handler_event(peer, cid, ev);
                    }
                } else {
                    let Some(event) = decode_wire(bytes, RequestId::fuzz(next_req)) else {
                        continue;
                    };
                    next_req = next_req.wrapping_add(1);
                    kad.on_connection_handler_event(peer, cid, event);
                }
            }
            FuzzAction::AddAddress { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                match kad.add_address(&peer, peer_addr(peer_slot)) {
                    RoutingUpdate::Success | RoutingUpdate::Pending => {
                        routed_peers.insert(peer);
                    }
                    RoutingUpdate::Failed => {}
                }
            }
            FuzzAction::GetClosestPeers { key_slot } => {
                let key = key_bytes(key_slot);
                let qid = kad.get_closest_peers(key);
                push_query(&mut active_queries, qid);
            }
            FuzzAction::PutRecord {
                key_slot,
                value,
                quorum_all,
            } => {
                let key = RecordKey::new(&key_bytes(key_slot));
                let value = if value.len() > MAX_DATA_BYTES {
                    value[..MAX_DATA_BYTES].to_vec()
                } else {
                    value
                };
                let record = Record::new(key, value);
                let quorum = if quorum_all {
                    Quorum::All
                } else {
                    Quorum::One
                };
                if let Ok(qid) = kad.put_record(record, quorum) {
                    push_query(&mut active_queries, qid);
                }
            }
            FuzzAction::PutRecordTo {
                key_slot,
                value,
                quorum_all,
                peer_count,
            } => {
                let key = RecordKey::new(&key_bytes(key_slot));
                let value = if value.len() > MAX_DATA_BYTES {
                    value[..MAX_DATA_BYTES].to_vec()
                } else {
                    value
                };
                let record = Record::new(key, value);
                let n = ((peer_count as usize) % PEER_POOL).max(1);
                let targets: Vec<PeerId> = peers.iter().take(n).copied().collect();
                let quorum = if quorum_all {
                    Quorum::All
                } else {
                    Quorum::One
                };
                let qid = kad.put_record_to(record, targets.into_iter(), quorum);
                push_query(&mut active_queries, qid);
            }
            FuzzAction::GetRecord { key_slot } => {
                let key = RecordKey::new(&key_bytes(key_slot));
                let qid = kad.get_record(key);
                push_query(&mut active_queries, qid);
            }
            FuzzAction::StartProviding { key_slot } => {
                let key = RecordKey::new(&key_bytes(key_slot));
                if let Ok(qid) = kad.start_providing(key) {
                    push_query(&mut active_queries, qid);
                }
            }
            FuzzAction::GetProviders { key_slot } => {
                let key = RecordKey::new(&key_bytes(key_slot));
                let qid = kad.get_providers(key);
                push_query(&mut active_queries, qid);
            }
            FuzzAction::InjectResponse {
                peer_slot,
                kind,
                closer_slot,
                query_slot,
                mismatch,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let Some(query_id) =
                    resolve_query_id(&active_queries, query_slot, mismatch)
                else {
                    continue;
                };
                let closer = kad_peer_from_slot(&peers, closer_slot);
                let event = match kind {
                    StructuredResponseKind::FindNodeRes => HandlerEvent::FindNodeRes {
                        closer_peers: vec![closer],
                        query_id,
                    },
                    StructuredResponseKind::GetProvidersRes => HandlerEvent::GetProvidersRes {
                        closer_peers: vec![closer.clone()],
                        // Empty provider set biases FinishedWithNoAdditionalRecord.
                        provider_peers: if closer_slot % 2 == 0 {
                            vec![closer]
                        } else {
                            vec![]
                        },
                        query_id,
                    },
                    StructuredResponseKind::GetRecordRes => HandlerEvent::GetRecordRes {
                        record: Some(Record::new(
                            RecordKey::new(&key_bytes(closer_slot)),
                            vec![closer_slot; 16],
                        )),
                        closer_peers: vec![closer],
                        query_id,
                    },
                    StructuredResponseKind::GetRecordEmpty => HandlerEvent::GetRecordRes {
                        record: None,
                        closer_peers: vec![],
                        query_id,
                    },
                    StructuredResponseKind::PutRecordRes => HandlerEvent::PutRecordRes {
                        key: RecordKey::new(&key_bytes(closer_slot)),
                        value: vec![closer_slot; 8],
                        query_id,
                    },
                    StructuredResponseKind::QueryError => HandlerEvent::QueryError {
                        error: HandlerQueryErr::UnexpectedMessage,
                        query_id,
                    },
                };
                kad.on_connection_handler_event(peer, cid, event);
            }
            FuzzAction::AdvanceJobs => {
                kad.fuzz_jobs_asap();
            }
            FuzzAction::AdvanceQueryClock { ms } => {
                // Cap so a single action can exceed the 60s fuzz query_timeout.
                let ms = u64::from(ms).max(1).min(120_000);
                kad.fuzz_advance_query_clock(Duration::from_millis(ms));
            }
            FuzzAction::Bootstrap => {
                if let Ok(qid) = kad.bootstrap() {
                    push_query(&mut active_queries, qid);
                }
            }
        }

        if !started_query {
            drain_polls(&mut kad, &mut handlers);
            pump_all_handlers(&mut kad, &mut handlers, &conn_ids);
        }
    }
    // Final drain: finish remaining queries / timeouts + handler response encode.
    drain_polls(&mut kad, &mut handlers);
    pump_all_handlers(&mut kad, &mut handlers, &conn_ids);

    let connected = kad.connected_peer_count();
    let queries = kad.query_count();
    let kb_entries = kad.kbucket_entry_count();
    // Hard asserts: cargo-fuzz builds --release, which strips `debug_assert!`.
    assert!(
        connected <= PEER_POOL.saturating_mul(4).saturating_add(8),
        "connected peers grew unboundedly: {connected}"
    );
    // After final AdvanceQueryClock drains + poll, queries should be reaped.
    assert!(
        queries <= MAX_ACTIONS,
        "queries not reaped / pool grew unboundedly: {queries}"
    );
    assert!(
        kb_entries <= 256,
        "kbucket entries grew unboundedly: {kb_entries}"
    );
    // End-of-run: every successfully AddAddress'd peer still in the RT
    // (ConnectionClosed must not purge addresses).
    for peer in &routed_peers {
        assert!(
            kad.fuzz_routing_table_contains(peer),
            "AddAddress'd peer missing from RT at end: {peer}"
        );
    }
    let _ = QueryId::fuzz(0);
}

fn drain_polls(kad: &mut Behaviour<MemoryStore>, handlers: &mut HashMap<PeerId, Handler>) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match NetworkBehaviour::poll(kad, &mut cx) {
            Poll::Ready(ToSwarm::NotifyHandler { peer_id, event, .. }) => {
                if let Some(h) = handlers.get_mut(&peer_id) {
                    h.on_behaviour_event(event);
                }
            }
            Poll::Ready(_) => continue,
            Poll::Pending => break,
        }
    }
}

fn pump_all_handlers(
    kad: &mut Behaviour<MemoryStore>,
    handlers: &mut HashMap<PeerId, Handler>,
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
) {
    for (peer, handler) in handlers.iter_mut() {
        let cid = conn_ids
            .get(peer)
            .and_then(|v| v.first().map(|(c, _)| *c))
            .unwrap_or_else(|| ConnectionId::new_unchecked(0));
        for ev in pump_handler(handler) {
            kad.on_connection_handler_event(*peer, cid, ev);
        }
    }
}

/// Deterministic local id (distinct from [`peer_pool`] slots).
fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0xC0u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed kad ed25519 seed")
            .public(),
    )
}

/// Deterministic PeerIds so InjectResponse / closer_peers / corpus correlate.
fn peer_pool() -> [PeerId; PEER_POOL] {
    std::array::from_fn(|i| {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xB0;
        bytes[1] = i as u8 + 1;
        bytes[31] = !(i as u8);
        PeerId::from(
            Keypair::ed25519_from_bytes(&mut bytes)
                .expect("pool ed25519 seed")
                .public(),
        )
    })
}

fn peer_addr(slot: u8) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(std::net::Ipv4Addr::new(
        127,
        0,
        0,
        1 + (slot % 200),
    )));
    addr.push(Protocol::Tcp(5000 + u16::from(slot)));
    addr
}

fn key_bytes(slot: u8) -> Vec<u8> {
    // 32-byte-ish key material indexed by slot for query correlation.
    let mut k = vec![slot; 32];
    k[0] = slot;
    k[31] = slot.wrapping_add(1);
    k
}

fn push_query(active: &mut Vec<QueryId>, qid: QueryId) {
    active.push(qid);
    if active.len() > 16 {
        active.remove(0);
    }
}

/// Resolve which [`QueryId`] an [`FuzzAction::InjectResponse`] should attribute.
///
/// - `mismatch` → ghost id never issued by the Behaviour (must not panic)
/// - else `query_slot == 0` → newest; higher slots walk older ring entries
fn resolve_query_id(active: &[QueryId], query_slot: u8, mismatch: bool) -> Option<QueryId> {
    if mismatch {
        // High bit range avoids colliding with sequential QueryPool ids under soak.
        return Some(QueryId::fuzz(
            0xF000_0000usize.wrapping_add(usize::from(query_slot)),
        ));
    }
    let n = active.len();
    if n == 0 {
        return None;
    }
    let from_end = (query_slot as usize) % n;
    Some(active[n - 1 - from_end])
}

fn kad_peer_from_slot(peers: &[PeerId; PEER_POOL], slot: u8) -> KadPeer {
    let node_id = peers[(slot as usize) % PEER_POOL];
    KadPeer {
        node_id,
        multiaddrs: vec![peer_addr(slot)],
        connection_ty: ConnectionType::Connected,
    }
}

/// LEB128 varint length prefix, matching `prost_codec`'s `unsigned_varint` framing.
fn push_varint(buf: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        buf.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
}

fn decode_inbound(bytes: &[u8], request_id: RequestId) -> Option<HandlerEvent> {
    let msg = proto::Message::decode(bytes).ok()?;
    let req = KadRequestMsg::try_from(msg).ok()?;
    request_to_handler(req, request_id)
}

/// Decode unsigned-varint length-prefixed DHT frames via inbound [`Codec`].
fn decode_wire(bytes: &[u8], request_id: RequestId) -> Option<HandlerEvent> {
    let mut codec = Codec::<KadResponseMsg, KadRequestMsg>::new(MAX_MSG_BYTES);
    let mut src = BytesMut::from(bytes);
    let req = match codec.decode(&mut src) {
        Ok(Some(r)) => r,
        _ => return None,
    };
    request_to_handler(req, request_id)
}

fn request_to_handler(req: KadRequestMsg, request_id: RequestId) -> Option<HandlerEvent> {
    Some(match req {
        KadRequestMsg::Ping => return None, // no HandlerEvent for bare ping
        KadRequestMsg::FindNode { key } => HandlerEvent::FindNodeReq { key, request_id },
        KadRequestMsg::GetProviders { key } => HandlerEvent::GetProvidersReq { key, request_id },
        KadRequestMsg::AddProvider { key, provider } => HandlerEvent::AddProvider { key, provider },
        KadRequestMsg::GetValue { key } => HandlerEvent::GetRecord { key, request_id },
        KadRequestMsg::PutValue { record } => HandlerEvent::PutRecord { record, request_id },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, GetClosestPeersError, GetRecordError, PutRecordError, QueryResult};

    fn drain_events(kad: &mut Behaviour<MemoryStore>) -> Vec<Event> {
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let mut out = Vec::new();
        for _ in 0..MAX_POLL_DRAIN {
            match NetworkBehaviour::poll(kad, &mut cx) {
                Poll::Ready(libp2p_swarm::ToSwarm::GenerateEvent(ev)) => out.push(ev),
                Poll::Ready(_) => continue,
                Poll::Pending => break,
            }
        }
        out
    }

    #[test]
    fn put_record_to_quorum_all_fails_without_successes() {
        let local_id = fuzz_local_peer_id();
        let mut config = Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
        config
            // Long timeout so the query finishes via peer failures, not Timeout.
            .set_query_timeout(Duration::from_secs(60))
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_provider_publication_interval(None)
            .set_periodic_bootstrap_interval(None)
            .set_caching(Caching::Disabled);
        let store = MemoryStore::with_config(
            local_id,
            MemoryStoreConfig {
                max_records: 64,
                max_value_bytes: MAX_DATA_BYTES,
                max_providers_per_key: 4,
                max_provided_keys: 32,
            },
        );
        let mut kad = Behaviour::with_config(local_id, store, config);
        let peers = peer_pool();

        // Connect two peers so NotifyHandler / on_failure can progress.
        for (slot, peer) in peers.iter().take(2).enumerate() {
            let cid = ConnectionId::new_unchecked(slot + 1);
            let remote = peer_addr(slot as u8);
            let _ = kad.handle_established_outbound_connection(
                cid,
                *peer,
                &remote,
                Endpoint::Dialer,
                PortUse::Reuse,
            );
            let endpoint = ConnectedPoint::Dialer {
                address: remote,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };
            kad.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: *peer,
                connection_id: cid,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: 0,
            }));
        }

        let record = Record::new(RecordKey::new(&key_bytes(1)), vec![1; 8]);
        let targets = peers.iter().take(2).copied().collect::<Vec<_>>();
        let qid = kad.put_record_to(record, targets.clone().into_iter(), Quorum::All);

        // Poll so the fixed query enters Waiting for connected peers.
        let _ = drain_events(&mut kad);

        // Fail both put targets → fixed query finishes below quorum.
        for (slot, peer) in targets.iter().enumerate() {
            let cid = ConnectionId::new_unchecked(slot + 1);
            kad.on_connection_handler_event(
                *peer,
                cid,
                HandlerEvent::QueryError {
                    error: HandlerQueryErr::UnexpectedMessage,
                    query_id: qid,
                },
            );
        }

        let events = drain_events(&mut kad);
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::OutboundQueryProgressed {
                    result: QueryResult::PutRecord(Err(PutRecordError::QuorumFailed { .. })),
                    ..
                }
            )),
            "expected QuorumFailed, got {events:?}"
        );
    }

    #[test]
    fn get_record_not_found_with_empty_routing_table() {
        let local_id = fuzz_local_peer_id();
        let mut config = Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
        config
            .set_query_timeout(Duration::from_secs(60))
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_provider_publication_interval(None)
            .set_periodic_bootstrap_interval(None)
            .set_caching(Caching::Disabled);
        let store = MemoryStore::with_config(
            local_id,
            MemoryStoreConfig {
                max_records: 64,
                max_value_bytes: MAX_DATA_BYTES,
                max_providers_per_key: 4,
                max_provided_keys: 32,
            },
        );
        let mut kad = Behaviour::with_config(local_id, store, config);
        let _qid = kad.get_record(RecordKey::new(&key_bytes(9)));
        let events = drain_events(&mut kad);
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::OutboundQueryProgressed {
                    result: QueryResult::GetRecord(Err(GetRecordError::NotFound { .. })),
                    ..
                }
            )),
            "expected NotFound, got {events:?}"
        );
    }

    #[test]
    fn wire_codec_roundtrip_find_node() {
        let wire = encode_structured_wire(StructuredInboundKind::FindNode, 3, None);
        assert!(!wire.is_empty());
        let ev = decode_wire(&wire, RequestId::fuzz(1)).expect("decode wire");
        assert!(matches!(ev, HandlerEvent::FindNodeReq { .. }));
    }

    #[test]
    fn handler_inbound_find_node_notifies() {
        let wire = encode_structured_wire(StructuredInboundKind::FindNode, 3, None);
        let events = crate::fuzz_handler_io(
            [wire],
            8,
            0,
            false,
            crate::OutboundDrive::MockResponse,
            crate::WriteFault::NONE,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::ProtocolConfirmed { .. })),
            "expected ProtocolConfirmed, got {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::FindNodeReq { .. })),
            "expected FindNodeReq, got {events:?}"
        );
    }

    #[test]
    fn handler_partial_reads_assemble_frame() {
        let wire = encode_structured_wire(StructuredInboundKind::GetProviders, 1, None);
        let events = crate::fuzz_handler_io(
            [wire],
            1,
            0,
            false,
            crate::OutboundDrive::MockResponse,
            crate::WriteFault::NONE,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::GetProvidersReq { .. })),
            "expected GetProvidersReq under chunk_cap=1, got {events:?}"
        );
    }

    #[test]
    fn handler_outbound_find_node_completes() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::MockResponse,
            crate::WriteFault::NONE,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::FindNodeRes { .. })),
            "expected FindNodeRes from outbound mock, got {events:?}"
        );
    }

    #[test]
    fn handler_encode_under_write_backpressure() {
        // Partial writes alone must complete outbound FindNodeRes.
        let write = crate::WriteFault {
            write_cap: 1,
            stall_every: 0,
            err_every: 0,
            flush_stall_every: 0,
            zero_progress_once: false,
        };
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::MockResponse,
            write,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::FindNodeRes { .. })),
            "expected FindNodeRes under partial writes, got {events:?}"
        );

        // Stalls alone (full-buffer accepts) must also complete.
        let write = crate::WriteFault {
            write_cap: 0,
            stall_every: 2,
            err_every: 0,
            flush_stall_every: 0,
            zero_progress_once: false,
        };
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::MockResponse,
            write,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::FindNodeRes { .. })),
            "expected FindNodeRes under write stalls, got {events:?}"
        );
        // Note: flush_stall_every on OutboundMockIo can starve FindNodeReq encode
        // under noop_waker (request flush Pending before response path). Flush
        // stalls are exercised on Behaviour Connect inbound duplex instead.
    }

    #[test]
    fn handler_dial_upgrade_timeout_emits_io_timed_out() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::DialUpgradeTimeout,
            crate::WriteFault::NONE,
        );
        assert!(
            crate::events_contain_io_timed_out(&events),
            "expected QueryError Io(TimedOut) via DialUpgradeError, got {events:?}"
        );
    }

    #[test]
    fn handler_substream_idle_timeout_emits_io_timed_out() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::SubstreamIdleTimeout,
            crate::WriteFault::NONE,
        );
        assert!(
            crate::events_contain_io_timed_out(&events),
            "expected QueryError Io(TimedOut) via FuturesTupleSet idle, got {events:?}"
        );
    }

    #[test]
    fn handler_dial_upgrade_negotiation_failed_emits_connection_refused() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::DialUpgradeNegotiationFailed,
            crate::WriteFault::NONE,
        );
        assert!(
            crate::events_contain_io_kind(&events, std::io::ErrorKind::ConnectionRefused),
            "expected QueryError Io(ConnectionRefused), got {events:?}"
        );
    }

    #[test]
    fn handler_dial_upgrade_apply_emits_invalid_data() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::DialUpgradeApply,
            crate::WriteFault::NONE,
        );
        assert!(
            crate::events_contain_io_kind(&events, std::io::ErrorKind::InvalidData),
            "expected QueryError Io(InvalidData) via Apply, got {events:?}"
        );
    }

    #[test]
    fn handler_dial_upgrade_io_emits_connection_reset() {
        let events = crate::fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            crate::OutboundDrive::DialUpgradeIo,
            crate::WriteFault::NONE,
        );
        assert!(
            crate::events_contain_io_kind(&events, std::io::ErrorKind::ConnectionReset),
            "expected QueryError Io(ConnectionReset), got {events:?}"
        );
    }

    #[test]
    fn advance_query_clock_times_out_get_closest() {
        // Connect + confirm so the query has peers, then advance past 60s timeout.
        let local_id = fuzz_local_peer_id();
        let mut config = Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
        config
            .set_query_timeout(Duration::from_secs(60))
            .set_replication_interval(None)
            .set_publication_interval(None)
            .set_provider_publication_interval(None)
            .set_periodic_bootstrap_interval(None)
            .set_caching(Caching::Disabled);
        let store = MemoryStore::with_config(
            local_id,
            MemoryStoreConfig {
                max_records: 64,
                max_value_bytes: MAX_DATA_BYTES,
                max_providers_per_key: 4,
                max_provided_keys: 32,
            },
        );
        let mut kad = Behaviour::with_config(local_id, store, config);
        let peers = peer_pool();
        let peer = peers[0];
        let cid = ConnectionId::new_unchecked(1);
        let remote = peer_addr(0);
        let _ = kad.handle_established_outbound_connection(
            cid,
            peer,
            &remote,
            Endpoint::Dialer,
            PortUse::Reuse,
        );
        let endpoint = ConnectedPoint::Dialer {
            address: remote,
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        };
        kad.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: cid,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        kad.on_connection_handler_event(
            peer,
            cid,
            HandlerEvent::ProtocolConfirmed {
                endpoint: endpoint.clone(),
            },
        );
        let _ = kad.add_address(&peer, peer_addr(0));
        let _qid = kad.get_closest_peers(key_bytes(7));
        kad.fuzz_advance_query_clock(Duration::from_secs(61));
        let events = drain_events(&mut kad);
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::OutboundQueryProgressed {
                    result: QueryResult::GetClosestPeers(Err(GetClosestPeersError::Timeout { .. })),
                    ..
                }
            )),
            "expected GetClosestPeers Timeout, got {events:?}"
        );
    }

    #[test]
    fn advance_jobs_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 0 },
            FuzzAction::PutRecord {
                key_slot: 0,
                value: vec![7; 16],
                quorum_all: false,
            },
            FuzzAction::StartProviding { key_slot: 1 },
            FuzzAction::AdvanceJobs,
            FuzzAction::GetRecord { key_slot: 99 },
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::GetRecordEmpty,
                closer_slot: 0,
                query_slot: 0,
                mismatch: false,
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(
                    StructuredInboundKind::GetProviders,
                    2,
                    None,
                ),
            },
        ]);
    }

    #[test]
    fn add_address_retained_after_connection_closed() {
        // Contract: AddAddress + ConnectionClosed must leave the peer in the RT.
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 0 },
            FuzzAction::AddAddress { peer_slot: 0 },
            FuzzAction::Disconnect { peer_slot: 0 },
            FuzzAction::AddAddress { peer_slot: 1 },
        ]);
    }

    #[test]
    fn disjoint_closest_and_not_found_smoke() {
        // Empty-RT NotFound first, then multi-peer mesh + disjoint closest + empty res.
        fuzz_behaviour([
            FuzzAction::GetRecord { key_slot: 0xFE },
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 0 },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 1 },
            FuzzAction::Connect {
                peer_slot: 2,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 2 },
            FuzzAction::GetClosestPeers { key_slot: 3 },
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::FindNodeRes,
                closer_slot: 1,
                query_slot: 0,
                mismatch: false,
            },
            FuzzAction::InjectResponse {
                peer_slot: 1,
                kind: StructuredResponseKind::FindNodeRes,
                closer_slot: 2,
                query_slot: 0,
                mismatch: false,
            },
            FuzzAction::GetRecord { key_slot: 9 },
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::GetRecordEmpty,
                closer_slot: 0,
                query_slot: 0,
                mismatch: false,
            },
            FuzzAction::InjectResponse {
                peer_slot: 1,
                kind: StructuredResponseKind::GetRecordEmpty,
                closer_slot: 0,
                query_slot: 0,
                mismatch: false,
            },
        ]);
    }

    #[test]
    fn query_id_confusion_smoke() {
        // Concurrent queries + older-slot / wrong-kind / ghost QueryId must not panic.
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 0 },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: true,
            },
            FuzzAction::ProtocolConfirmed { peer_slot: 1 },
            // Two live queries in the ring: GetClosestPeers then GetRecord.
            FuzzAction::GetClosestPeers { key_slot: 1 },
            FuzzAction::GetRecord { key_slot: 2 },
            // Ghost QueryId — Behaviour must ignore without panic.
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::FindNodeRes,
                closer_slot: 1,
                query_slot: 0,
                mismatch: true,
            },
            // Wrong kind for newest (GetRecord) query — PutRecordRes arm is a no-op.
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::PutRecordRes,
                closer_slot: 0,
                query_slot: 0,
                mismatch: false,
            },
            // Older query (GetClosestPeers): query_slot 1 from newest.
            FuzzAction::InjectResponse {
                peer_slot: 0,
                kind: StructuredResponseKind::FindNodeRes,
                closer_slot: 1,
                query_slot: 1,
                mismatch: false,
            },
            // Correct empty res for newest GetRecord.
            FuzzAction::InjectResponse {
                peer_slot: 1,
                kind: StructuredResponseKind::GetRecordEmpty,
                closer_slot: 0,
                query_slot: 0,
                mismatch: false,
            },
        ]);
    }

    #[test]
    fn resolve_query_id_newest_and_ghost() {
        let a = QueryId::fuzz(10);
        let b = QueryId::fuzz(11);
        let ring = vec![a, b];
        assert_eq!(resolve_query_id(&ring, 0, false), Some(b)); // newest
        assert_eq!(resolve_query_id(&ring, 1, false), Some(a)); // older
        assert_eq!(resolve_query_id(&ring, 2, false), Some(b)); // wrap
        assert!(resolve_query_id(&[], 0, false).is_none());
        let ghost = resolve_query_id(&ring, 3, true).expect("ghost");
        assert_ne!(ghost, a);
        assert_ne!(ghost, b);
    }
}

