//! Action-sequence fuzz driver for Identify [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Injects swarm / handler events and keeps
//! live [`Handler`]s with mock streams so libFuzzer reaches address translation,
//! peer-cache LRU, push/identify wire parse (large listen_addrs / protocols),
//! and ConnectionHandler poll.

use std::{
    collections::HashMap,
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::Encoder;
use bytes::BytesMut;
use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, PeerRecord, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionId, NetworkBehaviour, ToSwarm,
    behaviour::{
        ConnectionClosed, ConnectionEstablished, ExternalAddrConfirmed, FromSwarm, NewListenAddr,
    },
};

use crate::{
    Behaviour, Config, Event,
    fuzz_handler::{
        ChunkFeed, OutboundDrive, WriteFault, attach_live_inbound_push_ex,
        inject_outbound_identify, pump_handler,
    },
    handler::{Event as HandlerEvent, Handler, InEvent},
    proto,
};

/// Cap how many actions one fuzz input may drive.
pub const MAX_ACTIONS: usize = 64;
/// Cap inbound protobuf / wire blob size.
pub const MAX_MSG_BYTES: usize = 4 * 1024;
/// Soft cap on listen_addrs in structured messages (DoS surface).
pub const MAX_ADDRS: usize = 64;
/// Soft cap on protocols in structured messages.
pub const MAX_PROTOCOLS: usize = 64;
/// Fixed peer pool so connect / inject / disconnect correlate.
pub const PEER_POOL: usize = 8;
/// Bound polls drained after each action.
const MAX_POLL_DRAIN: usize = 256;
/// Identify framing limit (mirrors protocol.rs).
const MAX_MESSAGE_SIZE_BYTES: usize = 4096;

/// Well-formed Identify wire kinds for coverage of parse / merge / peer-id check.
#[derive(Clone, Copy, Debug)]
pub enum StructuredIdentifyKind {
    /// Valid Info matching peer_pool[slot] public key + a few addrs/protocols.
    MatchingPeer,
    /// Valid Info but wrong public key → discarded (no Identified).
    MismatchedPeer,
    /// Many listen_addrs (valid + garbage) and many protocol strings.
    LargeLists,
    /// Partial PushInfo-shaped message (missing public_key ok for push).
    PushPartial,
    /// Include a signed peer record for peer_pool[slot].
    WithSignedRecord,
}

/// Encode a length-delimited Identify protobuf for `kind` / `peer_slot`.
pub fn encode_structured_wire(kind: StructuredIdentifyKind, peer_slot: u8) -> Vec<u8> {
    let peers = peer_pool_keys();
    let slot = (peer_slot as usize) % PEER_POOL;
    let kp = &peers[slot];
    let wrong = &peers[(slot + 1) % PEER_POOL];

    let msg = match kind {
        StructuredIdentifyKind::MatchingPeer => proto::Identify {
            protocol_version: Some("fuzz/1.0.0".into()),
            agent_version: Some("fuzz-agent/0".into()),
            public_key: Some(kp.public().encode_protobuf()),
            listen_addrs: vec![peer_addr(peer_slot).to_vec()],
            observed_addr: Some(observed_addr(peer_slot).to_vec()),
            protocols: vec![
                "/ipfs/ping/1.0.0".into(),
                "/ipfs/id/1.0.0".into(),
                "/ipfs/kad/1.0.0".into(),
            ],
            signed_peer_record: None,
        },
        StructuredIdentifyKind::MismatchedPeer => proto::Identify {
            protocol_version: Some("fuzz/1.0.0".into()),
            agent_version: Some("fuzz-agent/0".into()),
            public_key: Some(wrong.public().encode_protobuf()),
            listen_addrs: vec![peer_addr(peer_slot).to_vec()],
            observed_addr: Some(observed_addr(peer_slot).to_vec()),
            protocols: vec!["/ipfs/ping/1.0.0".into()],
            signed_peer_record: None,
        },
        StructuredIdentifyKind::LargeLists => {
            let mut listen_addrs = Vec::with_capacity(MAX_ADDRS);
            for i in 0..MAX_ADDRS {
                if i % 4 == 3 {
                    // Garbage multiaddr bytes — parse_listen_addrs skips.
                    listen_addrs.push(vec![0xFF; 8]);
                } else {
                    let mut a = Multiaddr::empty();
                    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(
                        10,
                        0,
                        (i / 256) as u8,
                        (i % 256) as u8,
                    )));
                    a.push(Protocol::Tcp(10000 + i as u16));
                    listen_addrs.push(a.to_vec());
                }
            }
            let protocols = (0..MAX_PROTOCOLS)
                .map(|i| format!("/fuzz/proto/{i}/1.0.0"))
                .collect();
            proto::Identify {
                protocol_version: Some("fuzz/1.0.0".into()),
                agent_version: Some("fuzz-agent/large".into()),
                public_key: Some(kp.public().encode_protobuf()),
                listen_addrs,
                observed_addr: Some(observed_addr(peer_slot).to_vec()),
                protocols,
                signed_peer_record: None,
            }
        }
        StructuredIdentifyKind::PushPartial => proto::Identify {
            protocol_version: Some("fuzz/push".into()),
            agent_version: None,
            public_key: None,
            listen_addrs: vec![peer_addr(peer_slot).to_vec()],
            observed_addr: None,
            protocols: vec!["/fuzz/new/1.0.0".into()],
            signed_peer_record: None,
        },
        StructuredIdentifyKind::WithSignedRecord => {
            let addrs = vec![peer_addr(peer_slot)];
            let signed = PeerRecord::new(kp, addrs.clone())
                .ok()
                .map(|r| r.into_signed_envelope().into_protobuf_encoding());
            proto::Identify {
                protocol_version: Some("fuzz/1.0.0".into()),
                agent_version: Some("fuzz-agent/signed".into()),
                public_key: Some(kp.public().encode_protobuf()),
                listen_addrs: addrs.iter().map(|a| a.to_vec()).collect(),
                observed_addr: Some(observed_addr(peer_slot).to_vec()),
                protocols: vec!["/ipfs/id/1.0.0".into()],
                signed_peer_record: signed,
            }
        }
    };

    length_prefix_encode(&msg)
}

fn length_prefix_encode(msg: &proto::Identify) -> Vec<u8> {
    let mut codec = prost_codec::Codec::<proto::Identify>::new(MAX_MESSAGE_SIZE_BYTES);
    let mut buf = BytesMut::new();
    if codec.encode(msg.clone(), &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

/// Actions for the Identify behaviour harness.
#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect {
        peer_slot: u8,
    },
    /// Push local identify info to a connected peer (outbound push stream).
    Push {
        peer_slot: u8,
    },
    /// Feed length-delimited wire into the live inbound push feed.
    InjectWire {
        peer_slot: u8,
        wire_bytes: Vec<u8>,
    },
    /// Structured identify/push wire for peer_slot.
    InjectStructured {
        peer_slot: u8,
        kind: StructuredIdentifyKind,
    },
    /// Inject outbound identify response (parse path via FullyNegotiatedOutbound).
    InjectOutboundIdentify {
        peer_slot: u8,
        kind: StructuredIdentifyKind,
    },
    /// DialUpgradeError on the next outbound request.
    FailOutboundUpgrade {
        peer_slot: u8,
        timeout: bool,
    },
    /// Swarm NewListenAddr — may AddressesChanged + optional push.
    NewListenAddr {
        port: u16,
    },
    /// Confirm an external address candidate.
    ExternalAddrConfirmed {
        peer_slot: u8,
    },
    /// AddressesChanged to handlers with a synthetic address set size.
    AddressesChanged {
        peer_slot: u8,
        n_addrs: u8,
    },
    /// Fire the handler's periodic identify timer (`Delay` → OutboundSubstreamRequest).
    AdvanceInterval {
        peer_slot: u8,
    },
}

/// Local peer id for the harness (deterministic).
pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x41u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed local ed25519 seed")
            .public(),
    )
}

fn peer_pool_keys() -> Vec<Keypair> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0x50u8.wrapping_add(i as u8); 32];
            // Ensure distinct valid seeds: vary first bytes.
            bytes[0] = 0xC0u8.wrapping_add(i as u8);
            bytes[1] = 0x10u8.wrapping_add((i * 3) as u8);
            Keypair::ed25519_from_bytes(&mut bytes).expect("peer pool ed25519")
        })
        .collect()
}

fn peer_pool() -> Vec<PeerId> {
    peer_pool_keys()
        .into_iter()
        .map(|kp| PeerId::from(kp.public()))
        .collect()
}

fn peer_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(
        10,
        0,
        0,
        1 + (slot % 200),
    )));
    a.push(Protocol::Tcp(4000 + slot as u16));
    a
}

fn observed_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(
        198,
        51,
        100,
        1 + (slot % 200),
    )));
    a.push(Protocol::Tcp(5000 + slot as u16));
    a
}

/// Pre-populated starting state so a fuzz input can skip the Connect preamble and
/// jump into push / inject / address-change transitions with live handlers.
#[derive(Clone, Copy, Debug, Default)]
pub struct FuzzSeed {
    /// Pre-establish this many outbound connections + live push handlers.
    pub live_peers: u8,
}

/// Drive [`Behaviour`] with a sequence of actions.
///
/// Invariants: never panics; always terminates (bounded actions + poll drain).
/// Soft budgets on connected peers / discovered cache occupancy.
/// MismatchedPeer injects must not emit [`Event::Received`] for that peer.
/// Discovered LRU peer count stays ≤ configured `cache_size`.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    fuzz_behaviour_seeded(FuzzSeed::default(), actions);
}

/// [`fuzz_behaviour`] with a [`FuzzSeed`] pre-population step.
pub fn fuzz_behaviour_seeded(seed: FuzzSeed, actions: impl IntoIterator<Item = FuzzAction>) {
    let local_kp = {
        let mut bytes = [0x41u8; 32];
        Keypair::ed25519_from_bytes(&mut bytes).expect("fixed local ed25519 seed")
    };
    let cache_size = 16;
    let config = Config::new_with_signed_peer_record("fuzz/1.0.0".into(), &local_kp)
        .with_agent_version("fuzz-agent/0".into())
        // Long wall interval; periodic identify is driven by AdvanceInterval.
        .with_interval(Duration::from_secs(3600))
        .with_push_listen_addr_updates(true)
        .with_cache_size(cache_size)
        .with_hide_listen_addrs(false);

    let mut identify = Behaviour::new(config);
    let peers = peer_pool();
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>> = HashMap::new();
    let mut handlers: HashMap<PeerId, Handler> = HashMap::new();
    let mut inbound_feeds: HashMap<PeerId, ChunkFeed> = HashMap::new();
    let mut next_conn: usize = 1;
    let mut pending_fail: HashMap<PeerId, bool> = HashMap::new(); // timeout?
    let mut received_counts: HashMap<PeerId, u32> = HashMap::new();

    // Seed pre-population: pre-established live connections + push handlers.
    for slot in 0..(seed.live_peers.min(PEER_POOL as u8)) {
        let peer = peers[slot as usize];
        let cid = ConnectionId::new_unchecked(next_conn);
        next_conn = next_conn.wrapping_add(1).max(1);
        let remote = peer_addr(slot);
        if let Ok(mut h) = identify.handle_established_outbound_connection(
            cid, peer, &remote, Endpoint::Dialer, PortUse::Reuse,
        ) {
            let endpoint = ConnectedPoint::Dialer {
                address: remote,
                role_override: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };
            let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
            identify.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id: peer,
                connection_id: cid,
                endpoint: &endpoint,
                failed_addresses: &[],
                other_established: other,
            }));
            conn_ids.entry(peer).or_default().push((cid, endpoint));
            let feed = attach_live_inbound_push_ex(&mut h, WriteFault::NONE);
            for ev in pump_handler(&mut h) {
                identify.on_connection_handler_event(peer, cid, ev);
            }
            inbound_feeds.insert(peer, feed);
            handlers.insert(peer, h);
        }
    }

    for action in actions.into_iter().take(MAX_ACTIONS) {
        // Mismatch injects: Received count for that peer must not increase.
        let mismatch_peer = match &action {
            FuzzAction::InjectOutboundIdentify {
                peer_slot,
                kind: StructuredIdentifyKind::MismatchedPeer,
            }
            | FuzzAction::InjectStructured {
                peer_slot,
                kind: StructuredIdentifyKind::MismatchedPeer,
            } => {
                let peer = peers[(*peer_slot as usize) % PEER_POOL];
                Some((peer, *received_counts.get(&peer).unwrap_or(&0)))
            }
            _ => None,
        };

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
                    identify.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    identify.handle_established_inbound_connection(
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
                identify.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids.entry(peer).or_default().push((cid, endpoint));

                if let Ok(mut h) = handler {
                    // ~20% of connects: write_cap=1 so identify/push encode
                    // under backpressure is exercised on live handler streams.
                    let write = if peer_slot % 5 == 0 {
                        WriteFault {
                            write_cap: 1,
                            stall_every: 0,
                            err_every: 0,
                            flush_stall_every: 2,
                        }
                    } else {
                        WriteFault::NONE
                    };
                    let feed = attach_live_inbound_push_ex(&mut h, write);
                    for ev in pump_handler(&mut h) {
                        identify.on_connection_handler_event(peer, cid, ev);
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
                pending_fail.remove(&peer);
                let mut remaining = ids.len();
                for (cid, endpoint) in ids {
                    remaining = remaining.saturating_sub(1);
                    identify.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
            }
            FuzzAction::Push { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                identify.push([peer]);
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
                        identify.on_connection_handler_event(peer, cid, ev);
                    }
                }
            }
            FuzzAction::InjectStructured { peer_slot, kind } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                // Push merge needs a prior Identified; seed MatchingPeer first for PushPartial.
                if matches!(kind, StructuredIdentifyKind::PushPartial) {
                    if let Some(h) = handlers.get_mut(&peer) {
                        let seed = encode_structured_wire(
                            StructuredIdentifyKind::MatchingPeer,
                            peer_slot,
                        );
                        let feed_out = ChunkFeed::new(seed, 64, 0);
                        feed_out.close();
                        inject_outbound_identify(h, feed_out, WriteFault::NONE);
                        for ev in pump_handler(h) {
                            identify.on_connection_handler_event(peer, cid, ev);
                        }
                    }
                }
                let wire = encode_structured_wire(kind, peer_slot);
                if let Some(feed) = inbound_feeds.get(&peer) {
                    feed.push(&wire);
                }
                if let Some(h) = handlers.get_mut(&peer) {
                    for ev in pump_handler(h) {
                        identify.on_connection_handler_event(peer, cid, ev);
                    }
                }
            }
            FuzzAction::InjectOutboundIdentify { peer_slot, kind } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let Some(h) = handlers.get_mut(&peer) else {
                    continue;
                };
                let wire = encode_structured_wire(kind, peer_slot);
                let feed = ChunkFeed::new(wire, 64, 0);
                feed.close();
                inject_outbound_identify(h, feed, WriteFault::NONE);
                for ev in pump_handler(h) {
                    identify.on_connection_handler_event(peer, cid, ev);
                }
            }
            FuzzAction::FailOutboundUpgrade { peer_slot, timeout } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                pending_fail.insert(peer, timeout);
                // Trigger an outbound request so DialUpgradeError can apply.
                identify.push([peer]);
            }
            FuzzAction::NewListenAddr { port } => {
                let mut addr = Multiaddr::empty();
                addr.push(Protocol::Ip4(std::net::Ipv4Addr::UNSPECIFIED));
                addr.push(Protocol::Tcp(port.max(1)));
                let listener_id = libp2p_core::transport::ListenerId::next();
                identify.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
                    listener_id,
                    addr: &addr,
                }));
            }
            FuzzAction::ExternalAddrConfirmed { peer_slot } => {
                let addr = observed_addr(peer_slot);
                identify.on_swarm_event(FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
                    addr: &addr,
                }));
            }
            FuzzAction::AddressesChanged { peer_slot, n_addrs } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let Some(h) = handlers.get_mut(&peer) else {
                    continue;
                };
                let n = (n_addrs as usize % MAX_ADDRS).max(1);
                let addrs = (0..n)
                    .map(|i| {
                        let mut a = Multiaddr::empty();
                        a.push(Protocol::Ip4(std::net::Ipv4Addr::new(10, 1, 0, i as u8)));
                        a.push(Protocol::Tcp(6000 + i as u16));
                        a
                    })
                    .collect();
                h.on_behaviour_event(InEvent::AddressesChanged(addrs));
                for ev in pump_handler(h) {
                    identify.on_connection_handler_event(peer, cid, ev);
                }
            }
            FuzzAction::AdvanceInterval { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(h) = handlers.get_mut(&peer) else {
                    continue;
                };
                h.fuzz_trigger_identify_now();
                // Optional: fulfill with matching wire so periodic re-identify can succeed.
                let wire = encode_structured_wire(StructuredIdentifyKind::MatchingPeer, peer_slot);
                let fail = pending_fail.remove(&peer);
                for ev in pump_with_optional_fail_and_wire(h, fail, &wire) {
                    if let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()) {
                        identify.on_connection_handler_event(peer, *cid, ev);
                    }
                }
            }
        }

        drain_behaviour(
            &mut identify,
            &mut handlers,
            &mut inbound_feeds,
            &conn_ids,
            &mut pending_fail,
            &mut received_counts,
        );

        if let Some((peer, before)) = mismatch_peer {
            let after = *received_counts.get(&peer).unwrap_or(&0);
            assert_eq!(
                after, before,
                "MismatchedPeer produced Event::Received for {peer} (before={before} after={after})"
            );
        }

        // Cache capacity invariant (LRU peer slots ≤ configured size).
        assert!(
            identify.fuzz_discovered_peer_count() <= cache_size,
            "discovered peer cache exceeded capacity: {} > {cache_size}",
            identify.fuzz_discovered_peer_count()
        );
    }

    // Soft DoS clamps (panic = finding).
    assert!(
        conn_ids.len() <= PEER_POOL,
        "connected peer map exceeded pool: {}",
        conn_ids.len()
    );
    assert!(
        handlers.len() <= PEER_POOL,
        "handler map exceeded pool: {}",
        handlers.len()
    );
    assert!(
        identify.fuzz_discovered_peer_count() <= cache_size,
        "discovered peer cache exceeded capacity at end: {} > {cache_size}",
        identify.fuzz_discovered_peer_count()
    );
    // ≤ 10 addrs per peer in PeerAddresses; soft cap for soak.
    assert!(
        identify.fuzz_discovered_addr_count() <= cache_size.saturating_mul(10),
        "discovered addr cache grew unboundedly: {}",
        identify.fuzz_discovered_addr_count()
    );
}

fn drain_behaviour(
    identify: &mut Behaviour,
    handlers: &mut HashMap<PeerId, Handler>,
    _inbound_feeds: &mut HashMap<PeerId, ChunkFeed>,
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
    pending_fail: &mut HashMap<PeerId, bool>,
    received_counts: &mut HashMap<PeerId, u32>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match NetworkBehaviour::poll(identify, &mut cx) {
            Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                event,
                handler: _,
            }) => {
                let Some(h) = handlers.get_mut(&peer_id) else {
                    continue;
                };
                h.on_behaviour_event(event);
                // If FailOutboundUpgrade is pending, fulfill next outbound with error.
                let fail = pending_fail.remove(&peer_id);
                for ev in pump_with_optional_fail(h, fail) {
                    if let Some((cid, _)) = conn_ids.get(&peer_id).and_then(|v| v.first()) {
                        identify.on_connection_handler_event(peer_id, *cid, ev);
                    }
                }
            }
            Poll::Ready(ToSwarm::GenerateEvent(ev)) => {
                // Touch event fields so Received/Error paths stay live under soak.
                let _ = ev.connection_id();
                match &ev {
                    Event::Received { peer_id, info, .. } => {
                        *received_counts.entry(*peer_id).or_insert(0) += 1;
                        assert!(
                            info.listen_addrs.len() <= MAX_ADDRS * 2,
                            "listen_addrs grew past soft budget: {}",
                            info.listen_addrs.len()
                        );
                        assert!(
                            info.protocols.len() <= MAX_PROTOCOLS * 2,
                            "protocols grew past soft budget: {}",
                            info.protocols.len()
                        );
                    }
                    Event::Error { .. }
                    | Event::Sent { .. }
                    | Event::Pushed { .. } => {}
                }
            }
            Poll::Ready(_) => {}
            Poll::Pending => {
                // Also pump handlers for timer-driven outbound identify.
                for (peer, h) in handlers.iter_mut() {
                    let fail = pending_fail.remove(peer);
                    for ev in pump_with_optional_fail(h, fail) {
                        if let Some((cid, _)) = conn_ids.get(peer).and_then(|v| v.first()) {
                            identify.on_connection_handler_event(*peer, *cid, ev);
                        }
                    }
                }
                // One more behaviour poll after handler events.
                if let Poll::Ready(ToSwarm::GenerateEvent(ev)) =
                    NetworkBehaviour::poll(identify, &mut cx)
                {
                    if let Event::Received { peer_id, .. } = &ev {
                        *received_counts.entry(*peer_id).or_insert(0) += 1;
                    }
                    continue;
                }
                break;
            }
        }
    }
}

fn pump_with_optional_fail(
    handler: &mut Handler,
    fail: Option<bool>,
) -> Vec<HandlerEvent> {
    pump_with_optional_fail_and_wire(handler, fail, &[])
}

/// Like [`pump_with_optional_fail`], but fulfills identify outbound with `wire` bytes.
fn pump_with_optional_fail_and_wire(
    handler: &mut Handler,
    fail: Option<bool>,
    wire: &[u8],
) -> Vec<HandlerEvent> {
    use libp2p_swarm::{
        ConnectionHandler, ConnectionHandlerEvent,
        handler::{ConnectionEvent, DialUpgradeError},
    };
    use libp2p_swarm::StreamUpgradeError;

    use crate::fuzz_handler::{ChunkFeed, inject_outbound_identify};

    let Some(timeout) = fail else {
        if wire.is_empty() {
            return pump_handler(handler);
        }
        let mut events = Vec::new();
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        for _ in 0..MAX_POLL_DRAIN {
            match ConnectionHandler::poll(handler, &mut cx) {
                Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => events.push(ev),
                Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) => {
                    let is_push = matches!(protocol.upgrade(), either::Either::Right(_));
                    if is_push {
                        // Push outbound: blackhole via default pump path.
                        crate::fuzz_handler::inject_outbound_push(handler, WriteFault::NONE);
                    } else {
                        let feed = ChunkFeed::new(wire.iter().copied(), 64, 0);
                        feed.close();
                        inject_outbound_identify(handler, feed, WriteFault::NONE);
                    }
                }
                Poll::Ready(_) => {}
                Poll::Pending => break,
            }
        }
        return events;
    };
    let outbound = if timeout {
        OutboundDrive::DialUpgradeTimeout
    } else {
        OutboundDrive::DialUpgradeNegotiationFailed
    };
    let mut events = Vec::new();
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match ConnectionHandler::poll(handler, &mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => events.push(ev),
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. }) => {
                let error = match outbound {
                    OutboundDrive::DialUpgradeTimeout => StreamUpgradeError::Timeout,
                    _ => StreamUpgradeError::NegotiationFailed,
                };
                handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
                    info: (),
                    error,
                }));
            }
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_seeded_live_peers() {
        // Pre-established live handlers → push/inject must land without the
        // Connect preamble.
        fuzz_behaviour_seeded(
            FuzzSeed { live_peers: 3 },
            [
                FuzzAction::NewListenAddr { port: 4001 },
                FuzzAction::InjectStructured {
                    peer_slot: 0,
                    kind: StructuredIdentifyKind::LargeLists,
                },
                FuzzAction::Push { peer_slot: 1 },
                FuzzAction::FailOutboundUpgrade {
                    peer_slot: 2,
                    timeout: true,
                },
                FuzzAction::Disconnect { peer_slot: 0 },
            ],
        );
    }

    #[test]
    fn connect_identify_push_smoke() {
        let actions = vec![
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::NewListenAddr { port: 4001 },
            FuzzAction::InjectOutboundIdentify {
                peer_slot: 0,
                kind: StructuredIdentifyKind::MatchingPeer,
            },
            FuzzAction::InjectStructured {
                peer_slot: 0,
                kind: StructuredIdentifyKind::LargeLists,
            },
            FuzzAction::Push { peer_slot: 0 },
            FuzzAction::FailOutboundUpgrade {
                peer_slot: 0,
                timeout: true,
            },
            FuzzAction::Disconnect { peer_slot: 0 },
        ];
        fuzz_behaviour(actions);
    }

    #[test]
    fn signed_record_and_mismatch_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectOutboundIdentify {
                peer_slot: 1,
                kind: StructuredIdentifyKind::WithSignedRecord,
            },
            FuzzAction::InjectOutboundIdentify {
                peer_slot: 1,
                kind: StructuredIdentifyKind::MismatchedPeer,
            },
            FuzzAction::InjectStructured {
                peer_slot: 1,
                kind: StructuredIdentifyKind::PushPartial,
            },
        ]);
    }

    #[test]
    fn encode_structured_nonempty() {
        for kind in [
            StructuredIdentifyKind::MatchingPeer,
            StructuredIdentifyKind::MismatchedPeer,
            StructuredIdentifyKind::LargeLists,
            StructuredIdentifyKind::PushPartial,
            StructuredIdentifyKind::WithSignedRecord,
        ] {
            let w = encode_structured_wire(kind, 0);
            assert!(!w.is_empty(), "{kind:?} encoded empty");
        }
    }

    #[test]
    fn mismatched_peer_does_not_emit_received() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectOutboundIdentify {
                peer_slot: 0,
                kind: StructuredIdentifyKind::MismatchedPeer,
            },
            FuzzAction::InjectStructured {
                peer_slot: 0,
                kind: StructuredIdentifyKind::MismatchedPeer,
            },
        ]);
    }

    #[test]
    fn advance_interval_triggers_periodic_identify() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectOutboundIdentify {
                peer_slot: 0,
                kind: StructuredIdentifyKind::MatchingPeer,
            },
            // Second periodic identify via timer reset + matching wire.
            FuzzAction::AdvanceInterval { peer_slot: 0 },
            FuzzAction::AdvanceInterval { peer_slot: 0 },
        ]);
    }

    #[test]
    fn discovered_cache_respects_capacity() {
        // Identify many peers with LargeLists; LRU peer count must stay ≤ 16.
        let mut actions = Vec::new();
        for slot in 0..PEER_POOL as u8 {
            actions.push(FuzzAction::Connect {
                peer_slot: slot,
                outbound: true,
            });
            actions.push(FuzzAction::InjectOutboundIdentify {
                peer_slot: slot,
                kind: StructuredIdentifyKind::LargeLists,
            });
        }
        // Re-identify to churn cache entries.
        for slot in 0..PEER_POOL as u8 {
            actions.push(FuzzAction::InjectOutboundIdentify {
                peer_slot: slot,
                kind: StructuredIdentifyKind::MatchingPeer,
            });
        }
        fuzz_behaviour(actions);
    }
}
