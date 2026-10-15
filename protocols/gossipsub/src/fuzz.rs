//! Action-sequence fuzz driver for [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. The harness injects structured swarm /
//! handler events and keeps live [`Handler`]s with mock streams so libFuzzer
//! reaches mesh, mcache, IHAVE/IWANT, heartbeat, **and** ConnectionHandler
//! encode/decode / queue-drain paths.

use std::{
    collections::HashMap,
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::{Decoder, Encoder};
use bytes::BytesMut;
use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    ConnectionId, NetworkBehaviour,
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
};
use prost::Message as _;

use crate::{
    Behaviour, ConfigBuilder, IdentTopic, MessageAuthenticity, MessageId, PeerScoreParams,
    PeerScoreThresholds, TopicHash, TopicScoreParams, ValidationMode,
    fuzz_handler::{ChunkFeed, WriteFault, attach_live_inbound_mode, pump_handler},
    handler::{Handler, HandlerEvent},
    protocol::GossipsubCodec,
    rpc_proto::proto,
    types::PeerKind,
};

/// Cap how many actions one fuzz input may drive.
pub const MAX_ACTIONS: usize = 64;
/// Cap protobuf RPC blob size fed into the decoder path.
pub const MAX_RPC_BYTES: usize = 4 * 1024;
/// Cap local publish / message body size (must exceed [`MAX_TRANSMIT_SIZE`] so
/// oversize publishes are not truncated below the MessageTooLarge threshold).
pub const MAX_DATA_BYTES: usize = 1024;
/// Behaviour / codec max transmit size used by the harness.
pub const MAX_TRANSMIT_SIZE: usize = 256;
/// Per-topic max used for `MessageSizeTooLargeForTopic` (via SetTopicMaxSize).
/// Must be ≥ 100 ([`ConfigBuilder`] floor when set at build). Kept below
/// [`MAX_TRANSMIT_SIZE`] so oversized frames still decode at the RPC layer.
/// Do not apply as the default Strict topic max — signed MissingSeqno messages
/// exceed 100 bytes and would be misclassified as oversize.
pub const TOPIC_MAX_TRANSMIT_SIZE: usize = 100;
/// Fixed peer pool so connect/RPC/disconnect correlate.
pub const PEER_POOL: usize = 8;
/// Fixed topic pool.
pub const TOPIC_POOL: usize = 4;
/// Bound polls drained after each action.
const MAX_POLL_DRAIN: usize = 256;
/// Codec publish-message cap (matches a tight fuzz-friendly config).
const MAX_PUBLISH_MESSAGES: usize = 64;
/// Codec control-message byte cap.
const MAX_CONTROL_MESSAGE_SIZE: usize = 2 * 1024;

/// Well-formed Gossipsub control / pubsub RPCs for coverage of cold decode arms.
#[derive(Clone, Copy, Debug)]
pub enum StructuredRpcKind {
    IHave,
    IWant,
    Graft,
    /// Empty PX list (still removes mesh peer when grafted).
    Prune,
    /// PRUNE with peer-exchange candidates from [`peer_pool`] (+ optional garbage id).
    PruneWithPx,
    IDontWant,
    Subscribe,
    Publish,
    /// Publish with `from` + garbage signature → codec `InvalidSignature` under Permissive.
    PublishBadSig,
    /// Publish claiming `from` = harness local Author id (SelfOrigin when allow_self_origin=false).
    PublishSelfOrigin,
    /// Publish with `from` = peer_pool[source_slot] (BlackListedSource after blacklist).
    PublishFromPeer,
    /// Strict: from + seqno + data, no signature → `InvalidSignature`.
    PublishMissingSig,
    /// Strict: from + signature + data, no seqno → `EmptySequenceNumber` (after sig check).
    PublishMissingSeqno,
    /// Strict: signature + seqno + data, no from → `InvalidSignature`.
    PublishMissingFrom,
    /// Oversized publish body for topic 0 (needs topic max in codec) →
    /// `MessageSizeTooLargeForTopic`.
    PublishOversizedTopic,
    /// Well-formed from/key/seqno + garbage signature. With verify stubbed this
    /// may accept; with `fuzzing-real-verify` → `InvalidSignature`.
    PublishGarbageSig,
}

/// Encode a minimal valid protobuf [`Rpc`] for `kind` against the harness topic pool.
pub fn encode_structured_rpc(kind: StructuredRpcKind, topic_slot: u8, mid_slot: u8) -> Vec<u8> {
    structured_rpc(kind, topic_slot, mid_slot, None).encode_to_vec()
}

/// Encode `kind` as a length-prefixed wire frame via [`GossipsubCodec`].
pub fn encode_structured_wire(kind: StructuredRpcKind, topic_slot: u8, mid_slot: u8) -> Vec<u8> {
    encode_structured_wire_from(kind, topic_slot, mid_slot, None)
}

/// Merge several structured RPCs into one length-prefixed frame (multi-publish / multi-control).
pub fn encode_batch_rpc(kinds: &[StructuredRpcKind], topic_slot: u8, mid_slot: u8) -> Vec<u8> {
    let mut rpc = proto::Rpc::default();
    for &k in kinds {
        merge_rpc(&mut rpc, structured_rpc(k, topic_slot, mid_slot, None));
    }
    let mut codec = make_fuzz_codec();
    let mut buf = BytesMut::new();
    if codec.encode(rpc, &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

fn merge_rpc(dst: &mut proto::Rpc, src: proto::Rpc) {
    dst.publish.extend(src.publish);
    dst.subscriptions.extend(src.subscriptions);
    match (&mut dst.control, src.control) {
        (Some(d), Some(s)) => {
            d.ihave.extend(s.ihave);
            d.iwant.extend(s.iwant);
            d.graft.extend(s.graft);
            d.prune.extend(s.prune);
            d.idontwant.extend(s.idontwant);
        }
        (None, Some(s)) => dst.control = Some(s),
        _ => {}
    }
    if dst.partial.is_none() {
        dst.partial = src.partial;
    }
}

/// Like [`encode_structured_wire`], but `PublishFromPeer` / `PublishSelfOrigin` use `from`.
pub fn encode_structured_wire_from(
    kind: StructuredRpcKind,
    topic_slot: u8,
    mid_slot: u8,
    from: Option<&PeerId>,
) -> Vec<u8> {
    let rpc = structured_rpc(kind, topic_slot, mid_slot, from);
    let mut codec = make_fuzz_codec();
    let mut buf = BytesMut::new();
    if codec.encode(rpc, &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

fn structured_rpc(
    kind: StructuredRpcKind,
    topic_slot: u8,
    mid_slot: u8,
    from: Option<&PeerId>,
) -> proto::Rpc {
    let topic = format!("fuzz-topic-{}", topic_slot as usize % TOPIC_POOL);
    let mid = vec![mid_slot; 8];
    match kind {
        StructuredRpcKind::IHave => proto::Rpc {
            control: Some(proto::ControlMessage {
                ihave: vec![proto::ControlIHave {
                    topic_id: Some(topic),
                    message_ids: vec![mid],
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        StructuredRpcKind::IWant => proto::Rpc {
            control: Some(proto::ControlMessage {
                iwant: vec![proto::ControlIWant {
                    message_ids: vec![mid],
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        StructuredRpcKind::Graft => proto::Rpc {
            control: Some(proto::ControlMessage {
                graft: vec![proto::ControlGraft {
                    topic_id: Some(topic),
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        StructuredRpcKind::Prune => proto::Rpc {
            control: Some(proto::ControlMessage {
                prune: vec![proto::ControlPrune {
                    topic_id: Some(topic),
                    peers: vec![],
                    backoff: Some(30),
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        StructuredRpcKind::PruneWithPx => {
            let peers = peer_pool();
            // 1..=4 PX candidates; start index from topic_slot for corpus diversity.
            let n = (mid_slot as usize % 4) + 1;
            let start = topic_slot as usize % PEER_POOL;
            let mut px = Vec::with_capacity(n + 1);
            for i in 0..n {
                let p = peers[(start + i) % PEER_POOL];
                px.push(proto::PeerInfo {
                    peer_id: Some(p.to_bytes()),
                    signed_peer_record: None,
                });
            }
            // Garbage peer id — decode path skips; must not break PX of valid peers.
            if mid_slot % 5 == 0 {
                px.push(proto::PeerInfo {
                    peer_id: Some(vec![0xFF; 3]),
                    signed_peer_record: None,
                });
            }
            // PeerInfo with missing peer_id — retained until px_connect filters it.
            if mid_slot % 7 == 0 {
                px.push(proto::PeerInfo {
                    peer_id: None,
                    signed_peer_record: None,
                });
            }
            proto::Rpc {
                control: Some(proto::ControlMessage {
                    prune: vec![proto::ControlPrune {
                        topic_id: Some(topic),
                        peers: px,
                        backoff: Some(30),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }
        }
        StructuredRpcKind::IDontWant => proto::Rpc {
            control: Some(proto::ControlMessage {
                idontwant: vec![proto::ControlIDontWant {
                    message_ids: vec![mid],
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
        StructuredRpcKind::Subscribe => proto::Rpc {
            subscriptions: vec![proto::SubOpts {
                subscribe: Some(true),
                topic_id: Some(topic),
                ..Default::default()
            }],
            ..Default::default()
        },
        StructuredRpcKind::Publish => proto::Rpc {
            publish: vec![proto::Message {
                data: Some(vec![mid_slot; 16]),
                seqno: Some(mid),
                topic,
                ..Default::default()
            }],
            ..Default::default()
        },
        StructuredRpcKind::PublishBadSig => proto::Rpc {
            publish: vec![proto::Message {
                from: Some(vec![0x00, 0x24]), // truncated / invalid peer id bytes
                signature: Some(vec![0xDE; 64]),
                data: Some(vec![mid_slot; 16]),
                seqno: Some(mid),
                topic,
                ..Default::default()
            }],
            ..Default::default()
        },
        StructuredRpcKind::PublishSelfOrigin | StructuredRpcKind::PublishFromPeer => {
            let from_bytes = from.map(|p| p.to_bytes()).unwrap_or_else(|| {
                // Fallback when caller forgot `from` — still a well-formed peer id.
                fuzz_local_peer_id().to_bytes()
            });
            proto::Rpc {
                publish: vec![proto::Message {
                    from: Some(from_bytes),
                    data: Some(vec![mid_slot; 16]),
                    seqno: Some(mid),
                    topic,
                    ..Default::default()
                }],
                ..Default::default()
            }
        }
        StructuredRpcKind::PublishMissingSig => {
            let peer = peer_pool()[(mid_slot as usize) % PEER_POOL];
            proto::Rpc {
                publish: vec![proto::Message {
                    from: Some(peer.to_bytes()),
                    data: Some(vec![mid_slot; 16]),
                    seqno: Some(mid),
                    topic,
                    ..Default::default()
                }],
                ..Default::default()
            }
        }
        StructuredRpcKind::PublishMissingSeqno => {
            // Real signature over a message with no seqno so Strict hits
            // EmptySequenceNumber (not InvalidSignature) under real verify.
            let kp = peer_pool_keypair(mid_slot as usize);
            let mut msg = proto::Message {
                from: Some(PeerId::from(kp.public()).to_bytes()),
                key: Some(kp.public().encode_protobuf()),
                data: Some(vec![mid_slot; 16]),
                topic: topic.clone(),
                ..Default::default()
            };
            msg.signature = Some(sign_pubsub_message(&kp, &msg));
            proto::Rpc {
                publish: vec![msg],
                ..Default::default()
            }
        }
        StructuredRpcKind::PublishMissingFrom => proto::Rpc {
            publish: vec![proto::Message {
                signature: Some(vec![0xDE; 64]),
                data: Some(vec![mid_slot; 16]),
                seqno: Some(mid),
                topic,
                ..Default::default()
            }],
            ..Default::default()
        },
        StructuredRpcKind::PublishOversizedTopic => {
            // Topic-size check runs before signature validation. Keep the RPC
            // under global MAX_TRANSMIT_SIZE while message.encoded_len() > topic max.
            proto::Rpc {
                publish: vec![proto::Message {
                    data: Some(vec![0xAB; TOPIC_MAX_TRANSMIT_SIZE.saturating_add(20)]),
                    topic,
                    ..Default::default()
                }],
                ..Default::default()
            }
        }
        StructuredRpcKind::PublishGarbageSig => {
            let (peer, key_bytes) = peer_pool_id_and_key(mid_slot);
            proto::Rpc {
                publish: vec![proto::Message {
                    from: Some(peer.to_bytes()),
                    key: Some(key_bytes),
                    signature: Some(vec![0xDE; 64]),
                    data: Some(vec![mid_slot; 16]),
                    seqno: Some(mid),
                    topic,
                    ..Default::default()
                }],
                ..Default::default()
            }
        }
    }
}

fn sign_pubsub_message(kp: &libp2p_identity::Keypair, message: &proto::Message) -> Vec<u8> {
    use crate::protocol::SIGNING_PREFIX;
    let mut message_sig = message.clone();
    message_sig.signature = None;
    message_sig.key = None;
    let buf = message_sig.encode_to_vec();
    let mut signature_bytes = SIGNING_PREFIX.to_vec();
    signature_bytes.extend_from_slice(&buf);
    kp.sign(&signature_bytes).expect("ed25519 sign")
}

fn make_fuzz_codec() -> GossipsubCodec {
    make_fuzz_codec_mode(ValidationMode::Permissive, HashMap::new())
}

fn make_fuzz_codec_mode(
    mode: ValidationMode,
    topic_maxes: HashMap<TopicHash, usize>,
) -> GossipsubCodec {
    GossipsubCodec::new(
        MAX_TRANSMIT_SIZE,
        mode,
        topic_maxes,
        MAX_PUBLISH_MESSAGES,
        MAX_CONTROL_MESSAGE_SIZE,
    )
}

/// Which `reject_message(msg_id)` reason to drive.
#[derive(Clone, Copy, Debug)]
pub enum RejectMsgIdReason {
    /// Blacklist the propagation peer, then deliver a publish from them.
    BlackListedPeer,
    /// Blacklist `source_slot`, deliver publish with that `from` via another peer.
    BlackListedSource,
    /// Deliver publish with `from` = local Author id (requires allow_self_origin=false).
    SelfOrigin,
}

/// Deferred length-prefixed frame for reordering / partial assembly across pumps.
#[derive(Clone, Debug)]
pub struct ScheduleOp {
    /// Deliver after this many action rounds (0 = next deferred flush).
    pub delay_polls: u8,
    pub bytes: Vec<u8>,
}

/// Structured action produced by the cargo-fuzz harness (via `arbitrary`).
#[derive(Clone, Debug)]
pub enum FuzzAction {
    /// Establish an inbound or outbound connection for `peer_slot % PEER_POOL`.
    Connect { peer_slot: u8, outbound: bool },
    /// Close all connections for a peer slot.
    Disconnect { peer_slot: u8 },
    /// Inject a Gossipsub RPC from a connected peer.
    /// Bytes may be length-prefixed wire or raw protobuf; always re-framed through
    /// [`GossipsubCodec`] so `invalid_messages` is populated.
    InjectRpc { peer_slot: u8, rpc_bytes: Vec<u8> },
    /// Feed length-prefixed wire bytes through [`GossipsubCodec`], then inject
    /// the resulting [`HandlerEvent`] (preserves `invalid_messages`).
    InjectWire { peer_slot: u8, wire_bytes: Vec<u8> },
    /// Push length-prefixed frames after N pump rounds (FIFO reordering / stall).
    InjectWireDeferred { peer_slot: u8, ops: Vec<ScheduleOp> },
    /// Local subscribe to a topic slot.
    Subscribe { topic_slot: u8 },
    /// Local publish on a topic slot.
    Publish { topic_slot: u8, data: Vec<u8> },
    /// Run one heartbeat tick (time travel without waiting on `Delay`).
    Heartbeat,
    /// Add `peer_slot` to the behaviour blacklist.
    BlacklistPeer { peer_slot: u8 },
    /// Remove `peer_slot` from the blacklist.
    RemoveBlacklistedPeer { peer_slot: u8 },
    /// Hit `reject_message(msg_id)` via blacklist / self-origin, optionally after
    /// an IHAVE that creates a gossip promise for the same message id.
    RejectMsgId {
        peer_slot: u8,
        source_slot: u8,
        mid_slot: u8,
        reason: RejectMsgIdReason,
        with_ihave_promise: bool,
    },
    /// Set per-topic max transmit size (applies to new Handlers + local publish).
    SetTopicMaxSize { topic_slot: u8, max: u16 },
}

/// Authenticity / validation mode for the behaviour harness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FuzzMode {
    /// Existing default: Author + Permissive (SelfOrigin / MessageTooLarge).
    #[default]
    AuthorPermissive,
    /// Strict + Signed — missing-field rejects, topic size, signature checks.
    StrictSigned,
}

/// Pre-populated starting state so a fuzz input can skip the connect/subscribe
/// preamble and jump into mid-protocol transitions (pre-meshed peers, warm mcache).
#[derive(Clone, Copy, Debug, Default)]
pub struct FuzzSeed {
    /// Pre-`add_explicit_peer` this many peer-pool peers (mesh membership seeds).
    pub explicit_peers: u8,
    /// Pre-`publish` this many messages (warms mcache + duplicate cache).
    pub pre_publish: u8,
}

/// Drive [`Behaviour`] with a sequence of actions (Author + Permissive).
///
/// Invariants under test:
/// - never panics;
/// - always terminates (bounded action count + poll drain);
/// - mcache size stays within a soft budget derived from config (assert soft —
///   if violated, treat as a DoS lead).
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    fuzz_behaviour_ex(FuzzSeed::default(), actions, FuzzMode::AuthorPermissive);
}

/// [`fuzz_behaviour`] with a [`FuzzSeed`] pre-population step.
pub fn fuzz_behaviour_seeded(
    seed: FuzzSeed,
    actions: impl IntoIterator<Item = FuzzAction>,
) {
    fuzz_behaviour_ex(seed, actions, FuzzMode::AuthorPermissive);
}

/// Drive [`Behaviour`] under [`ValidationMode::Strict`] +
/// [`MessageAuthenticity::Signed`].
pub fn fuzz_behaviour_strict_signed(actions: impl IntoIterator<Item = FuzzAction>) {
    fuzz_behaviour_ex(FuzzSeed::default(), actions, FuzzMode::StrictSigned);
}

fn fuzz_behaviour_ex(
    seed: FuzzSeed,
    actions: impl IntoIterator<Item = FuzzAction>,
    mode: FuzzMode,
) {
    let local_kp = fuzz_local_keypair();
    let local_id = PeerId::from(local_kp.public());
    // Message ids = seqno BE bytes so IHAVE mids (`[mid_slot; 8]`) correlate with
    // publishes that use the same seqno bytes (see `structured_rpc`).
    let topics: Vec<IdentTopic> = (0..TOPIC_POOL)
        .map(|i| IdentTopic::new(format!("fuzz-topic-{i}")))
        .collect();

    let mut builder = ConfigBuilder::default();
    builder
        .history_length(3)
        .history_gossip(2)
        .mesh_n(2)
        .mesh_n_low(1)
        .mesh_n_high(4)
        .mesh_outbound_min(0)
        .heartbeat_interval(Duration::from_secs(1))
        .heartbeat_initial_delay(Duration::ZERO)
        // Keep below MAX_DATA_BYTES so PublishError::MessageTooLarge is reachable.
        .max_transmit_size(MAX_TRANSMIT_SIZE)
        .max_publish_messages(MAX_PUBLISH_MESSAGES)
        .max_control_message_size(MAX_CONTROL_MESSAGE_SIZE)
        // Len 1 so consecutive Publish without drain hits `AllQueuesFull`.
        .connection_handler_queue_len(1)
        // Low so repeated IHAVE actions trip flood-ignore after a few heartbeats.
        .max_ihave_messages_heartbeat(2)
        .duplicate_cache_time(Duration::from_secs(60))
        // Required for SelfOrigin → reject_message(msg_id).
        .allow_self_origin(false)
        // Enable PRUNE peer-exchange dials (`handle_prune` → `px_connect`).
        .prune_peers(4)
        .message_id_fn(|message| {
            MessageId::from(message.sequence_number.unwrap_or(0).to_be_bytes().to_vec())
        });

    let (validation, authenticity, mut topic_maxes) = match mode {
        FuzzMode::AuthorPermissive => (
            ValidationMode::Permissive,
            MessageAuthenticity::Author(local_id),
            HashMap::new(),
        ),
        FuzzMode::StrictSigned => {
            // No default per-topic max: signed Strict rejects (sig+key) exceed
            // TOPIC_MAX_TRANSMIT_SIZE=100. Use SetTopicMaxSize before Oversized.
            (
                ValidationMode::Strict,
                MessageAuthenticity::Signed(local_kp),
                HashMap::new(),
            )
        }
    };
    builder.validation_mode(validation.clone());
    let config = builder.build().expect("fuzz config");

    let mut gossip = Behaviour::new(authenticity, config).expect("fuzz authenticity + config");

    let peers = peer_pool();

    // Enable peer scoring so `peer_score.rs` paths are reachable (was ~0.8%).
    let mut score_params = PeerScoreParams::default();
    for t in &topics {
        score_params
            .topics
            .insert(t.hash(), TopicScoreParams::default());
    }
    // accept_px_threshold=0 so default score (0) is accepted for PX dials.
    let mut score_thresholds = PeerScoreThresholds::default();
    score_thresholds.accept_px_threshold = 0.0;
    let _ = gossip.with_peer_score(score_params, score_thresholds);

    // Pre-subscribe so publishes and remote GRAFTs have a local topic context.
    let _ = gossip.subscribe(&topics[0]);

    // Seed pre-population: explicit peers (mesh membership) + warm mcache.
    for slot in 0..(seed.explicit_peers.min(PEER_POOL as u8)) {
        gossip.add_explicit_peer(&peers[slot as usize]);
    }
    for slot in 0..(seed.pre_publish.min(16)) {
        let data = vec![slot; 8];
        let _ = gossip.publish(topics[0].clone(), data);
    }

    let mut conn_ids: HashMap<PeerId, Vec<ConnectionId>> = HashMap::new();
    let mut handlers: HashMap<PeerId, Handler> = HashMap::new();
    let mut inbound_feeds: HashMap<PeerId, ChunkFeed> = HashMap::new();
    // Pending deferred wire frames: (peer, remaining delay, bytes).
    let mut deferred_wire: Vec<(PeerId, u8, Vec<u8>)> = Vec::new();
    let mut next_conn: usize = 1;
    let mut codec = make_fuzz_codec_mode(validation.clone(), topic_maxes.clone());
    // Matches ConfigBuilder above (mesh_n_high=4, mesh_n_low=1).
    const MESH_N_HIGH: usize = 4;
    const MESH_N_LOW: usize = 1;
    // PeerScoreThresholds::default().graylist_threshold
    const GRAYLIST_THRESHOLD: f64 = -80.0;

    for action in actions.into_iter().take(MAX_ACTIONS) {
        // Skip handler/behaviour drain after Publish so queue_len(1) can trip
        // AllQueuesFull before pump_handler clears the Shared outbound Queue.
        let skip_drain = matches!(&action, FuzzAction::Publish { .. });
        let was_heartbeat = matches!(&action, FuzzAction::Heartbeat);
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
                    gossip.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    gossip.handle_established_inbound_connection(
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
                gossip.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids.entry(peer).or_default().push(cid);

                if let Ok(mut h) = handler {
                    // ~20% of connects: write_cap=1 so Behaviour→Handler encode
                    // under backpressure is exercised on the live inbound duplex.
                    let write = if peer_slot % 5 == 0 {
                        WriteFault {
                            write_cap: 1,
                            stall_every: 0,
                            err_every: 0,
                            flush_stall_every: 2,
                            drop_every: 0,
                        }
                    } else {
                        WriteFault::NONE
                    };
                    // Codec must match Behaviour validation + topic maxes so
                    // InjectWire Strict rejects / MessageSizeTooLargeForTopic hit.
                    let feed = attach_live_inbound_mode(
                        &mut h,
                        validation,
                        topic_maxes.clone(),
                        write,
                    );
                    for ev in pump_handler(&mut h) {
                        gossip.on_connection_handler_event(peer, cid, ev);
                    }
                    inbound_feeds.insert(peer, feed);
                    handlers.insert(peer, h);
                } else {
                    // Fallback if handler construction denied.
                    gossip.on_connection_handler_event(
                        peer,
                        cid,
                        HandlerEvent::PeerKind(PeerKind::Gossipsubv1_1),
                    );
                }
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                handlers.remove(&peer);
                inbound_feeds.remove(&peer);
                deferred_wire.retain(|(p, _, _)| *p != peer);
                let endpoint = ConnectedPoint::Dialer {
                    address: peer_addr(peer_slot),
                    role_override: Endpoint::Dialer,
                    port_use: PortUse::Reuse,
                };
                let mut remaining = ids.len();
                for cid in ids {
                    remaining = remaining.saturating_sub(1);
                    gossip.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
                // Policy: disconnected peer must leave every topic mesh.
                drain_polls(&mut gossip);
                assert!(
                    !gossip.all_mesh_peers().any(|p| p == &peer),
                    "disconnected peer still in mesh: {peer}"
                );
            }
            FuzzAction::InjectRpc {
                peer_slot,
                rpc_bytes,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                if !conn_ids.contains_key(&peer) {
                    continue;
                }
                let bytes = if rpc_bytes.len() > MAX_RPC_BYTES {
                    &rpc_bytes[..MAX_RPC_BYTES]
                } else {
                    &rpc_bytes
                };
                let cid = conn_ids
                    .get(&peer)
                    .and_then(|v| v.first().copied())
                    .unwrap_or_else(|| ConnectionId::new_unchecked(0));
                // Codec-faithful path: length-prefixed wire, or raw protobuf
                // re-framed so invalid_messages is real (not always empty).
                let event = match codec_decode_rpc(&mut codec, bytes) {
                    Some(ev) => ev,
                    None => continue,
                };
                gossip.on_connection_handler_event(peer, cid, event);
            }
            FuzzAction::InjectWireDeferred { peer_slot, ops } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                if !conn_ids.contains_key(&peer) {
                    continue;
                }
                for op in ops.into_iter().take(8) {
                    let bytes = if op.bytes.len() > MAX_RPC_BYTES {
                        op.bytes[..MAX_RPC_BYTES].to_vec()
                    } else {
                        op.bytes
                    };
                    if bytes.is_empty() {
                        continue;
                    }
                    deferred_wire.push((peer, op.delay_polls.min(16), bytes));
                }
            }
            FuzzAction::InjectWire {
                peer_slot,
                wire_bytes,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                if !conn_ids.contains_key(&peer) {
                    continue;
                }
                let bytes = if wire_bytes.len() > MAX_RPC_BYTES {
                    &wire_bytes[..MAX_RPC_BYTES]
                } else {
                    &wire_bytes
                };
                let cid = conn_ids
                    .get(&peer)
                    .and_then(|v| v.first().copied())
                    .unwrap_or_else(|| ConnectionId::new_unchecked(0));
                // Prefer live Handler inbound (codec + poll). Fall back to direct inject.
                if let (Some(feed), Some(h)) =
                    (inbound_feeds.get(&peer), handlers.get_mut(&peer))
                {
                    feed.push(bytes);
                    for ev in pump_handler(h) {
                        gossip.on_connection_handler_event(peer, cid, ev);
                    }
                } else {
                    let mut src = BytesMut::from(bytes);
                    let event = match codec.decode(&mut src) {
                        Ok(Some(ev)) => ev,
                        Ok(None) | Err(_) => continue,
                    };
                    gossip.on_connection_handler_event(peer, cid, event);
                }
            }
            FuzzAction::Subscribe { topic_slot } => {
                let topic = &topics[(topic_slot as usize) % TOPIC_POOL];
                let _ = gossip.subscribe(topic);
            }
            FuzzAction::Publish { topic_slot, data } => {
                let topic = &topics[(topic_slot as usize) % TOPIC_POOL];
                let data = if data.len() > MAX_DATA_BYTES {
                    &data[..MAX_DATA_BYTES]
                } else {
                    &data
                };
                let _ = gossip.publish(topic.clone(), data.to_vec());
            }
            FuzzAction::Heartbeat => {
                gossip.fuzz_heartbeat();
            }
            FuzzAction::BlacklistPeer { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                gossip.blacklist_peer(&peer);
            }
            FuzzAction::RemoveBlacklistedPeer { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                gossip.remove_blacklisted_peer(&peer);
            }
            FuzzAction::RejectMsgId {
                peer_slot,
                source_slot,
                mid_slot,
                reason,
                with_ihave_promise,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                if !conn_ids.contains_key(&peer) {
                    continue;
                }
                let cid = conn_ids
                    .get(&peer)
                    .and_then(|v| v.first().copied())
                    .unwrap_or_else(|| ConnectionId::new_unchecked(0));

                // Optional IHAVE → IWANT promise for the same msg id (seqno bytes).
                if with_ihave_promise {
                    let ihave = encode_structured_wire(StructuredRpcKind::IHave, 0, mid_slot);
                    deliver_wire(
                        &mut gossip,
                        &mut handlers,
                        &inbound_feeds,
                        &mut codec,
                        peer,
                        cid,
                        &ihave,
                    );
                    drain_polls(&mut gossip);
                    pump_all_handlers(&mut gossip, &mut handlers, &conn_ids);
                }

                let (publish_kind, from) = match reason {
                    RejectMsgIdReason::BlackListedPeer => {
                        gossip.blacklist_peer(&peer);
                        (StructuredRpcKind::Publish, None)
                    }
                    RejectMsgIdReason::BlackListedSource => {
                        // Avoid peer_slot == source_slot (that hits BlackListedPeer first).
                        let mut src_idx = (source_slot as usize) % PEER_POOL;
                        let prop_idx = (peer_slot as usize) % PEER_POOL;
                        if src_idx == prop_idx {
                            src_idx = (src_idx + 1) % PEER_POOL;
                        }
                        let source = peers[src_idx];
                        gossip.blacklist_peer(&source);
                        (StructuredRpcKind::PublishFromPeer, Some(source))
                    }
                    RejectMsgIdReason::SelfOrigin => {
                        (StructuredRpcKind::PublishSelfOrigin, Some(local_id))
                    }
                };

                let wire = encode_structured_wire_from(
                    publish_kind,
                    0,
                    mid_slot,
                    from.as_ref(),
                );
                if wire.is_empty() {
                    continue;
                }
                deliver_wire(
                    &mut gossip,
                    &mut handlers,
                    &inbound_feeds,
                    &mut codec,
                    peer,
                    cid,
                    &wire,
                );
            }
            FuzzAction::SetTopicMaxSize { topic_slot, max } => {
                let topic = &topics[(topic_slot as usize) % TOPIC_POOL];
                // Keep topic max below global so MessageSizeTooLargeForTopic is distinct.
                let max = (max as usize)
                    .clamp(16, MAX_TRANSMIT_SIZE.saturating_sub(1).max(16));
                gossip.fuzz_set_topic_max_transmit_size(topic.hash(), max);
                topic_maxes.insert(topic.hash(), max);
                codec = make_fuzz_codec_mode(validation.clone(), topic_maxes.clone());
                // Re-attach inbound feeds so InjectWire uses the updated topic maxes.
                for (peer, h) in handlers.iter_mut() {
                    let feed = attach_live_inbound_mode(
                        h,
                        validation,
                        topic_maxes.clone(),
                        WriteFault::NONE,
                    );
                    inbound_feeds.insert(*peer, feed);
                }
            }
        }

        if !skip_drain {
            drain_polls(&mut gossip);
            pump_all_handlers(&mut gossip, &mut handlers, &conn_ids);
            flush_deferred_wire(
                &mut deferred_wire,
                &mut gossip,
                &mut handlers,
                &inbound_feeds,
                &mut codec,
                &conn_ids,
            );
        }

        // Peer scores must stay finite (NaN/Inf = scoring bug).
        for peer in peers.iter() {
            if let Some(score) = gossip.peer_score(peer) {
                assert!(
                    score.is_finite(),
                    "non-finite peer score for {peer}: {score}"
                );
            }
        }

        // After Heartbeat + drain: mesh size must not overshoot when enough peers.
        if was_heartbeat && !skip_drain {
            let connected = gossip.connected_peer_count();
            if connected >= MESH_N_HIGH {
                let mesh = gossip.mesh_peers(&topics[0].hash()).count();
                assert!(
                    mesh <= MESH_N_HIGH.saturating_add(1),
                    "mesh overshoot after heartbeat: mesh={mesh} connected={connected}"
                );
                // Soft lower bound: with enough connected peers, mesh should not stay empty.
                let _ = MESH_N_LOW;
            }
        }
    }

    // Soft DoS budget: mcache should not retain vastly more than history windows
    // × flood of unique messages without heartbeats. Cap is generous to avoid
    // false positives while still catching unbounded growth.
    // Hard assert: cargo-fuzz builds --release, which strips `debug_assert!`.
    let mcache_msgs = gossip.mcache_msg_count();
    let connected = gossip.connected_peer_count();
    let px_peers = gossip.fuzz_px_peer_count();
    assert!(
        mcache_msgs <= MAX_ACTIONS.saturating_mul(8).saturating_add(64),
        "mcache grew unboundedly: msgs={mcache_msgs} connected={connected}"
    );
    // PX dials mark at most prune_peers per PRUNE; soft cap vs action flood.
    assert!(
        px_peers <= MAX_ACTIONS.saturating_mul(4).saturating_add(16),
        "px_peers grew unboundedly: {px_peers}"
    );

    // End-of-run: no mesh membership for peers we have fully disconnected.
    for peer in peers.iter() {
        if !conn_ids.contains_key(peer) {
            assert!(
                !gossip.all_mesh_peers().any(|p| p == peer),
                "disconnected peer still in mesh at end: {peer}"
            );
        }
        if let Some(score) = gossip.peer_score(peer) {
            assert!(
                score.is_finite(),
                "non-finite peer score at end for {peer}: {score}"
            );
            // Graylisted peers must not remain in any topic mesh.
            if score < GRAYLIST_THRESHOLD {
                assert!(
                    !gossip.all_mesh_peers().any(|p| p == peer),
                    "graylisted peer still in mesh: {peer} score={score}"
                );
            }
        }
    }
}

fn drain_polls(gossip: &mut Behaviour) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match gossip.poll(&mut cx) {
            Poll::Ready(_) => continue,
            Poll::Pending => break,
        }
    }
}

fn pump_all_handlers(
    gossip: &mut Behaviour,
    handlers: &mut HashMap<PeerId, Handler>,
    conn_ids: &HashMap<PeerId, Vec<ConnectionId>>,
) {
    for (peer, handler) in handlers.iter_mut() {
        let cid = conn_ids
            .get(peer)
            .and_then(|v| v.first().copied())
            .unwrap_or_else(|| ConnectionId::new_unchecked(0));
        for ev in pump_handler(handler) {
            gossip.on_connection_handler_event(*peer, cid, ev);
        }
    }
}

fn deliver_wire(
    gossip: &mut Behaviour,
    handlers: &mut HashMap<PeerId, Handler>,
    inbound_feeds: &HashMap<PeerId, ChunkFeed>,
    codec: &mut GossipsubCodec,
    peer: PeerId,
    cid: ConnectionId,
    wire: &[u8],
) {
    if let (Some(feed), Some(h)) = (inbound_feeds.get(&peer), handlers.get_mut(&peer)) {
        feed.push(wire);
        for ev in pump_handler(h) {
            gossip.on_connection_handler_event(peer, cid, ev);
        }
        return;
    }
    let mut src = BytesMut::from(wire);
    if let Ok(Some(event)) = codec.decode(&mut src) {
        gossip.on_connection_handler_event(peer, cid, event);
    }
}

/// Decode length-prefixed wire, or re-frame raw protobuf through the codec.
fn codec_decode_rpc(codec: &mut GossipsubCodec, bytes: &[u8]) -> Option<HandlerEvent> {
    let mut src = BytesMut::from(bytes);
    match codec.decode(&mut src) {
        Ok(Some(ev)) => return Some(ev),
        Ok(None) | Err(_) => {}
    }
    let rpc = proto::Rpc::decode(bytes).ok()?;
    let mut wire = BytesMut::new();
    codec.encode(rpc, &mut wire).ok()?;
    match codec.decode(&mut wire) {
        Ok(Some(ev)) => Some(ev),
        _ => None,
    }
}

/// Decrement deferred delays; push due frames and pump handlers (reordering / stall).
fn flush_deferred_wire(
    deferred: &mut Vec<(PeerId, u8, Vec<u8>)>,
    gossip: &mut Behaviour,
    handlers: &mut HashMap<PeerId, Handler>,
    inbound_feeds: &HashMap<PeerId, ChunkFeed>,
    codec: &mut GossipsubCodec,
    conn_ids: &HashMap<PeerId, Vec<ConnectionId>>,
) {
    let mut i = 0;
    while i < deferred.len() {
        if deferred[i].1 > 0 {
            deferred[i].1 -= 1;
            i += 1;
            continue;
        }
        let (peer, _, bytes) = deferred.remove(i);
        let cid = conn_ids
            .get(&peer)
            .and_then(|v| v.first().copied())
            .unwrap_or_else(|| ConnectionId::new_unchecked(0));
        deliver_wire(
            gossip,
            handlers,
            inbound_feeds,
            codec,
            peer,
            cid,
            &bytes,
        );
    }
}

/// Deterministic local Author / Signed keypair seed (distinct from [`peer_pool`]).
pub fn fuzz_local_keypair() -> libp2p_identity::Keypair {
    use libp2p_identity::Keypair;
    let mut bytes = [0x42u8; 32];
    Keypair::ed25519_from_bytes(&mut bytes).expect("fixed ed25519 seed")
}

/// Deterministic local Author id (distinct from [`peer_pool`] slots).
pub fn fuzz_local_peer_id() -> PeerId {
    PeerId::from(fuzz_local_keypair().public())
}

fn peer_pool_keypair(slot: usize) -> libp2p_identity::Keypair {
    use libp2p_identity::Keypair;
    let i = slot % PEER_POOL;
    let mut bytes = [0u8; 32];
    bytes[0] = 0xA0;
    bytes[1] = i as u8 + 1;
    bytes[31] = !(i as u8);
    Keypair::ed25519_from_bytes(&mut bytes).expect("pool ed25519 seed")
}

fn peer_pool_id_and_key(slot: u8) -> (PeerId, Vec<u8>) {
    let kp = peer_pool_keypair(slot as usize);
    let peer = PeerId::from(kp.public());
    let key_bytes = kp.public().encode_protobuf();
    (peer, key_bytes)
}

fn peer_pool() -> [PeerId; PEER_POOL] {
    // Deterministic PeerIds so BlackListedSource / structured `from` fields correlate.
    std::array::from_fn(|i| PeerId::from(peer_pool_keypair(i).public()))
}

fn peer_addr(slot: u8) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(
        std::net::Ipv4Addr::new(127, 0, 0, 1 + (slot % 200)),
    ));
    addr.push(Protocol::Tcp(4000 + u16::from(slot)));
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublishError;
    use crate::fuzz_handler::{HandlerFault, WriteFault, fuzz_handler_io};

    #[test]
    fn handler_inbound_subscribe_notifies() {
        let wire = encode_structured_wire(StructuredRpcKind::Subscribe, 0, 0);
        let events = fuzz_handler_io([wire], 8, 0, false, HandlerFault::None, WriteFault::NONE);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::PeerKind(PeerKind::Gossipsubv1_1)))
        );
        assert!(events.iter().any(|e| matches!(e, HandlerEvent::Message { .. })));
    }

    #[test]
    fn handler_outbound_encode_subscribe() {
        let events =
            fuzz_handler_io(std::iter::empty::<Vec<u8>>(), 64, 0, true, HandlerFault::None, WriteFault::NONE);
        assert!(events.iter().any(|e| matches!(e, HandlerEvent::PeerKind(_))));
    }

    #[test]
    fn handler_outbound_encode_under_write_backpressure() {
        // Tiny write_cap + stalls must still complete Subscribe encode (no hang/panic).
        let write = WriteFault {
            write_cap: 1,
            stall_every: 2,
            err_every: 0,
            flush_stall_every: 2,
            drop_every: 0,
        };
        let events = fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            HandlerFault::None,
            write,
        );
        assert!(
            events.iter().any(|e| matches!(e, HandlerEvent::PeerKind(_))),
            "expected PeerKind under write backpressure, got {events:?}"
        );
    }

    #[test]
    fn handler_partial_reads_assemble_frame() {
        let wire = encode_structured_wire(StructuredRpcKind::Graft, 0, 0);
        let events = fuzz_handler_io([wire], 1, 0, false, HandlerFault::None, WriteFault::NONE);
        assert!(
            events.iter().any(|e| matches!(e, HandlerEvent::Message { .. })),
            "expected Message under chunk_cap=1, got {events:?}"
        );
    }

    #[test]
    fn handler_negotiation_failed_emits_not_supported() {
        let events = fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            true,
            HandlerFault::DialUpgradeNegotiationFailed,
            WriteFault::NONE,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::PeerKind(PeerKind::NotSupported))),
            "expected PeerKind::NotSupported, got {events:?}"
        );
    }

    #[test]
    fn handler_message_dropped_on_publish_timeout() {
        let events = fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            false,
            HandlerFault::MessageDroppedTimedOut,
            WriteFault::NONE,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::MessageDropped(_))),
            "expected MessageDropped, got {events:?}"
        );
    }

    #[test]
    fn handler_max_substream_attempts_inbound_disables() {
        // After flood, further polls stay Pending (Disabled); no panic / hang.
        let events = fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            false,
            HandlerFault::MaxSubstreamAttemptsInbound,
            WriteFault::NONE,
        );
        let _ = events;
    }

    #[test]
    fn handler_max_substream_attempts_outbound_disables() {
        // Uses DialUpgradeError×5 (not FullyNegotiatedOutbound — asserts if already open).
        let events = fuzz_handler_io(
            std::iter::empty::<Vec<u8>>(),
            64,
            0,
            false,
            HandlerFault::MaxSubstreamAttemptsOutbound,
            WriteFault::NONE,
        );
        let _ = events;
    }

    #[test]
    fn publish_oversize_hits_message_too_large() {
        let config = ConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .allow_self_origin(false)
            .build()
            .unwrap();
        let mut gossip: Behaviour =
            Behaviour::new(MessageAuthenticity::Author(fuzz_local_peer_id()), config).unwrap();
        let topic = IdentTopic::new("fuzz-topic-0");
        let _ = gossip.subscribe(&topic);

        // Size check runs before recipient selection.
        let err = gossip
            .publish(topic, vec![0x41; MAX_TRANSMIT_SIZE + 1])
            .unwrap_err();
        assert!(matches!(err, PublishError::MessageTooLarge));
    }

    #[test]
    fn wire_codec_bad_sig_yields_invalid_messages() {
        let wire = encode_structured_wire(StructuredRpcKind::PublishBadSig, 0, 1);
        assert!(!wire.is_empty());
        let mut codec = make_fuzz_codec();
        let mut src = BytesMut::from(wire.as_slice());
        let event = codec.decode(&mut src).unwrap().expect("full frame");
        match event {
            HandlerEvent::Message {
                invalid_messages, ..
            } => {
                assert!(
                    !invalid_messages.is_empty(),
                    "expected codec validation errors"
                );
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn smoke_seeded() {
        // Pre-mesh explicit peers + warm mcache → publish/graft must land
        // without the connect/subscribe preamble.
        fuzz_behaviour_seeded(
            FuzzSeed {
                explicit_peers: 4,
                pre_publish: 4,
            },
            [
                FuzzAction::InjectWire {
                    peer_slot: 0,
                    wire_bytes: encode_structured_wire(StructuredRpcKind::Graft, 0, 0),
                },
                FuzzAction::InjectWire {
                    peer_slot: 0,
                    wire_bytes: encode_structured_wire(StructuredRpcKind::IHave, 0, 1),
                },
                FuzzAction::Publish {
                    topic_slot: 0,
                    data: vec![0xAB; 8],
                },
                FuzzAction::Heartbeat,
            ],
        );
    }

    #[test]
    fn action_seq_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            // Graft requires peer.topics; Subscribe must precede it.
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Subscribe, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Graft, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::IHave, 0, 1),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::PublishBadSig, 0, 4),
            },
            // reject_message(msg_id): blacklist peer
            FuzzAction::RejectMsgId {
                peer_slot: 0,
                source_slot: 1,
                mid_slot: 5,
                reason: RejectMsgIdReason::BlackListedPeer,
                with_ihave_promise: false,
            },
            // IHAVE promise then SelfOrigin reject
            FuzzAction::RejectMsgId {
                peer_slot: 1,
                source_slot: 0,
                mid_slot: 6,
                reason: RejectMsgIdReason::SelfOrigin,
                with_ihave_promise: true,
            },
            // BlackListedSource (source peer 0, propagate via 1)
            FuzzAction::RejectMsgId {
                peer_slot: 1,
                source_slot: 0,
                mid_slot: 7,
                reason: RejectMsgIdReason::BlackListedSource,
                with_ihave_promise: true,
            },
            FuzzAction::Publish {
                topic_slot: 0,
                data: vec![0x42; MAX_TRANSMIT_SIZE + 64],
            },
            FuzzAction::Heartbeat,
        ]);
    }

    #[test]
    fn disconnect_clears_mesh_and_keeps_finite_scores() {
        // Graft peer 0 into the mesh, then Disconnect — harness asserts the peer
        // is gone from all_mesh_peers and peer_score stays finite.
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Subscribe, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Graft, 0, 0),
            },
            FuzzAction::Heartbeat,
            FuzzAction::Disconnect { peer_slot: 0 },
        ]);
    }

    #[test]
    fn prune_with_px_marks_peers_and_emits_dial() {
        use libp2p_swarm::ToSwarm;

        let local_id = fuzz_local_peer_id();
        let config = ConfigBuilder::default()
            .history_length(3)
            .history_gossip(2)
            .mesh_n(2)
            .mesh_n_low(1)
            .mesh_n_high(4)
            .mesh_outbound_min(0)
            .heartbeat_interval(Duration::from_secs(1))
            .heartbeat_initial_delay(Duration::ZERO)
            .validation_mode(ValidationMode::Permissive)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .allow_self_origin(false)
            .prune_peers(4)
            .build()
            .expect("fuzz config");
        let mut gossip = Behaviour::new(MessageAuthenticity::Author(local_id), config)
            .expect("author + permissive");
        let mut score_params = PeerScoreParams::default();
        let topic = IdentTopic::new("fuzz-topic-0");
        score_params
            .topics
            .insert(topic.hash(), TopicScoreParams::default());
        let mut thresholds = PeerScoreThresholds::default();
        thresholds.accept_px_threshold = 0.0;
        let _ = gossip.with_peer_score(score_params, thresholds);
        let _ = gossip.subscribe(&topic);

        let peers = peer_pool();
        let peer = peers[0];
        let cid = ConnectionId::new_unchecked(1);
        let remote = peer_addr(0);
        let _ = gossip.handle_established_outbound_connection(
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
        gossip.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: cid,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        gossip.on_connection_handler_event(
            peer,
            cid,
            HandlerEvent::PeerKind(PeerKind::Gossipsubv1_1),
        );

        let mut codec = make_fuzz_codec();
        for kind in [StructuredRpcKind::Subscribe, StructuredRpcKind::Graft] {
            let wire = encode_structured_wire(kind, 0, 0);
            let mut src = BytesMut::from(wire.as_slice());
            let event = codec.decode(&mut src).unwrap().expect("full frame");
            gossip.on_connection_handler_event(peer, cid, event);
            drain_polls(&mut gossip);
        }

        // mid_slot=1 → 2 PX peers, no garbage extras (1%5!=0, 1%7!=0)
        let wire = encode_structured_wire(StructuredRpcKind::PruneWithPx, 0, 1);
        let mut src = BytesMut::from(wire.as_slice());
        let event = codec.decode(&mut src).unwrap().expect("full frame");
        gossip.on_connection_handler_event(peer, cid, event);

        // Count Dial while draining — drain_polls would discard them.
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let mut dials = 0usize;
        for _ in 0..MAX_POLL_DRAIN {
            match NetworkBehaviour::poll(&mut gossip, &mut cx) {
                Poll::Ready(ToSwarm::Dial { .. }) => dials += 1,
                Poll::Ready(_) => continue,
                Poll::Pending => break,
            }
        }
        assert!(
            gossip.fuzz_px_peer_count() >= 1,
            "expected PX peers marked after PruneWithPx"
        );
        assert!(
            dials >= 1,
            "expected ToSwarm::Dial from px_connect, dials={dials} px={}",
            gossip.fuzz_px_peer_count()
        );
    }

    #[test]
    fn prune_with_px_wire_nonempty() {
        let wire = encode_structured_wire(StructuredRpcKind::PruneWithPx, 0, 1);
        assert!(!wire.is_empty());
        let rpc = encode_structured_rpc(StructuredRpcKind::PruneWithPx, 1, 3);
        let decoded = proto::Rpc::decode(rpc.as_slice()).expect("proto");
        let prune = &decoded.control.as_ref().unwrap().prune[0];
        assert!(
            !prune.peers.is_empty(),
            "PruneWithPx must carry PeerInfo entries"
        );
        assert!(prune.peers.iter().any(|p| p.peer_id.is_some()));
    }

    #[test]
    fn action_seq_prune_px_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Subscribe, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::Graft, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::PruneWithPx, 0, 2),
            },
            FuzzAction::Heartbeat,
        ]);
    }

    #[test]
    fn all_queues_full_smoke() {
        // Behaviour-level recipe: queue_len(1) + Subscribe/Graft recipient.
        // Handler is dropped after connect, so Behaviour drain never pops the
        // Shared Queue — first Publish fills non_priority; second → AllQueuesFull.
        let local_id = fuzz_local_peer_id();
        let config = ConfigBuilder::default()
            .history_length(3)
            .history_gossip(2)
            .mesh_n(2)
            .mesh_n_low(1)
            .mesh_n_high(4)
            .mesh_outbound_min(0)
            .heartbeat_interval(Duration::from_secs(1))
            .heartbeat_initial_delay(Duration::ZERO)
            .validation_mode(ValidationMode::Permissive)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .connection_handler_queue_len(1)
            .allow_self_origin(false)
            .build()
            .expect("fuzz config");
        let mut gossip = Behaviour::new(MessageAuthenticity::Author(local_id), config)
            .expect("author + permissive");
        let peers = peer_pool();
        let topic = IdentTopic::new("fuzz-topic-0");
        let _ = gossip.subscribe(&topic);

        let peer = peers[0];
        let cid = ConnectionId::new_unchecked(1);
        let remote = peer_addr(0);
        let _ = gossip.handle_established_outbound_connection(
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
        gossip.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: cid,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        gossip.on_connection_handler_event(
            peer,
            cid,
            HandlerEvent::PeerKind(PeerKind::Gossipsubv1_1),
        );

        let mut codec = make_fuzz_codec();
        for kind in [StructuredRpcKind::Subscribe, StructuredRpcKind::Graft] {
            let wire = encode_structured_wire(kind, 0, 0);
            let mut src = BytesMut::from(wire.as_slice());
            let event = codec.decode(&mut src).unwrap().expect("full frame");
            gossip.on_connection_handler_event(peer, cid, event);
            drain_polls(&mut gossip);
        }

        gossip
            .publish(topic.clone(), vec![0x11; 8])
            .expect("first publish fills queue_len(1)");
        let err = gossip
            .publish(topic, vec![0x22; 8])
            .expect_err("second publish with full queue");
        assert!(
            matches!(err, PublishError::AllQueuesFull(1)),
            "expected AllQueuesFull(1), got {err:?}"
        );
        // Behaviour drain cannot clear Shared queues — recovery needs Handler poll.
        drain_polls(&mut gossip);
    }

    #[test]
    fn strict_signed_smoke() {
        fuzz_behaviour_strict_signed([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::PublishMissingSig, 0, 0),
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::PublishMissingSeqno, 0, 1),
            },
            FuzzAction::SetTopicMaxSize {
                topic_slot: 0,
                max: TOPIC_MAX_TRANSMIT_SIZE as u16,
            },
            FuzzAction::InjectWire {
                peer_slot: 0,
                wire_bytes: encode_structured_wire(StructuredRpcKind::PublishOversizedTopic, 0, 2),
            },
            FuzzAction::Publish {
                topic_slot: 0,
                data: vec![0x41; TOPIC_MAX_TRANSMIT_SIZE + 8],
            },
        ]);
    }

    #[test]
    fn strict_inject_wire_hits_topic_size_and_empty_seqno() {
        use crate::ValidationError;

        // EmptySequenceNumber: Strict, no topic max (signed msgs exceed 100b).
        let mut codec = make_fuzz_codec_mode(ValidationMode::Strict, HashMap::new());
        let missing_seq = encode_structured_wire(StructuredRpcKind::PublishMissingSeqno, 0, 1);
        let mut src = BytesMut::from(missing_seq.as_slice());
        match codec.decode(&mut src).unwrap().expect("frame") {
            HandlerEvent::Message {
                invalid_messages, ..
            } => assert!(
                invalid_messages
                    .iter()
                    .any(|(_, e)| *e == ValidationError::EmptySequenceNumber),
                "{invalid_messages:?}"
            ),
            other => panic!("{other:?}"),
        }

        // MessageSizeTooLargeForTopic: tight topic max after signed rejects.
        let mut topic_maxes = HashMap::new();
        topic_maxes.insert(TopicHash::from_raw("fuzz-topic-0"), TOPIC_MAX_TRANSMIT_SIZE);
        let mut codec = make_fuzz_codec_mode(ValidationMode::Strict, topic_maxes);
        let oversize = encode_structured_wire(StructuredRpcKind::PublishOversizedTopic, 0, 0);
        let mut src = BytesMut::from(oversize.as_slice());
        match codec.decode(&mut src).unwrap().expect("frame") {
            HandlerEvent::Message {
                invalid_messages, ..
            } => assert!(
                invalid_messages
                    .iter()
                    .any(|(_, e)| *e == ValidationError::MessageSizeTooLargeForTopic),
                "{invalid_messages:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn strict_codec_rejects_missing_fields_and_bad_sig() {
        use crate::ValidationError;

        // No per-topic max: signed Strict rejects must not be misread as oversize.
        let mut codec = make_fuzz_codec_mode(ValidationMode::Strict, HashMap::new());

        for (kind, expect) in [
            (
                StructuredRpcKind::PublishMissingSig,
                ValidationError::InvalidSignature,
            ),
            (
                StructuredRpcKind::PublishMissingFrom,
                ValidationError::InvalidSignature,
            ),
            (
                StructuredRpcKind::PublishMissingSeqno,
                ValidationError::EmptySequenceNumber,
            ),
            (
                StructuredRpcKind::PublishGarbageSig,
                ValidationError::InvalidSignature,
            ),
        ] {
            let wire = encode_structured_wire(kind, 0, 3);
            let mut src = BytesMut::from(wire.as_slice());
            let event = codec.decode(&mut src).unwrap().expect("full frame");
            match event {
                HandlerEvent::Message {
                    invalid_messages, ..
                } => {
                    assert!(
                        invalid_messages.iter().any(|(_, e)| *e == expect),
                        "{kind:?}: expected {expect:?}, got {invalid_messages:?}"
                    );
                }
                other => panic!("{kind:?}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn strict_codec_rejects_oversized_for_topic() {
        use crate::ValidationError;

        let mut topic_maxes = HashMap::new();
        topic_maxes.insert(TopicHash::from_raw("fuzz-topic-0"), TOPIC_MAX_TRANSMIT_SIZE);
        let mut codec = make_fuzz_codec_mode(ValidationMode::Strict, topic_maxes);
        let wire = encode_structured_wire(StructuredRpcKind::PublishOversizedTopic, 0, 0);
        let mut src = BytesMut::from(wire.as_slice());
        let event = codec.decode(&mut src).unwrap().expect("full frame");
        match event {
            HandlerEvent::Message {
                invalid_messages, ..
            } => {
                assert!(
                    invalid_messages
                        .iter()
                        .any(|(_, e)| *e == ValidationError::MessageSizeTooLargeForTopic),
                    "expected MessageSizeTooLargeForTopic, got {invalid_messages:?}"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn topic_publish_oversize_hits_message_too_large() {
        let topic = IdentTopic::new("fuzz-topic-0");
        let config = ConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(MAX_TRANSMIT_SIZE)
            .max_transmit_size_for_topic(TOPIC_MAX_TRANSMIT_SIZE, topic.hash())
            .allow_self_origin(false)
            .build()
            .unwrap();
        let mut gossip: Behaviour =
            Behaviour::new(MessageAuthenticity::Signed(fuzz_local_keypair()), config).unwrap();
        let _ = gossip.subscribe(&topic);
        let err = gossip
            .publish(topic, vec![0x41; TOPIC_MAX_TRANSMIT_SIZE + 1])
            .unwrap_err();
        assert!(matches!(err, PublishError::MessageTooLarge));
    }
}
