#![no_main]

//! Action-sequence fuzzer for the Swarm orchestrator.
//!
//! Drives real [`Swarm`]s over [`MemoryTransport`] + **Noise XX / TLS / plaintext**
//! + yamux, or whole-mesh **QUIC** (`/ip4/127.0.0.1/udp/0/quic-v1`) with a
//! composed Behaviour: [`connection_limits`] + gossipsub + Kademlia + **Identify**.
//! Transport is chosen per input (whole mesh; mixed security cannot interconnect).
//! Biases Noise; TLS (~⅛) and QUIC (~⅛) exercise cert/ALPN / UDP upgrade races
//! under the same dial+limits surface.
//!
//! Dict: `dicts/swarm.dict`. Seeds: `seeds/swarm_orchestrator/`.
//!
//! When Noise/TLS is selected, ~¼ of meshes wrap MemoryTransport I/O with
//! [`TransportFault`] (drop after first XX frame / flip a byte in msg2) so
//! mid-handshake auth races warm beyond dial+poll-budget alone. QUIC mid-
//! handshake corrupt stays in `quic_handshake` — [`TransportFault`] is Noise/TLS-only.
//!
//! Invariants (panic = finding):
//! - Event-tracked peer/connection counts stay aligned with `Swarm::is_connected`
//!   / `connected_peers` (catches forgotten `ConnectionClosed` bookkeeping leaks).
//! - Soft DoS clamps on swarm count, established totals, and tracked maps.
//! - Identify discovered-peer LRU stays ≤ configured cache size.
//!
//! Time is paused (`tokio::time::pause`) so Poll actions can advance the clock
//! and hit idle-connection-timeout vs hard `CloseConnection` / `Disconnect`.

use std::{
    collections::HashMap,
    io,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{AsyncRead, AsyncWrite, Stream, future::poll_fn};
use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use libp2p_connection_limits::{Behaviour as LimitsBehaviour, ConnectionLimits};
use libp2p_core::{
    Multiaddr, Transport,
    multiaddr::Protocol,
    muxing::StreamMuxerBox,
    transport::MemoryTransport,
    upgrade::Version,
};
use libp2p_gossipsub::{
    Behaviour as GossipsubBehaviour, ConfigBuilder as GossipsubConfigBuilder, IdentTopic,
    MessageAuthenticity, ValidationMode,
};
use libp2p_identify::{Behaviour as IdentifyBehaviour, Config as IdentifyConfig};
use libp2p_identity::{Keypair, PeerId};
use libp2p_kad::{
    Behaviour as KadBehaviour, Config as KadConfig, Mode, Quorum, Record, RecordKey,
    store::{MemoryStore, MemoryStoreConfig},
};
use libp2p_noise as noise;
use libp2p_plaintext as plaintext;
use libp2p_quic as quic;
use libp2p_swarm::{
    ConnectionId, NetworkBehaviour, Swarm, SwarmEvent,
    Config as SwarmConfig,
    dial_opts::{DialOpts, PeerCondition},
};
use libp2p_tls as tls;
use libp2p_yamux as yamux;

/// Whole-mesh security upgrade (mixed meshes cannot interconnect).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Security {
    Plaintext,
    Noise,
    Tls,
    /// Whole-mesh QUIC (UDP loopback). Cannot mix with MemoryTransport peers.
    Quic,
}

impl Security {
    fn needs_extra_poll(self) -> bool {
        matches!(self, Security::Noise | Security::Tls | Security::Quic)
    }

    fn is_quic(self) -> bool {
        matches!(self, Security::Quic)
    }

    /// Mid-handshake MemoryTransport faults apply only to Noise/TLS (not QUIC).
    fn allows_transport_fault(self) -> bool {
        matches!(self, Security::Noise | Security::Tls)
    }
}

const MAX_SWARMS: usize = 4;
const MIN_SWARMS: usize = 2;
const MAX_ACTIONS: usize = 48;
const MAX_POLL_PER_ACTION: usize = 64;
const MAX_TOTAL_POLLS: usize = 2_048;
const MAX_CONN_IDS: usize = 64;
const MAX_ESTABLISHED_SOFT: u32 = 32;
const TOPIC_POOL: usize = 2;
const MAX_PUBLISH_BYTES: usize = 128;
const MAX_RECORD_BYTES: usize = 64;
const IDENTIFY_CACHE_SIZE: usize = 16;

/// Mid-handshake fault applied under MemoryTransport before Noise/plaintext.
#[derive(Clone, Copy, Debug, Default)]
enum TransportFault {
    #[default]
    None,
    /// After the first complete u16-BE length-prefixed frame, subsequent I/O fails.
    DropAfterNoiseMsg1,
    /// Flip one byte inside the second length-prefixed frame at payload offset `at`.
    FlipByteInMsg2 { at: u8 },
}

/// Wraps a MemoryTransport channel to inject handshake-level faults.
struct FaultyIo<T> {
    inner: T,
    fault: TransportFault,
    /// Bytes seen on this direction for frame assembly (read side).
    read_buf: Vec<u8>,
    /// Complete frames observed on read.
    frames_read: u8,
    /// Complete frames observed on write.
    frames_written: u8,
    write_pending: Vec<u8>,
    dead: bool,
    flip_done: bool,
}

impl<T> FaultyIo<T> {
    fn new(inner: T, fault: TransportFault) -> Self {
        Self {
            inner,
            fault,
            read_buf: Vec::new(),
            frames_read: 0,
            frames_written: 0,
            write_pending: Vec::new(),
            dead: false,
            flip_done: false,
        }
    }

    fn maybe_kill_after_msg1(&mut self) {
        if matches!(self.fault, TransportFault::DropAfterNoiseMsg1)
            && (self.frames_read >= 1 || self.frames_written >= 1)
        {
            self.dead = true;
        }
    }

    fn note_frames_from(buf: &[u8], pending: &mut Vec<u8>, frames: &mut u8) {
        pending.extend_from_slice(buf);
        while pending.len() >= 2 {
            let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
            if pending.len() < 2 + len {
                break;
            }
            pending.drain(..2 + len);
            *frames = frames.saturating_add(1);
        }
    }

    fn maybe_flip_read(buf: &mut [u8], frames_before: u8, fault: TransportFault, flip_done: &mut bool) {
        let TransportFault::FlipByteInMsg2 { at } = fault else {
            return;
        };
        if *flip_done || frames_before != 1 || buf.is_empty() {
            return;
        }
        let idx = (at as usize) % buf.len();
        buf[idx] ^= 0xFF;
        *flip_done = true;
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FaultyIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.dead {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let frames_before = self.frames_read;
        let n = match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let fault = self.fault;
        let mut flip_done = self.flip_done;
        Self::maybe_flip_read(&mut buf[..n], frames_before, fault, &mut flip_done);
        self.flip_done = flip_done;
        let mut pending = std::mem::take(&mut self.read_buf);
        let mut frames = self.frames_read;
        Self::note_frames_from(&buf[..n], &mut pending, &mut frames);
        self.read_buf = pending;
        self.frames_read = frames;
        self.maybe_kill_after_msg1();
        Poll::Ready(Ok(n))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FaultyIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.dead {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let mut pending = std::mem::take(&mut self.write_pending);
                let mut frames = self.frames_written;
                Self::note_frames_from(&buf[..n], &mut pending, &mut frames);
                self.write_pending = pending;
                self.frames_written = frames;
                self.maybe_kill_after_msg1();
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.dead {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Composed tree: limits gate dials; gossipsub + kad + identify on the same
/// MemoryTransport mesh.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p_swarm::derive_prelude")]
struct FuzzBehaviour {
    limits: LimitsBehaviour,
    gossipsub: GossipsubBehaviour,
    kad: KadBehaviour<MemoryStore>,
    identify: IdentifyBehaviour,
}

#[derive(Debug, Clone)]
enum FuzzAction {
    /// Ensure swarm listens on `/memory/0` (no-op if already listening).
    Listen { swarm: u8 },
    /// Dial `to` from `from` using known listen address.
    Dial {
        from: u8,
        to: u8,
        always: bool,
    },
    /// Dial a non-listening memory port (pending / failure path).
    DialUnreachable { swarm: u8 },
    Disconnect { swarm: u8, peer_slot: u8 },
    CloseConnection { swarm: u8, conn_idx: u8 },
    MutateLimits {
        swarm: u8,
        max_established: Option<u8>,
        max_pending_out: Option<u8>,
        max_per_peer: Option<u8>,
    },
    AddExternal { swarm: u8 },
    RemoveExternal { swarm: u8 },
    /// Subscribe swarm to a fuzz topic (idempotent).
    GossipSubscribe { swarm: u8, topic_slot: u8 },
    /// Publish a small payload on a topic.
    GossipPublish {
        swarm: u8,
        topic_slot: u8,
        data: Vec<u8>,
    },
    /// Force one gossipsub heartbeat tick (fuzzing feature).
    GossipHeartbeat { swarm: u8 },
    /// Add connected peer addresses into the local DHT routing table.
    KadAddAddress { swarm: u8, peer_slot: u8 },
    /// Start a GetRecord query (empty RT → NotFound under soak).
    KadGetRecord { swarm: u8, key_slot: u8 },
    /// Put a small record (local store + optional replication).
    KadPutRecord {
        swarm: u8,
        key_slot: u8,
        value: Vec<u8>,
    },
    /// Bootstrap (NoKnownPeers when RT empty).
    KadBootstrap { swarm: u8 },
    /// Active Identify push to a connected peer (or no-op if none).
    IdentifyPush { swarm: u8, peer_slot: u8 },
    /// Flip the global identity-verify stub to always-fail / always-pass so a
    /// single input drives both accepted and rejected signature lanes (e.g.
    /// Noise AuthFailed, gossipsub InvalidSignature) without real crypto.
    SetVerifyMode { always_fail: bool },
    /// Burst-dial every other swarm from `swarm` under tight `connection_limits`
    /// (max_established=1, max_pending_out=1) so the deny path and
    /// `OutgoingConnectionError`/`DialFailure` bookkeeping stay warm.
    LimitsFlood { swarm: u8 },
    /// Advance all swarms + tokio tasks.
    Poll { budget: u8 },
}

#[derive(Debug)]
struct ActionSeq {
    n_swarms: usize,
    /// Whole-mesh security (global per input).
    security: Security,
    /// Mid-handshake I/O fault (Noise/TLS meshes; plaintext always None).
    transport_fault: TransportFault,
    actions: Vec<FuzzAction>,
}

impl<'a> Arbitrary<'a> for ActionSeq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let n_swarms = u.int_in_range(MIN_SWARMS..=MAX_SWARMS)?;
        // Bias: Noise ~½, plaintext ~¼, TLS ~⅛, QUIC ~⅛.
        let security = match u.int_in_range(0u8..=7)? {
            0 | 1 => Security::Plaintext,
            2 => Security::Tls,
            3 => Security::Quic,
            _ => Security::Noise,
        };
        // ~¼ of Noise/TLS meshes get a mid-handshake MemoryTransport fault.
        // QUIC mid-handshake corrupt stays in `quic_handshake`.
        let transport_fault = if security.allows_transport_fault() && u.ratio(1, 4)? {
            if u.ratio(1, 2)? {
                TransportFault::DropAfterNoiseMsg1
            } else {
                TransportFault::FlipByteInMsg2 {
                    at: u.arbitrary()?,
                }
            }
        } else {
            TransportFault::None
        };
        let n = u.int_in_range(8..=MAX_ACTIONS)?;
        let mut actions = Vec::with_capacity(n + n_swarms + 4);
        // Setup: every swarm listens, then a burst of polls.
        for i in 0..n_swarms {
            actions.push(FuzzAction::Listen { swarm: i as u8 });
        }
        // Extra poll budget after listen so Noise/TLS can finish before dials.
        actions.push(FuzzAction::Poll {
            budget: if security.needs_extra_poll() { 48 } else { 32 },
        });
        for step in 0..n {
            actions.push(fuzz_action(u, step, n_swarms, security)?);
        }
        actions.push(FuzzAction::Poll {
            budget: if security.needs_extra_poll() { 96 } else { 64 },
        });
        Ok(ActionSeq {
            n_swarms,
            security,
            transport_fault,
            actions,
        })
    }
}

fn fuzz_action(
    u: &mut Unstructured<'_>,
    step: usize,
    n_swarms: usize,
    security: Security,
) -> arbitrary::Result<FuzzAction> {
    let slot = |u: &mut Unstructured<'_>| -> arbitrary::Result<u8> {
        Ok((u.int_in_range(0..=255)? as usize % n_swarms) as u8)
    };
    let encrypted = security.needs_extra_poll();
    let poll_hi = if encrypted {
        MAX_POLL_PER_ACTION as u8
    } else {
        32
    };

    // Early steps: form a mesh (dial + poll), then light protocol traffic.
    // Noise XX needs more poll budget between dials than plaintext.
    if step < 4 {
        return Ok(match step % 3 {
            0 => FuzzAction::Dial {
                from: slot(u)?,
                to: slot(u)?,
                always: false,
            },
            1 => FuzzAction::Poll {
                budget: u.int_in_range(16..=poll_hi)?,
            },
            _ => FuzzAction::Dial {
                from: slot(u)?,
                to: slot(u)?,
                always: true,
            },
        });
    }
    if step == 4 {
        return Ok(FuzzAction::GossipSubscribe {
            swarm: slot(u)?,
            topic_slot: 0,
        });
    }
    if step == 5 {
        return Ok(FuzzAction::KadAddAddress {
            swarm: slot(u)?,
            peer_slot: u.arbitrary()?,
        });
    }
    if step == 6 {
        return Ok(FuzzAction::IdentifyPush {
            swarm: slot(u)?,
            peer_slot: u.arbitrary()?,
        });
    }

    // Coverage-biased weights (sum = 54):
    //   Dial(+Always) 8 | Poll(+time) 6 | MutateLimits(tight) 6 | Disconnect 4
    //   CloseConnection 4 | DialUnreachable 3 | Listen 2 | Add/RemoveExternal 3
    //   GossipPublish 3 | GossipHeartbeat 2 | GossipSubscribe 1
    //   KadGetRecord 2 | KadPutRecord 2 | KadAddAddress 1 | KadBootstrap 1
    //   IdentifyPush 2 | SetVerifyMode(fail) 1 | SetVerifyMode(pass) 1
    //   LimitsFlood 2
    Ok(match u.int_in_range(0u8..=53)? {
        0..=7 => FuzzAction::Dial {
            from: slot(u)?,
            to: slot(u)?,
            // Bias Always so multi-conn + per-peer limits deny paths stay warm.
            always: u.ratio(2, 3)?,
        },
        8..=13 => FuzzAction::Poll {
            budget: u.int_in_range(if encrypted { 12 } else { 4 }..=MAX_POLL_PER_ACTION as u8)?,
        },
        14..=19 => FuzzAction::MutateLimits {
            swarm: slot(u)?,
            // Bias toward *tight* limits (1..=2) so DialFailure / Denied fire.
            max_established: if u.ratio(3, 4)? {
                Some(u.int_in_range(1..=2)?)
            } else {
                None
            },
            max_pending_out: if u.ratio(1, 2)? {
                Some(u.int_in_range(1..=2)?)
            } else {
                None
            },
            max_per_peer: if u.ratio(3, 4)? {
                Some(1)
            } else {
                None
            },
        },
        20..=23 => FuzzAction::Disconnect {
            swarm: slot(u)?,
            peer_slot: u.arbitrary()?,
        },
        24..=27 => FuzzAction::CloseConnection {
            swarm: slot(u)?,
            conn_idx: u.arbitrary()?,
        },
        28..=30 => FuzzAction::DialUnreachable { swarm: slot(u)? },
        31..=32 => FuzzAction::Listen { swarm: slot(u)? },
        33..=34 => FuzzAction::AddExternal { swarm: slot(u)? },
        35 => FuzzAction::RemoveExternal { swarm: slot(u)? },
        36..=38 => {
            let len = u.int_in_range(0..=MAX_PUBLISH_BYTES)?;
            FuzzAction::GossipPublish {
                swarm: slot(u)?,
                topic_slot: u.int_in_range(0..=(TOPIC_POOL as u8 - 1))?,
                data: u.bytes(len)?.to_vec(),
            }
        }
        39..=40 => FuzzAction::GossipHeartbeat { swarm: slot(u)? },
        41 => FuzzAction::GossipSubscribe {
            swarm: slot(u)?,
            topic_slot: u.int_in_range(0..=(TOPIC_POOL as u8 - 1))?,
        },
        42..=43 => FuzzAction::KadGetRecord {
            swarm: slot(u)?,
            key_slot: u.arbitrary()?,
        },
        44..=45 => {
            let len = u.int_in_range(0..=MAX_RECORD_BYTES)?;
            FuzzAction::KadPutRecord {
                swarm: slot(u)?,
                key_slot: u.arbitrary()?,
                value: u.bytes(len)?.to_vec(),
            }
        }
        46 => FuzzAction::KadAddAddress {
            swarm: slot(u)?,
            peer_slot: u.arbitrary()?,
        },
        47 => FuzzAction::KadBootstrap { swarm: slot(u)? },
        48..=49 => FuzzAction::IdentifyPush {
            swarm: slot(u)?,
            peer_slot: u.arbitrary()?,
        },
        // Flip the verify stub mid-input so rejected-signature lanes stay warm.
        50 => FuzzAction::SetVerifyMode { always_fail: true },
        51 => FuzzAction::SetVerifyMode { always_fail: false },
        _ => FuzzAction::LimitsFlood { swarm: slot(u)? },
    })
}

struct SwarmState {
    swarm: Swarm<FuzzBehaviour>,
    listen_addr: Option<Multiaddr>,
    /// PeerId → established connection count (from SwarmEvents).
    peers: HashMap<PeerId, u32>,
    /// Established connection ids (for CloseConnection).
    conn_ids: Vec<ConnectionId>,
}

struct World {
    swarms: Vec<SwarmState>,
    security: Security,
    total_polls: usize,
    /// Soft counters (coverage / soak telemetry; not asserted).
    dial_failures: u32,
    incoming_errors: u32,
    behaviour_events: u32,
}

impl World {
    fn new(n: usize, security: Security, transport_fault: TransportFault) -> Self {
        let mut swarms = Vec::with_capacity(n);
        for slot in 0..n {
            swarms.push(SwarmState {
                swarm: new_swarm(default_limits(), security, slot as u8, transport_fault),
                listen_addr: None,
                peers: HashMap::new(),
                conn_ids: Vec::new(),
            });
        }
        Self {
            swarms,
            security,
            total_polls: 0,
            dial_failures: 0,
            incoming_errors: 0,
            behaviour_events: 0,
        }
    }

    fn idx(&self, slot: u8) -> usize {
        (slot as usize) % self.swarms.len()
    }

    fn peer_listen(&self, peer: &PeerId) -> Option<Multiaddr> {
        self.swarms
            .iter()
            .find(|st| st.swarm.local_peer_id() == peer)
            .and_then(|st| st.listen_addr.clone())
    }

    fn handle_event(&mut self, i: usize, ev: SwarmEvent<FuzzBehaviourEvent>) {
        match ev {
            SwarmEvent::NewListenAddr { address, .. } => {
                let usable = address
                    .iter()
                    .any(|p| matches!(p, Protocol::Memory(_)))
                    || address
                        .iter()
                        .any(|p| matches!(p, Protocol::QuicV1 | Protocol::Quic));
                if usable {
                    self.swarms[i].listen_addr = Some(address.clone());
                    // Advertise so peer-id dials have an address candidate.
                    self.swarms[i].swarm.add_external_address(address);
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                *self.swarms[i].peers.entry(peer_id).or_insert(0) += 1;
                if self.swarms[i].conn_ids.len() < MAX_CONN_IDS {
                    self.swarms[i].conn_ids.push(connection_id);
                }
                // Clone before mutating behaviour (avoid overlapping borrows).
                let peer_addr = self.peer_listen(&peer_id);
                let behaviour = self.swarms[i].swarm.behaviour_mut();
                if let Some(addr) = peer_addr {
                    let _ = behaviour.kad.add_address(&peer_id, addr);
                }
                behaviour.gossipsub.add_explicit_peer(&peer_id);
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(c) = self.swarms[i].peers.get_mut(&peer_id) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.swarms[i].peers.remove(&peer_id);
                    }
                }
                self.swarms[i].conn_ids.retain(|id| *id != connection_id);
                self.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
            }
            SwarmEvent::OutgoingConnectionError { .. } => {
                self.dial_failures = self.dial_failures.saturating_add(1);
            }
            SwarmEvent::IncomingConnectionError { .. } => {
                self.incoming_errors = self.incoming_errors.saturating_add(1);
            }
            SwarmEvent::Behaviour(_) => {
                self.behaviour_events = self.behaviour_events.saturating_add(1);
            }
            _ => {}
        }
    }

    fn check_invariants(&self) {
        for (i, st) in self.swarms.iter().enumerate() {
            let info = st.swarm.network_info();
            assert!(
                info.connection_counters().num_established() <= MAX_ESTABLISHED_SOFT,
                "swarm {i}: established {} exceeds soft clamp",
                info.connection_counters().num_established()
            );
            assert!(
                st.peers.len() <= MAX_SWARMS * 4,
                "swarm {i}: tracked peer map grew to {}",
                st.peers.len()
            );

            for peer in st.swarm.connected_peers() {
                assert!(
                    st.peers.contains_key(peer),
                    "swarm {i}: Swarm connected to {peer} but tracker missed ConnectionEstablished (notify leak?)"
                );
                assert!(
                    st.swarm.is_connected(peer),
                    "swarm {i}: connected_peers yielded {peer} but is_connected=false"
                );
            }

            for peer in st.peers.keys() {
                assert!(
                    st.swarm.is_connected(peer),
                    "swarm {i}: tracker still holds {peer} after Swarm dropped it (ConnectionClosed leak)"
                );
            }

            let id_peers = st.swarm.behaviour().identify.fuzz_discovered_peer_count();
            assert!(
                id_peers <= IDENTIFY_CACHE_SIZE,
                "swarm {i}: identify discovered peers {id_peers} > cache {IDENTIFY_CACHE_SIZE}"
            );
            let id_addrs = st.swarm.behaviour().identify.fuzz_discovered_addr_count();
            assert!(
                id_addrs <= IDENTIFY_CACHE_SIZE.saturating_mul(10),
                "swarm {i}: identify discovered addrs grew unboundedly: {id_addrs}"
            );
        }
    }
}

fn default_limits() -> ConnectionLimits {
    ConnectionLimits::default()
        .with_max_established(Some(8))
        .with_max_established_per_peer(Some(4))
        .with_max_pending_outgoing(Some(8))
        .with_max_established_incoming(Some(8))
        .with_max_established_outgoing(Some(8))
}

fn topic(slot: u8) -> IdentTopic {
    IdentTopic::new(format!("swarm-fuzz-{}", slot as usize % TOPIC_POOL))
}

fn record_key(slot: u8) -> RecordKey {
    RecordKey::new(&format!("swarm-key-{slot}").into_bytes())
}

fn new_swarm(
    limits: ConnectionLimits,
    security: Security,
    swarm_slot: u8,
    transport_fault: TransportFault,
) -> Swarm<FuzzBehaviour> {
    // Corpus-stable local keys (like Gossipsub/Kad peer pools) aid crash minimization.
    let mut seed = [0x53u8; 32];
    seed[30] = match security {
        Security::Plaintext => 0,
        Security::Noise => 1,
        Security::Tls => 2,
        Security::Quic => 3,
    };
    seed[31] = swarm_slot;
    let identity = Keypair::ed25519_from_bytes(&mut seed).expect("swarm ed25519 seed");
    let peer_id = PeerId::from(identity.public());
    // Noise/TLS/QUIC need more budget than plaintext for the multi-message handshake.
    let dial_timeout = if security.needs_extra_poll() {
        Duration::from_millis(500)
    } else {
        Duration::from_millis(200)
    };
    let transport = match security {
        Security::Quic => {
            // QUIC = transport + security + mux in one; no MemoryTransport / yamux.
            // TransportFault is not applied (mid-handshake corrupt stays in quic_handshake).
            let _ = transport_fault;
            let mut config = quic::Config::new(&identity);
            config.handshake_timeout = dial_timeout;
            config.max_idle_timeout = 5_000;
            config.keep_alive_interval = Duration::from_millis(0);
            quic::tokio::Transport::new(config)
                .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
                .boxed()
        }
        Security::Noise | Security::Tls | Security::Plaintext => {
            // Wrap MemoryTransport I/O before security upgrade so mid-frame faults apply.
            let base = MemoryTransport::default().map(move |channel, _endpoint| {
                FaultyIo::new(channel, transport_fault)
            });
            match security {
                Security::Noise => {
                    let noise_cfg = noise::Config::new(&identity).expect("noise XX config");
                    base.upgrade(Version::V1Lazy)
                        .authenticate(noise_cfg)
                        .multiplex(yamux::Config::default())
                        .timeout(dial_timeout)
                        .boxed()
                }
                Security::Tls => {
                    let tls_cfg = tls::Config::new(&identity).expect("tls config");
                    base.upgrade(Version::V1Lazy)
                        .authenticate(tls_cfg)
                        .multiplex(yamux::Config::default())
                        .timeout(dial_timeout)
                        .boxed()
                }
                Security::Plaintext => base
                    .upgrade(Version::V1Lazy)
                    .authenticate(plaintext::Config::new(&identity))
                    .multiplex(yamux::Config::default())
                    .timeout(dial_timeout)
                    .boxed(),
                Security::Quic => unreachable!("handled above"),
            }
        }
    };

    let gossip_cfg = GossipsubConfigBuilder::default()
        .history_length(3)
        .history_gossip(2)
        .mesh_n(2)
        .mesh_n_low(1)
        .mesh_n_high(4)
        .mesh_outbound_min(0)
        .heartbeat_interval(Duration::from_millis(50))
        .heartbeat_initial_delay(Duration::ZERO)
        .validation_mode(ValidationMode::Permissive)
        .max_transmit_size(256)
        .allow_self_origin(true)
        .build()
        .expect("gossipsub fuzz config");
    let mut gossipsub = GossipsubBehaviour::new(MessageAuthenticity::Anonymous, gossip_cfg)
        .expect("anonymous + permissive");
    let _ = gossipsub.subscribe(&topic(0));

    let mut kad_cfg = KadConfig::new(libp2p_swarm::StreamProtocol::new("/ipfs/kad/1.0.0"));
    kad_cfg
        .set_kbucket_size(NonZeroUsize::new(4).expect("4 != 0"))
        .set_replication_factor(NonZeroUsize::new(2).expect("2 != 0"))
        .set_parallelism(NonZeroUsize::new(2).expect("2 != 0"))
        .set_query_timeout(Duration::from_millis(50))
        .set_record_ttl(Some(Duration::from_secs(60)))
        .set_replication_interval(None)
        .set_publication_interval(None)
        .set_provider_publication_interval(None)
        .set_periodic_bootstrap_interval(None);
    let store = MemoryStore::with_config(
        peer_id,
        MemoryStoreConfig {
            max_records: 64,
            max_value_bytes: MAX_RECORD_BYTES,
            max_providers_per_key: 4,
            max_provided_keys: 32,
        },
    );
    let mut kad = KadBehaviour::with_config(peer_id, store, kad_cfg);
    kad.set_mode(Some(Mode::Server));

    // Identify: short interval so organic reconnects re-identify; initial Delay
    // is ZERO so first connection poll opens `/ipfs/id/1.0.0` immediately.
    let identify = IdentifyBehaviour::new(
        IdentifyConfig::new_with_signed_peer_record("swarm-fuzz/1.0.0".into(), &identity)
            .with_agent_version("swarm-fuzz-agent/0".into())
            .with_interval(Duration::from_millis(200))
            .with_push_listen_addr_updates(true)
            .with_cache_size(IDENTIFY_CACHE_SIZE)
            .with_hide_listen_addrs(false),
    );

    Swarm::new(
        transport,
        FuzzBehaviour {
            limits: LimitsBehaviour::new(limits),
            gossipsub,
            kad,
            identify,
        },
        peer_id,
        SwarmConfig::with_tokio_executor()
            // Short idle so paused-time advances in `drive` hit idle-close.
            .with_idle_connection_timeout(Duration::from_millis(50)),
    )
}

async fn drive(world: &mut World, budget: usize) {
    let budget = budget.min(MAX_POLL_PER_ACTION);
    for tick in 0..budget {
        if world.total_polls >= MAX_TOTAL_POLLS {
            break;
        }
        world.total_polls += 1;

        let mut progress = false;
        for i in 0..world.swarms.len() {
            // Drain all immediately-ready events for this swarm.
            loop {
                let ev = poll_fn(|cx| match Pin::new(&mut world.swarms[i].swarm).poll_next(cx) {
                    Poll::Ready(Some(e)) => Poll::Ready(Some(e)),
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Ready(None),
                })
                .await;
                match ev {
                    Some(e) => {
                        world.handle_event(i, e);
                        progress = true;
                    }
                    None => break,
                }
            }
        }
        // Let connection tasks spawned on the current-thread runtime run.
        tokio::task::yield_now().await;
        // Advance paused clock so idle-connection-timeout / gossip heartbeats fire.
        if tick % 4 == 3 {
            tokio::time::advance(Duration::from_millis(60)).await;
        }
        if !progress {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(10)).await;
        }
    }
    world.check_invariants();
    let _ = (
        world.dial_failures,
        world.incoming_errors,
        world.behaviour_events,
    );
}

async fn run(seq: ActionSeq) {
    let mut world = World::new(seq.n_swarms, seq.security, seq.transport_fault);
    // Default: verify stub passes; SetVerifyMode actions flip it mid-input.
    #[cfg(fuzzing)]
    libp2p_identity::fuzz::set_verify_always_pass();

    for action in seq.actions {
        match action {
            FuzzAction::Listen { swarm } => {
                let i = world.idx(swarm);
                if world.swarms[i].listen_addr.is_none() {
                    let addr: Multiaddr = if world.security.is_quic() {
                        "/ip4/127.0.0.1/udp/0/quic-v1"
                            .parse()
                            .expect("quic listen multiaddr")
                    } else {
                        Protocol::Memory(0).into()
                    };
                    let _ = world.swarms[i].swarm.listen_on(addr);
                }
            }
            FuzzAction::Dial { from, to, always } => {
                let fi = world.idx(from);
                let ti = world.idx(to);
                if fi == ti {
                    continue;
                }
                let Some(addr) = world.swarms[ti].listen_addr.clone() else {
                    continue;
                };
                let peer = *world.swarms[ti].swarm.local_peer_id();
                let builder = DialOpts::peer_id(peer);
                let builder = if always {
                    builder.condition(PeerCondition::Always)
                } else {
                    builder
                };
                let _ = world.swarms[fi]
                    .swarm
                    .dial(builder.addresses(vec![addr]).build());
            }
            FuzzAction::DialUnreachable { swarm } => {
                let i = world.idx(swarm);
                let addr: Multiaddr = if world.security.is_quic() {
                    // Closed / unused high UDP port on loopback.
                    format!("/ip4/127.0.0.1/udp/{}/quic-v1", 55_000 + u16::from(swarm))
                        .parse()
                        .expect("quic unreachable multiaddr")
                } else {
                    // High port unlikely to be registered in the MemoryTransport hub.
                    Protocol::Memory(u64::MAX - (swarm as u64)).into()
                };
                let _ = world.swarms[i].swarm.dial(addr);
            }
            FuzzAction::Disconnect { swarm, peer_slot } => {
                let i = world.idx(swarm);
                let peers: Vec<PeerId> = world.swarms[i].peers.keys().copied().collect();
                if peers.is_empty() {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % peers.len()];
                let _ = world.swarms[i].swarm.disconnect_peer_id(peer);
            }
            FuzzAction::CloseConnection { swarm, conn_idx } => {
                let i = world.idx(swarm);
                if world.swarms[i].conn_ids.is_empty() {
                    continue;
                }
                let id =
                    world.swarms[i].conn_ids[(conn_idx as usize) % world.swarms[i].conn_ids.len()];
                let _ = world.swarms[i].swarm.close_connection(id);
            }
            FuzzAction::MutateLimits {
                swarm,
                max_established,
                max_pending_out,
                max_per_peer,
            } => {
                let i = world.idx(swarm);
                let limits = world.swarms[i].swarm.behaviour_mut().limits.limits_mut();
                *limits = ConnectionLimits::default()
                    .with_max_established(max_established.map(|v| v as u32))
                    .with_max_pending_outgoing(max_pending_out.map(|v| v as u32))
                    .with_max_established_per_peer(max_per_peer.map(|v| v as u32))
                    .with_max_established_incoming(max_established.map(|v| v as u32))
                    .with_max_established_outgoing(max_established.map(|v| v as u32));
            }
            FuzzAction::AddExternal { swarm } => {
                let i = world.idx(swarm);
                if let Some(addr) = world.swarms[i].listen_addr.clone() {
                    world.swarms[i].swarm.add_external_address(addr);
                }
            }
            FuzzAction::RemoveExternal { swarm } => {
                let i = world.idx(swarm);
                if let Some(addr) = world.swarms[i].listen_addr.clone() {
                    world.swarms[i].swarm.remove_external_address(&addr);
                }
            }
            FuzzAction::GossipSubscribe { swarm, topic_slot } => {
                let i = world.idx(swarm);
                let _ = world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .subscribe(&topic(topic_slot));
            }
            FuzzAction::GossipPublish {
                swarm,
                topic_slot,
                data,
            } => {
                let i = world.idx(swarm);
                let _ = world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic(topic_slot), data);
            }
            FuzzAction::GossipHeartbeat { swarm } => {
                let i = world.idx(swarm);
                world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .fuzz_heartbeat();
            }
            FuzzAction::KadAddAddress { swarm, peer_slot } => {
                let i = world.idx(swarm);
                let peers: Vec<(PeerId, Multiaddr)> = world
                    .swarms
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .filter_map(|(_, st)| {
                        st.listen_addr
                            .clone()
                            .map(|a| (*st.swarm.local_peer_id(), a))
                    })
                    .collect();
                if peers.is_empty() {
                    continue;
                }
                let (peer, addr) = &peers[(peer_slot as usize) % peers.len()];
                let _ = world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .kad
                    .add_address(peer, addr.clone());
            }
            FuzzAction::KadGetRecord { swarm, key_slot } => {
                let i = world.idx(swarm);
                let _ = world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .kad
                    .get_record(record_key(key_slot));
            }
            FuzzAction::KadPutRecord {
                swarm,
                key_slot,
                value,
            } => {
                let i = world.idx(swarm);
                let record = Record {
                    key: record_key(key_slot),
                    value,
                    publisher: Some(*world.swarms[i].swarm.local_peer_id()),
                    expires: None,
                };
                let _ = world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, Quorum::One);
            }
            FuzzAction::KadBootstrap { swarm } => {
                let i = world.idx(swarm);
                let _ = world.swarms[i].swarm.behaviour_mut().kad.bootstrap();
            }
            FuzzAction::IdentifyPush { swarm, peer_slot } => {
                let i = world.idx(swarm);
                let peers: Vec<PeerId> = world.swarms[i].peers.keys().copied().collect();
                if peers.is_empty() {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % peers.len()];
                world.swarms[i]
                    .swarm
                    .behaviour_mut()
                    .identify
                    .push([peer]);
            }
            FuzzAction::SetVerifyMode { always_fail } => {
                #[cfg(fuzzing)]
                {
                    if always_fail {
                        libp2p_identity::fuzz::set_verify_always_fail();
                    } else {
                        libp2p_identity::fuzz::set_verify_always_pass();
                    }
                }
                #[cfg(not(fuzzing))]
                let _ = always_fail;
            }
            FuzzAction::LimitsFlood { swarm } => {
                let i = world.idx(swarm);
                // Tighten limits first so the burst trips `ConnectionDenied`.
                let limits = world.swarms[i].swarm.behaviour_mut().limits.limits_mut();
                *limits = ConnectionLimits::default()
                    .with_max_established(Some(1))
                    .with_max_pending_outgoing(Some(1))
                    .with_max_established_per_peer(Some(1))
                    .with_max_established_incoming(Some(1))
                    .with_max_established_outgoing(Some(1));
                // Burst-dial every other swarm; `PeerCondition::Always` bypasses
                // the pending-slot dedup so the pending/established caps engage.
                for j in 0..world.swarms.len() {
                    if j == i {
                        continue;
                    }
                    if let Some(addr) = world.swarms[j].listen_addr.clone() {
                        let peer = *world.swarms[j].swarm.local_peer_id();
                        let _ = world.swarms[i].swarm.dial(
                            DialOpts::peer_id(peer)
                                .condition(PeerCondition::Always)
                                .addresses(vec![addr])
                                .build(),
                        );
                    }
                }
                // Drive so Denied dials surface as OutgoingConnectionError.
                drive(&mut world, MAX_POLL_PER_ACTION).await;
            }
            FuzzAction::Poll { budget } => {
                drive(&mut world, budget as usize).await;
            }
        }
    }

    // Final drain so disconnects settle before drop.
    drive(&mut world, MAX_POLL_PER_ACTION).await;
    world.check_invariants();
}

static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fuzz_target!(|seq: ActionSeq| {
    // Reuse a single runtime across iterations: a fresh
    // `new_current_thread().enable_all()` per input leaks the I/O driver's
    // epoll + eventfd fds (~2 fds/iteration), exhausting the process fd limit
    // (EMFILE, "Too many open files") after a few hundred execs.
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio current_thread runtime")
    });
    rt.block_on(async {
        // Pause so `drive` can deterministically advance idle / dial timeouts.
        tokio::time::pause();
        run(seq).await;
        // Reset the paused clock so the next input starts from a clean state.
        tokio::time::resume();
    });
});
