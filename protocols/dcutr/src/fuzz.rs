//! Action-sequence fuzz driver for DCUtR [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Exercises relayed vs direct connection
//! setup, hole-punch handler events, dial failures, and address candidates.

use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use asynchronous_codec::Encoder;
use bytes::BytesMut;
use either::Either;
use futures::{AsyncRead, AsyncWrite, task::noop_waker_ref};
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionId, DialError, NetworkBehaviour, Stream, ToSwarm,
    behaviour::{ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm, NewExternalAddrCandidate},
    handler::{ConnectionEvent, FullyNegotiatedInbound, FullyNegotiatedOutbound},
};

use crate::{
    Behaviour,
    behaviour::MAX_NUMBER_OF_UPGRADE_ATTEMPTS,
    handler::relayed::{self, Handler as RelayedHandler},
    proto,
};

const HOLEPUNCH_MAX_BYTES: usize = 4096;

pub const MAX_ACTIONS: usize = 64;
pub const MAX_MSG_BYTES: usize = 4 * 1024;
pub const PEER_POOL: usize = 8;
const MAX_POLL_DRAIN: usize = 256;

#[derive(Clone, Copy, Debug)]
pub enum StructuredHolePunchKind {
    Connect,
    Sync,
    EmptyAddrs,
    ManyAddrs,
}

pub fn encode_structured_holepunch_wire(kind: StructuredHolePunchKind, slot: u8) -> Vec<u8> {
    let msg = match kind {
        StructuredHolePunchKind::Connect => proto::HolePunch {
            r#type: proto::Type::Connect as i32,
            obs_addrs: vec![direct_addr(slot).to_vec()],
        },
        StructuredHolePunchKind::Sync => proto::HolePunch {
            r#type: proto::Type::Sync as i32,
            obs_addrs: vec![direct_addr(slot).to_vec()],
        },
        StructuredHolePunchKind::EmptyAddrs => proto::HolePunch {
            r#type: proto::Type::Connect as i32,
            obs_addrs: vec![],
        },
        StructuredHolePunchKind::ManyAddrs => proto::HolePunch {
            r#type: proto::Type::Connect as i32,
            obs_addrs: (0..32)
                .map(|i| {
                    let mut a = Multiaddr::empty();
                    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(192, 0, 2, i as u8)));
                    a.push(Protocol::Tcp(9000 + i as u16));
                    a.to_vec()
                })
                .collect(),
        },
    };
    length_prefix(&msg)
}

fn length_prefix(msg: &proto::HolePunch) -> Vec<u8> {
    let mut codec = prost_codec::Codec::<proto::HolePunch>::new(HOLEPUNCH_MAX_BYTES);
    let mut buf = BytesMut::new();
    if codec.encode(msg.clone(), &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

#[derive(Clone, Debug)]
pub enum FuzzAction {
    ConnectRelayed {
        peer_slot: u8,
        relay_slot: u8,
        outbound: bool,
    },
    ConnectDirect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect { peer_slot: u8 },
    NewExternalAddrCandidate { slot: u8 },
    InjectInboundConnectNegotiated {
        peer_slot: u8,
        addr_slot: u8,
    },
    InjectOutboundConnectFailed { peer_slot: u8 },
    DialFailure {
        peer_slot: u8,
        relayed_conn: bool,
    },
    /// Inject length-prefixed HolePunch wire via inbound FullyNegotiated stream.
    InjectHolePunchWire {
        peer_slot: u8,
        kind: StructuredHolePunchKind,
    },
    /// Flood dial-failures on a relayed peer (concurrent upgrade attempt budget).
    FloodDialFailure {
        peer_slot: u8,
        count: u8,
    },
    /// Race: inbound connect negotiated then immediate disconnect of relayed peer.
    ConcurrentUpgradeTeardown {
        peer_slot: u8,
        addr_slot: u8,
    },
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x62u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn peer_pool() -> Vec<PeerId> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0x80u8.wrapping_add(i as u8); 32];
            bytes[0] = 0xE0u8.wrapping_add(i as u8);
            PeerId::from(
                Keypair::ed25519_from_bytes(&mut bytes)
                    .expect("pool ed25519")
                    .public(),
            )
        })
        .collect()
}

fn direct_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(203, 0, 113, 1 + slot % 200)));
    a.push(Protocol::Tcp(9100 + slot as u16));
    a
}

fn relayed_addr(relay: PeerId, remote: PeerId, relay_slot: u8) -> Multiaddr {
    direct_addr(relay_slot)
        .with(Protocol::P2p(relay))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(remote))
}

fn pump_relayed(handler: &mut RelayedHandler) -> Vec<relayed::Event> {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    let mut out = Vec::new();
    for _ in 0..MAX_POLL_DRAIN {
        match handler.poll(&mut cx) {
            Poll::Ready(libp2p_swarm::ConnectionHandlerEvent::NotifyBehaviour(ev)) => out.push(ev),
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
    out
}

/// Outbound write-side faults for hole-punch encode / flush depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFault {
    pub write_cap: usize,
    pub stall_every: usize,
    pub err_every: usize,
    pub flush_stall_every: usize,
}

impl WriteFault {
    pub const NONE: Self = Self {
        write_cap: 0,
        stall_every: 0,
        err_every: 0,
        flush_stall_every: 0,
    };

    pub fn stressed() -> Self {
        Self {
            write_cap: 1,
            stall_every: 2,
            err_every: 0,
            flush_stall_every: 2,
        }
    }
}

/// Mock inbound hole-punch stream (EOF after wire bytes; writes honor [`WriteFault`]).
fn inject_inbound_holepunch(handler: &mut RelayedHandler, wire: Vec<u8>) {
    let fault = if wire.len() % 2 == 0 {
        WriteFault::stressed()
    } else {
        WriteFault::NONE
    };
    inject_inbound_holepunch_ex(handler, wire, fault);
}

fn inject_inbound_holepunch_ex(handler: &mut RelayedHandler, wire: Vec<u8>, fault: WriteFault) {
    #[derive(Clone)]
    struct Feed {
        inner: Arc<Mutex<VecDeque<u8>>>,
    }
    #[derive(Clone)]
    struct WriteCtrl {
        inner: Arc<Mutex<(usize, usize, WriteFault, bool, bool)>>,
    }
    impl WriteCtrl {
        fn new(fault: WriteFault) -> Self {
            Self {
                inner: Arc::new(Mutex::new((0, 0, fault, false, false))),
            }
        }
        fn poll_write(&self, buf: &[u8]) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut st = self.inner.lock().expect("write");
            let (writes, _, fault, resume, _) = &mut *st;
            if *resume {
                *resume = false;
            } else if fault.stall_every != 0 {
                let next = writes.wrapping_add(1);
                if next % fault.stall_every == 0 {
                    *writes = next;
                    *resume = true;
                    return Poll::Pending;
                }
            }
            *writes = writes.wrapping_add(1);
            if fault.err_every != 0 && *writes % fault.err_every == 0 {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            let n = if fault.write_cap == 0 {
                buf.len()
            } else {
                buf.len().min(fault.write_cap.max(1))
            };
            Poll::Ready(Ok(n))
        }
        fn poll_flush(&self) -> Poll<io::Result<()>> {
            let mut st = self.inner.lock().expect("write");
            let (_, flushes, fault, _, flush_resume) = &mut *st;
            if fault.flush_stall_every == 0 {
                return Poll::Ready(Ok(()));
            }
            if *flush_resume {
                *flush_resume = false;
                return Poll::Ready(Ok(()));
            }
            let next = flushes.wrapping_add(1);
            *flushes = next;
            if next % fault.flush_stall_every == 0 {
                *flush_resume = true;
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }
    }
    struct FeedIo {
        feed: Feed,
        write: WriteCtrl,
    }
    impl AsyncRead for FeedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut q = self.feed.inner.lock().expect("feed");
            if q.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = q.len().min(buf.len());
            for b in buf.iter_mut().take(n) {
                *b = q.pop_front().expect("len");
            }
            Poll::Ready(Ok(n))
        }
    }
    impl AsyncWrite for FeedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write.poll_write(buf)
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.write.poll_flush()
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let feed = Feed {
        inner: Arc::new(Mutex::new(wire.into_iter().collect())),
    };
    let stream = Stream::from_async_rw(FeedIo {
        feed,
        write: WriteCtrl::new(fault),
    });
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: futures::future::Either::Left(stream),
            info: (),
        },
    ));
}

/// Mock outbound hole-punch stream: preloaded response bytes on read; the write
/// side sinks (with optional [`WriteFault`]) the CONNECT / SYNC messages the
/// [`protocol::outbound::handshake`] sends.
struct OutboundMockIo {
    response: Vec<u8>,
    pos: usize,
    write: OutboundWriteCtrl,
}

impl AsyncRead for OutboundMockIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let rem = &this.response[this.pos..];
        let n = rem.len().min(buf.len());
        buf[..n].copy_from_slice(&rem[..n]);
        this.pos += n;
        Poll::Ready(Ok(n)) // 0 → EOF after the response is consumed
    }
}

impl AsyncWrite for OutboundMockIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write.poll_write(buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write.poll_flush()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct OutboundWriteCtrl {
    inner: Arc<Mutex<OutboundWriteState>>,
}

struct OutboundWriteState {
    writes: usize,
    flushes: usize,
    fault: WriteFault,
    resume: bool,
    flush_resume: bool,
}

impl OutboundWriteCtrl {
    fn new(fault: WriteFault) -> Self {
        Self {
            inner: Arc::new(Mutex::new(OutboundWriteState {
                writes: 0,
                flushes: 0,
                fault,
                resume: false,
                flush_resume: false,
            })),
        }
    }

    fn poll_write(&self, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut st = self.inner.lock().expect("outbound write");
        if st.resume {
            st.resume = false;
        } else if st.fault.stall_every != 0 {
            let next = st.writes.wrapping_add(1);
            if next % st.fault.stall_every == 0 {
                st.writes = next;
                st.resume = true;
                return Poll::Pending;
            }
        }
        st.writes = st.writes.wrapping_add(1);
        if st.fault.err_every != 0 && st.writes % st.fault.err_every == 0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let n = if st.fault.write_cap == 0 {
            buf.len()
        } else {
            buf.len().min(st.fault.write_cap.max(1))
        };
        Poll::Ready(Ok(n))
    }

    fn poll_flush(&self) -> Poll<io::Result<()>> {
        let mut st = self.inner.lock().expect("outbound flush");
        if st.fault.flush_stall_every == 0 {
            return Poll::Ready(Ok(()));
        }
        if st.flush_resume {
            st.flush_resume = false;
            return Poll::Ready(Ok(()));
        }
        let next = st.flushes.wrapping_add(1);
        st.flushes = next;
        if next % st.fault.flush_stall_every == 0 {
            st.flush_resume = true;
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

fn inject_outbound_holepunch(
    handler: &mut RelayedHandler,
    response_wire: Vec<u8>,
    write: WriteFault,
) {
    let stream = Stream::from_async_rw(OutboundMockIo {
        response: response_wire,
        pos: 0,
        write: OutboundWriteCtrl::new(write),
    });
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedOutbound(
        FullyNegotiatedOutbound {
            protocol: stream,
            info: (),
        },
    ));
}

/// Standalone listener-side hole-punch driver.
///
/// Covers `protocol/outbound.rs` (0% before): the dialer-side `handshake` that
/// sends CONNECT, reads + validates the peer's CONNECT response, sends SYNC, and
/// waits RTT/2. Returns the [`relayed::Event`]s the handler produces
/// (`OutboundConnectNegotiated` on success, `OutboundConnectFailed` on a
/// malformed response / EOF / type mismatch).
pub fn fuzz_outbound_holepunch(
    response_wire: Vec<u8>,
    candidates: Vec<Multiaddr>,
    write: WriteFault,
) -> Vec<relayed::Event> {
    // Listener endpoint → `Command::Connect` emits an OutboundSubstreamRequest
    // (per the DCUtR spec, the relayed listener initiates the direct upgrade).
    let endpoint = ConnectedPoint::Listener {
        local_addr: direct_addr(0),
        send_back_addr: direct_addr(1),
    };
    let mut handler = RelayedHandler::new(endpoint, candidates);
    handler.on_behaviour_event(relayed::Command::Connect);

    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    let mut events = Vec::new();
    let mut outbound_injected = false;
    let mut idle_waits = 0u8;
    for _ in 0..MAX_POLL_DRAIN {
        match handler.poll(&mut cx) {
            Poll::Ready(libp2p_swarm::ConnectionHandlerEvent::NotifyBehaviour(ev)) => {
                events.push(ev);
            }
            Poll::Ready(libp2p_swarm::ConnectionHandlerEvent::OutboundSubstreamRequest { .. }) => {
                if !outbound_injected {
                    inject_outbound_holepunch(&mut handler, response_wire.clone(), write);
                    outbound_injected = true;
                }
            }
            Poll::Ready(_) => {}
            Poll::Pending => {
                // `outbound::handshake` ends with `Delay(rtt / 2)`; rtt is the
                // (sub-microsecond) mock read latency, so the deadline is ~now.
                // The global futures-timer thread fires it within a millisecond;
                // sleep (bounded) rather than spin-yield so it reliably fires.
                if idle_waits < 16 {
                    idle_waits = idle_waits.saturating_add(1);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                break;
            }
        }
    }
    events
}

pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    let local = fuzz_local_peer_id();
    let mut dcutr = Behaviour::new(local);
    let peers = peer_pool();
    let relay_id = peers[0];
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint, bool)>> = HashMap::new();
    let mut handlers: HashMap<PeerId, RelayedHandler> = HashMap::new();
    // High base so harness ConnectionIds never collide with DialOpts IDs that
    // Behaviour inserts into `direct_to_relayed_connections` (global allocator
    // starts near 0; collision trips `assert!` at behaviour.rs:220 during
    // in-process corpus replay / coverage).
    let mut next_conn: usize = 0xE000_0001;
    let attempt_bound = PEER_POOL * PEER_POOL * (MAX_NUMBER_OF_UPGRADE_ATTEMPTS as usize + 1);

    for action in actions.into_iter().take(MAX_ACTIONS) {
        match action {
            FuzzAction::ConnectRelayed {
                peer_slot,
                relay_slot,
                outbound,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let cid = ConnectionId::new_unchecked(next_conn);
                next_conn = next_conn.wrapping_add(1).max(1);
                let addr = relayed_addr(relay_id, peer, relay_slot);
                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: addr.clone(),
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::Reuse,
                    }
                } else {
                    ConnectedPoint::Listener {
                        local_addr: addr.clone(),
                        send_back_addr: direct_addr(peer_slot),
                    }
                };

                let handler = if outbound {
                    dcutr.handle_established_outbound_connection(
                        cid,
                        peer,
                        &addr,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    dcutr.handle_established_inbound_connection(
                        cid,
                        peer,
                        &addr,
                        &direct_addr(peer_slot),
                    )
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                dcutr.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids
                    .entry(peer)
                    .or_default()
                    .push((cid, endpoint, true));

                if let Ok(Either::Left(mut h)) = handler {
                    let _ = pump_relayed(&mut h);
                    handlers.insert(peer, h);
                }
            }
            FuzzAction::ConnectDirect {
                peer_slot,
                outbound,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let cid = ConnectionId::new_unchecked(next_conn);
                next_conn = next_conn.wrapping_add(1).max(1);
                let addr = direct_addr(peer_slot).with(Protocol::P2p(peer));
                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: addr.clone(),
                        role_override: Endpoint::Dialer,
                        port_use: PortUse::Reuse,
                    }
                } else {
                    ConnectedPoint::Listener {
                        local_addr: addr.clone(),
                        send_back_addr: direct_addr(peer_slot),
                    }
                };

                let handler = if outbound {
                    dcutr.handle_established_outbound_connection(
                        cid,
                        peer,
                        &addr,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    dcutr.handle_established_inbound_connection(
                        cid,
                        peer,
                        &addr,
                        &direct_addr(peer_slot),
                    )
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                dcutr.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids
                    .entry(peer)
                    .or_default()
                    .push((cid, endpoint, false));

                if let Ok(Either::Right(_)) = handler {
                    // Direct connections use dummy handler — nothing to store.
                }
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                handlers.remove(&peer);
                let mut remaining = ids.len();
                for (cid, endpoint, is_relayed) in &ids {
                    if !is_relayed {
                        assert!(
                            dcutr.fuzz_peer_has_direct_connection(peer),
                            "direct connection missing before close"
                        );
                    }
                    remaining = remaining.saturating_sub(1);
                    dcutr.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: *cid,
                        endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
                drain_behaviour(&mut dcutr, &mut handlers, &conn_ids);
                assert!(
                    !dcutr.fuzz_peer_has_direct_connection(peer),
                    "direct connection set inconsistent after disconnect"
                );
            }
            FuzzAction::NewExternalAddrCandidate { slot } => {
                let addr = direct_addr(slot).with(Protocol::P2p(local));
                dcutr.on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                    NewExternalAddrCandidate { addr: &addr },
                ));
            }
            FuzzAction::InjectInboundConnectNegotiated { peer_slot, addr_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let addrs = vec![direct_addr(addr_slot).with(Protocol::P2p(peer))];
                dcutr.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(relayed::Event::InboundConnectNegotiated {
                        remote_addrs: addrs,
                    }),
                );
            }
            FuzzAction::InjectOutboundConnectFailed { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                dcutr.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(relayed::Event::OutboundConnectFailed {
                        error: crate::protocol::outbound::Error::Unsupported,
                    }),
                );
            }
            FuzzAction::DialFailure {
                peer_slot,
                relayed_conn,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_relayed)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if relayed_conn && !is_relayed {
                    continue;
                }
                let failed_cid = if is_relayed {
                    // Seed a mapped direct dial id, then fail that dial.
                    let addrs = vec![direct_addr(peer_slot).with(Protocol::P2p(peer))];
                    dcutr.on_connection_handler_event(
                        peer,
                        cid,
                        Either::Left(relayed::Event::OutboundConnectNegotiated {
                            remote_addrs: addrs,
                        }),
                    );
                    let waker = noop_waker_ref();
                    let mut cx = Context::from_waker(waker);
                    let mut direct = None;
                    for _ in 0..MAX_POLL_DRAIN {
                        match NetworkBehaviour::poll(&mut dcutr, &mut cx) {
                            Poll::Ready(ToSwarm::Dial { opts }) => {
                                direct = Some(opts.connection_id());
                                break;
                            }
                            Poll::Ready(_) => {}
                            Poll::Pending => break,
                        }
                    }
                    match direct {
                        Some(d) => d,
                        None => continue,
                    }
                } else {
                    cid
                };
                dcutr.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                    peer_id: Some(peer),
                    connection_id: failed_cid,
                    error: &DialError::NoAddresses,
                }));
            }
            FuzzAction::InjectHolePunchWire { peer_slot, kind } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(h) = handlers.get_mut(&peer) else {
                    continue;
                };
                let wire = encode_structured_holepunch_wire(kind, peer_slot);
                inject_inbound_holepunch(h, wire);
                if let Some((cid, _, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() {
                    // Extra rounds so WriteFault Pending writes/flushes can resume.
                    for _ in 0..4 {
                        for ev in pump_relayed(h) {
                            dcutr.on_connection_handler_event(peer, cid, Either::Left(ev));
                        }
                    }
                }
            }
            FuzzAction::FloodDialFailure { peer_slot, count } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((relayed_cid, _, is_relayed)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if !is_relayed {
                    continue;
                }
                // AttemptsExceeded requires (1) OutboundConnectNegotiated to bump
                // `outgoing_direct_connection_attempts` and insert direct→relayed,
                // (2) DialFailure on that *direct* ConnectionId (not the relayed one).
                let addrs = vec![direct_addr(peer_slot).with(Protocol::P2p(peer))];
                let mut direct_cids = Vec::new();
                for _ in 0..MAX_NUMBER_OF_UPGRADE_ATTEMPTS {
                    dcutr.on_connection_handler_event(
                        peer,
                        relayed_cid,
                        Either::Left(relayed::Event::OutboundConnectNegotiated {
                            remote_addrs: addrs.clone(),
                        }),
                    );
                }
                let waker = noop_waker_ref();
                let mut cx = Context::from_waker(waker);
                for _ in 0..MAX_POLL_DRAIN {
                    match NetworkBehaviour::poll(&mut dcutr, &mut cx) {
                        Poll::Ready(ToSwarm::Dial { opts }) => {
                            direct_cids.push(opts.connection_id());
                        }
                        Poll::Ready(ToSwarm::NotifyHandler {
                            peer_id,
                            event,
                            handler: _,
                        }) => {
                            let Either::Left(cmd) = event;
                            if let Some(h) = handlers.get_mut(&peer_id) {
                                h.on_behaviour_event(cmd);
                                if let Some((cid, _, _)) =
                                    conn_ids.get(&peer_id).and_then(|v| v.first())
                                {
                                    for ev in pump_relayed(h) {
                                        dcutr.on_connection_handler_event(
                                            peer_id,
                                            *cid,
                                            Either::Left(ev),
                                        );
                                    }
                                }
                            }
                        }
                        Poll::Ready(_) => {}
                        Poll::Pending => break,
                    }
                }
                let Some(&failed_cid) = direct_cids.last() else {
                    continue;
                };
                let n = (count as usize % 8).max(1);
                for _ in 0..n {
                    dcutr.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id: Some(peer),
                        connection_id: failed_cid,
                        error: &DialError::NoAddresses,
                    }));
                }
            }
            FuzzAction::ConcurrentUpgradeTeardown {
                peer_slot,
                addr_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _, is_relayed)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                if !is_relayed {
                    continue;
                }
                let addrs = vec![direct_addr(addr_slot).with(Protocol::P2p(peer))];
                dcutr.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(relayed::Event::InboundConnectNegotiated {
                        remote_addrs: addrs,
                    }),
                );
                drain_behaviour(&mut dcutr, &mut handlers, &conn_ids);
                if let Some(ids) = conn_ids.remove(&peer) {
                    handlers.remove(&peer);
                    let mut remaining = ids.len();
                    for (c, endpoint, _) in ids {
                        remaining = remaining.saturating_sub(1);
                        dcutr.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                            peer_id: peer,
                            connection_id: c,
                            endpoint: &endpoint,
                            remaining_established: remaining,
                            cause: None,
                        }));
                    }
                }
            }
        }

        drain_behaviour(&mut dcutr, &mut handlers, &conn_ids);

        assert!(
            dcutr.fuzz_outgoing_attempt_count() <= attempt_bound.saturating_add(2),
            "outgoing attempt map grew without bound: {}",
            dcutr.fuzz_outgoing_attempt_count()
        );
        assert!(
            dcutr.fuzz_direct_connection_count() <= MAX_ACTIONS.saturating_add(2),
            "direct connections unbounded: {}",
            dcutr.fuzz_direct_connection_count()
        );
    }

    assert!(
        dcutr.fuzz_outgoing_attempt_count() <= attempt_bound.saturating_add(2),
        "end-of-run attempt map unbounded: {}",
        dcutr.fuzz_outgoing_attempt_count()
    );
    assert!(
        dcutr.fuzz_direct_connection_count() <= MAX_ACTIONS.saturating_add(2),
        "end-of-run direct connections unbounded: {}",
        dcutr.fuzz_direct_connection_count()
    );
}

fn drain_behaviour(
    dcutr: &mut Behaviour,
    handlers: &mut HashMap<PeerId, RelayedHandler>,
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint, bool)>>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match NetworkBehaviour::poll(dcutr, &mut cx) {
            Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                event,
                handler: _,
            }) => {
                let Either::Left(cmd) = event;
                if let Some(h) = handlers.get_mut(&peer_id) {
                    h.on_behaviour_event(cmd);
                    if let Some((cid, _, _)) = conn_ids.get(&peer_id).and_then(|v| v.first()) {
                        for ev in pump_relayed(h) {
                            dcutr.on_connection_handler_event(peer_id, *cid, Either::Left(ev));
                        }
                    }
                }
            }
            Poll::Ready(ToSwarm::Dial { .. }) | Poll::Ready(ToSwarm::GenerateEvent(_)) => {}
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_outbound_holepunch_success_and_fail() {
        let candidates = vec![direct_addr(0), direct_addr(1)];
        // Valid CONNECT response → OutboundConnectNegotiated.
        let ok = fuzz_outbound_holepunch(
            encode_structured_holepunch_wire(StructuredHolePunchKind::Connect, 1),
            candidates.clone(),
            WriteFault::NONE,
        );
        assert!(
            ok.iter()
                .any(|e| matches!(e, relayed::Event::OutboundConnectNegotiated { .. })),
            "valid CONNECT response should negotiate: {ok:?}"
        );
        // Garbage / short frame → OutboundConnectFailed (no panic).
        let bad = fuzz_outbound_holepunch(vec![0xAB, 0xCD], candidates, WriteFault::NONE);
        assert!(
            bad.iter()
                .any(|e| matches!(e, relayed::Event::OutboundConnectFailed { .. })),
            "malformed response should fail cleanly: {bad:?}"
        );
    }

    #[test]
    fn smoke_relayed_then_holepunch_inject() {
        fuzz_behaviour([
            FuzzAction::NewExternalAddrCandidate { slot: 0 },
            FuzzAction::ConnectRelayed {
                peer_slot: 1,
                relay_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectInboundConnectNegotiated {
                peer_slot: 1,
                addr_slot: 2,
            },
        ]);
    }

    #[test]
    fn smoke_direct_connect_disconnect() {
        fuzz_behaviour([
            FuzzAction::ConnectDirect {
                peer_slot: 2,
                outbound: false,
            },
            FuzzAction::Disconnect { peer_slot: 2 },
        ]);
    }

    #[test]
    fn concurrent_upgrade_teardown_and_holepunch_wire() {
        fuzz_behaviour([
            FuzzAction::NewExternalAddrCandidate { slot: 0 },
            FuzzAction::ConnectRelayed {
                peer_slot: 1,
                relay_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectHolePunchWire {
                peer_slot: 1,
                kind: StructuredHolePunchKind::ManyAddrs,
            },
            FuzzAction::FloodDialFailure {
                peer_slot: 1,
                count: 5,
            },
            FuzzAction::ConcurrentUpgradeTeardown {
                peer_slot: 1,
                addr_slot: 3,
            },
        ]);
    }

    #[test]
    fn flood_dial_failure_attempts_exceeded() {
        fuzz_behaviour([
            FuzzAction::NewExternalAddrCandidate { slot: 0 },
            FuzzAction::ConnectRelayed {
                peer_slot: 1,
                relay_slot: 0,
                outbound: true,
            },
            FuzzAction::FloodDialFailure {
                peer_slot: 1,
                count: 7,
            },
        ]);
    }
}
