//! Action-sequence fuzz driver for relay [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Injects swarm / handler events with mock
//! hop streams so libFuzzer reaches reservation limits, circuit routing, status
//! changes, and inbound hop decode.

use std::{
    collections::HashMap,
    num::NonZeroU32,
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::Encoder;
use bytes::BytesMut;
use either::Either;
use futures::task::noop_waker_ref;
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionId, NetworkBehaviour, Stream, ToSwarm,
    behaviour::{ConnectionClosed, ConnectionEstablished, ExternalAddrConfirmed, FromSwarm},
};

use crate::{
    Behaviour, CircuitId, Config, Status,
    behaviour::handler::{self, Handler},
    fuzz_handler::{
        BlackholeIo, ChunkFeed, WriteFault, inject_inbound_hop_ex, pump_handler, RW,
    },
    proto,
    protocol::{MAX_MESSAGE_SIZE, inbound_hop},
};

pub const MAX_ACTIONS: usize = 64;
pub const MAX_MSG_BYTES: usize = 4 * 1024;
pub const PEER_POOL: usize = 8;
const MAX_POLL_DRAIN: usize = 256;
// Tight caps so FloodReservations / FloodCircuits hit Deny* arms: Active is
// keyed per ConnectionId, so per-peer deny needs distinct conns; global deny
// needs sum(active) >= max_reservations (production uses `>=` / `>`).
const MAX_RESERVATIONS: usize = 2;
const MAX_RESERVATIONS_PER_PEER: usize = 1;
const MAX_CIRCUITS: usize = 2;
const MAX_CIRCUITS_PER_PEER: usize = 1;

#[derive(Clone, Copy, Debug)]
pub enum StructuredHopKind {
    Reserve,
    Connect { dst_slot: u8 },
    StatusOk,
    MalformedPeer,
}

#[derive(Clone, Copy, Debug)]
pub enum StructuredStopKind {
    Connect { src_slot: u8 },
    Status,
}

pub fn encode_structured_hop_wire(kind: StructuredHopKind, slot: u8) -> Vec<u8> {
    let peers = peer_pool();
    let msg = match kind {
        StructuredHopKind::Reserve => proto::HopMessage {
            r#type: proto::HopMessageType::Reserve as i32,
            ..Default::default()
        },
        StructuredHopKind::Connect { dst_slot } => {
            let dst = peers[(dst_slot as usize) % PEER_POOL];
            proto::HopMessage {
                r#type: proto::HopMessageType::Connect as i32,
                peer: Some(proto::Peer {
                    id: dst.to_bytes(),
                    addrs: vec![],
                }),
                ..Default::default()
            }
        }
        StructuredHopKind::StatusOk => proto::HopMessage {
            r#type: proto::HopMessageType::Status as i32,
            status: Some(proto::Status::Ok as i32),
            ..Default::default()
        },
        StructuredHopKind::MalformedPeer => proto::HopMessage {
            r#type: proto::HopMessageType::Connect as i32,
            peer: Some(proto::Peer {
                id: vec![0xFF; 4],
                addrs: vec![],
            }),
            ..Default::default()
        },
    };
    let _ = slot;
    length_prefix_hop(&msg)
}

pub fn encode_structured_stop_wire(kind: StructuredStopKind) -> Vec<u8> {
    let peers = peer_pool();
    let msg = match kind {
        StructuredStopKind::Connect { src_slot } => {
            let src = peers[(src_slot as usize) % PEER_POOL];
            proto::StopMessage {
                r#type: proto::StopMessageType::Connect as i32,
                peer: Some(proto::Peer {
                    id: src.to_bytes(),
                    addrs: vec![],
                }),
                ..Default::default()
            }
        }
        StructuredStopKind::Status => proto::StopMessage {
            r#type: proto::StopMessageType::Status as i32,
            ..Default::default()
        },
    };
    length_prefix_stop(&msg)
}

fn length_prefix_hop(msg: &proto::HopMessage) -> Vec<u8> {
    let mut codec = prost_codec::Codec::<proto::HopMessage>::new(MAX_MESSAGE_SIZE);
    let mut buf = BytesMut::new();
    if codec.encode(msg.clone(), &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

fn length_prefix_stop(msg: &proto::StopMessage) -> Vec<u8> {
    let mut codec = prost_codec::Codec::<proto::StopMessage>::new(MAX_MESSAGE_SIZE);
    let mut buf = BytesMut::new();
    if codec.encode(msg.clone(), &mut buf).is_err() {
        return Vec::new();
    }
    buf.to_vec()
}

#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect { peer_slot: u8, outbound: bool },
    Disconnect { peer_slot: u8 },
    ConfirmExternalAddr { slot: u8 },
    SetStatusEnable,
    SetStatusDisable,
    InjectReservationReq { peer_slot: u8 },
    InjectCircuitReq { peer_slot: u8, dst_slot: u8 },
    InjectReservationAccepted { peer_slot: u8, renewed: bool },
    InjectReservationTimedOut { peer_slot: u8 },
    /// Close a circuit with Kad-style attribution:
    /// - `circuit_slot == 0` → newest tracked id
    /// - `circuit_slot > 0` → walk older ids
    /// - `mismatch` → ghost [`CircuitId`] never issued
    InjectCircuitClosed {
        peer_slot: u8,
        dst_slot: u8,
        circuit_slot: u8,
        mismatch: bool,
    },
    FloodReservations { peer_slot: u8, count: u8 },
    /// Flood concurrent circuit requests (src→dst) for DoS / teardown races.
    FloodCircuits {
        src_slot: u8,
        dst_slot: u8,
        count: u8,
    },
    /// Disconnect src while flooding circuit-closed (concurrent hop teardown).
    ConcurrentTeardown {
        src_slot: u8,
        dst_slot: u8,
    },
    InjectHopWire { peer_slot: u8, wire: Vec<u8> },
    InjectStopWire { peer_slot: u8, wire: Vec<u8> },
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x61u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn fuzz_config(rate_limit: Option<(NonZeroU32, Duration)>) -> Config {
    let mut config = Config {
        max_reservations: MAX_RESERVATIONS,
        max_reservations_per_peer: MAX_RESERVATIONS_PER_PEER,
        reservation_duration: Duration::from_secs(3600),
        reservation_rate_limiters: vec![],
        max_circuits: MAX_CIRCUITS,
        max_circuits_per_peer: MAX_CIRCUITS_PER_PEER,
        max_circuit_duration: Duration::from_secs(120),
        max_circuit_bytes: 1 << 17,
        circuit_src_rate_limiters: vec![],
    };
    if let Some((limit, interval)) = rate_limit {
        // Enable all four limiter lanes (per-peer + per-IP for both reservation
        // and circuit-src) so `rate_limiter.rs` token-bucket allow/deny arms run.
        // Previously empty (0% coverage).
        config = config
            .reservation_rate_per_peer(limit, interval)
            .reservation_rate_per_ip(limit, interval)
            .circuit_src_per_peer(limit, interval)
            .circuit_src_per_ip(limit, interval);
    }
    config
}

fn peer_pool_keys() -> Vec<Keypair> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0x70u8.wrapping_add(i as u8); 32];
            bytes[0] = 0xD0u8.wrapping_add(i as u8);
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
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(10, 0, 0, 1 + slot % 200)));
    a.push(Protocol::Tcp(7000 + slot as u16));
    a
}

fn external_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(203, 0, 113, 1 + slot % 200)));
    a.push(Protocol::Tcp(8000 + slot as u16));
    a
}

fn reservation_stream() -> Stream {
    let wire = encode_structured_hop_wire(StructuredHopKind::Reserve, 0);
    let feed = ChunkFeed::new(wire, 64);
    feed.close();
    Stream::from_async_rw(RW(
        feed.into_io(),
        BlackholeIo::new(WriteFault::NONE),
    ))
}

fn circuit_stream(dst_slot: u8) -> Stream {
    let wire = encode_structured_hop_wire(StructuredHopKind::Connect { dst_slot }, dst_slot);
    let feed = ChunkFeed::new(wire, 64);
    feed.close();
    // Bias circuit accept/deny encode under partial writes + flush stalls.
    Stream::from_async_rw(RW(
        feed.into_io(),
        BlackholeIo::new(WriteFault {
            write_cap: 1,
            stall_every: 2,
            err_every: 0,
            flush_stall_every: 2,
        }),
    ))
}

fn hop_write_fault(peer_slot: u8, wire_len: usize) -> WriteFault {
    // ~½ of hop injects stress encode / flush; correlates with slot + length.
    if peer_slot % 2 == 0 || wire_len % 3 == 0 {
        WriteFault {
            write_cap: 1,
            stall_every: 2,
            err_every: 0,
            flush_stall_every: 2,
        }
    } else {
        WriteFault::NONE
    }
}

fn endpoint_for(peer_slot: u8, outbound: bool) -> ConnectedPoint {
    let remote = peer_addr(peer_slot);
    if outbound {
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
    }
}

/// Drive [`Behaviour`] with a sequence of actions.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    fuzz_behaviour_ex(actions, None);
}

/// Like [`fuzz_behaviour`], but with tight per-peer + per-IP rate limiters so the
/// `rate_limiter.rs` token-bucket deny arms fire under reservation / circuit floods.
pub fn fuzz_behaviour_rate_limited(
    actions: impl IntoIterator<Item = FuzzAction>,
    limit: NonZeroU32,
) {
    fuzz_behaviour_ex(actions, Some((limit, Duration::from_secs(3600))));
}

fn fuzz_behaviour_ex(
    actions: impl IntoIterator<Item = FuzzAction>,
    rate_limit: Option<(NonZeroU32, Duration)>,
) {
    let local = fuzz_local_peer_id();
    let config = fuzz_config(rate_limit);
    let mut relay = Behaviour::new(local, config);
    let peers = peer_pool();
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>> = HashMap::new();
    let mut handlers: HashMap<PeerId, Handler> = HashMap::new();
    let mut next_conn: usize = 1;

    for action in actions.into_iter().take(MAX_ACTIONS) {
        match action {
            FuzzAction::Connect {
                peer_slot,
                outbound,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let cid = ConnectionId::new_unchecked(next_conn);
                next_conn = next_conn.wrapping_add(1).max(1);
                let remote = peer_addr(peer_slot);
                let endpoint = endpoint_for(peer_slot, outbound);

                let handler = if outbound {
                    relay.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    relay.handle_established_inbound_connection(
                        cid,
                        peer,
                        &Multiaddr::empty(),
                        &remote,
                    )
                };

                let other = conn_ids.get(&peer).map(|v| v.len()).unwrap_or(0);
                relay.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
                    peer_id: peer,
                    connection_id: cid,
                    endpoint: &endpoint,
                    failed_addresses: &[],
                    other_established: other,
                }));
                conn_ids.entry(peer).or_default().push((cid, endpoint));

                if let Ok(Either::Left(mut h)) = handler {
                    let _ = pump_handler(&mut h);
                    handlers.insert(peer, h);
                }
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                handlers.remove(&peer);
                let mut remaining = ids.len();
                for (cid, endpoint) in ids {
                    remaining = remaining.saturating_sub(1);
                    relay.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
                drain_behaviour(&mut relay, &mut handlers, &conn_ids);
                assert!(
                    !relay.fuzz_peer_has_active_reservation(peer),
                    "peer still has active reservation after disconnect"
                );
            }
            FuzzAction::ConfirmExternalAddr { slot } => {
                let addr = external_addr(slot);
                relay.on_swarm_event(FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
                    addr: &addr,
                }));
            }
            FuzzAction::SetStatusEnable => relay.set_status(Some(Status::Enable)),
            FuzzAction::SetStatusDisable => relay.set_status(Some(Status::Disable)),
            FuzzAction::InjectReservationReq { peer_slot } => {
                inject_reservation_req(&mut relay, &peers, &conn_ids, peer_slot);
            }
            FuzzAction::InjectCircuitReq { peer_slot, dst_slot } => {
                inject_circuit_req(&mut relay, &peers, &conn_ids, peer_slot, dst_slot);
            }
            FuzzAction::InjectReservationAccepted { peer_slot, renewed } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                relay.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(handler::Event::ReservationReqAccepted { renewed }),
                );
            }
            FuzzAction::InjectReservationTimedOut { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                // A real handler only times out a reservation it actually holds,
                // on its own connection. Inject on an active-reservation
                // connection rather than an arbitrary `conn_ids[peer].first()`;
                // otherwise a peer whose reservation was already consumed (or
                // never existed) would trip the behaviour's
                // `Expect to track timed out reservation` unreachable! panic.
                let Some(cid) = relay
                    .fuzz_active_reservation_connections(&peer)
                    .first()
                    .copied()
                else {
                    continue;
                };
                relay.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(handler::Event::ReservationTimedOut {}),
                );
            }
            FuzzAction::InjectCircuitClosed {
                peer_slot,
                dst_slot,
                circuit_slot,
                mismatch,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let dst = peers[(dst_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let ids = relay.fuzz_circuit_ids();
                let Some(circuit_id) = resolve_circuit_id(&ids, circuit_slot, mismatch) else {
                    continue;
                };
                relay.on_connection_handler_event(
                    peer,
                    cid,
                    Either::Left(handler::Event::CircuitClosed {
                        circuit_id,
                        dst_peer_id: dst,
                        error: None,
                    }),
                );
            }
            FuzzAction::FloodReservations { peer_slot, count } => {
                let n = (count as usize % 8).max(1);
                for i in 0..n {
                    // Rotate ConnectionId so per-peer Active count can exceed
                    // max_reservations_per_peer (same-cid accept only overwrites).
                    inject_reservation_req_on(
                        &mut relay,
                        &peers,
                        &conn_ids,
                        peer_slot,
                        i,
                    );
                    // Drain after each inject so DenyReservationReq reaches the
                    // Handler and ReservationReqDenied can fire under WriteFault.
                    drain_behaviour(&mut relay, &mut handlers, &conn_ids);
                }
            }
            FuzzAction::FloodCircuits {
                src_slot,
                dst_slot,
                count,
            } => {
                let n = (count as usize % 8).max(1);
                for _ in 0..n {
                    inject_circuit_req(&mut relay, &peers, &conn_ids, src_slot, dst_slot);
                    drain_behaviour(&mut relay, &mut handlers, &conn_ids);
                }
            }
            FuzzAction::ConcurrentTeardown { src_slot, dst_slot } => {
                // Race: close newest circuits then drop src connection mid-teardown.
                let src = peers[(src_slot as usize) % PEER_POOL];
                let dst = peers[(dst_slot as usize) % PEER_POOL];
                let ids = relay.fuzz_circuit_ids();
                if let Some((cid, _)) = conn_ids.get(&src).and_then(|v| v.first()).cloned() {
                    for (i, _) in ids.iter().enumerate().take(4) {
                        let Some(circuit_id) =
                            resolve_circuit_id(&ids, i as u8, false)
                        else {
                            break;
                        };
                        relay.on_connection_handler_event(
                            src,
                            cid,
                            Either::Left(handler::Event::CircuitClosed {
                                circuit_id,
                                dst_peer_id: dst,
                                error: Some(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    "fuzz teardown",
                                )),
                            }),
                        );
                    }
                }
                // Disconnect both ends while closes are in-flight.
                for peer_slot in [src_slot, dst_slot] {
                    let peer = peers[(peer_slot as usize) % PEER_POOL];
                    if let Some(ids) = conn_ids.remove(&peer) {
                        handlers.remove(&peer);
                        let mut remaining = ids.len();
                        for (cid, endpoint) in ids {
                            remaining = remaining.saturating_sub(1);
                            relay.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                                peer_id: peer,
                                connection_id: cid,
                                endpoint: &endpoint,
                                remaining_established: remaining,
                                cause: None,
                            }));
                        }
                    }
                }
            }
            FuzzAction::InjectHopWire { peer_slot, wire } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let bytes = if wire.len() > MAX_MSG_BYTES {
                    &wire[..MAX_MSG_BYTES]
                } else {
                    &wire
                };
                if let Some(h) = handlers.get_mut(&peer) {
                    let fault = hop_write_fault(peer_slot, bytes.len());
                    inject_inbound_hop_ex(h, bytes.to_vec(), fault);
                    for _ in 0..4 {
                        for ev in pump_handler(h) {
                            relay.on_connection_handler_event(peer, cid, Either::Left(ev));
                        }
                    }
                }
            }
            FuzzAction::InjectStopWire { peer_slot, wire } => {
                // Stop frames share hop handler inject path (decode reject / status).
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let bytes = if wire.len() > MAX_MSG_BYTES {
                    &wire[..MAX_MSG_BYTES]
                } else {
                    &wire
                };
                if let Some(h) = handlers.get_mut(&peer) {
                    let fault = hop_write_fault(peer_slot, bytes.len());
                    inject_inbound_hop_ex(h, bytes.to_vec(), fault);
                    for _ in 0..4 {
                        for ev in pump_handler(h) {
                            relay.on_connection_handler_event(peer, cid, Either::Left(ev));
                        }
                    }
                }
            }
        }

        drain_behaviour(&mut relay, &mut handlers, &conn_ids);

        // Soft DoS clamps (allow tiny overshoot for in-flight accept/deny races).
        assert!(
            relay.fuzz_active_reservation_count() <= MAX_RESERVATIONS.saturating_add(2),
            "reservations unbounded: {}",
            relay.fuzz_active_reservation_count()
        );
        assert!(
            relay.fuzz_circuit_count() <= MAX_CIRCUITS.saturating_add(2),
            "circuits unbounded: {}",
            relay.fuzz_circuit_count()
        );
    }

    assert!(
        relay.fuzz_active_reservation_count() <= MAX_RESERVATIONS.saturating_add(2),
        "end-of-run reservations unbounded: {}",
        relay.fuzz_active_reservation_count()
    );
    assert!(
        relay.fuzz_circuit_count() <= MAX_CIRCUITS.saturating_add(2),
        "end-of-run circuits unbounded: {}",
        relay.fuzz_circuit_count()
    );
}

fn inject_reservation_req(
    relay: &mut Behaviour,
    peers: &[PeerId],
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
    peer_slot: u8,
) {
    inject_reservation_req_on(relay, peers, conn_ids, peer_slot, 0);
}

fn inject_reservation_req_on(
    relay: &mut Behaviour,
    peers: &[PeerId],
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
    peer_slot: u8,
    conn_idx: usize,
) {
    let peer = peers[(peer_slot as usize) % PEER_POOL];
    let Some(ids) = conn_ids.get(&peer) else {
        return;
    };
    if ids.is_empty() {
        return;
    }
    let (cid, endpoint) = ids[conn_idx % ids.len()].clone();
    let stream = reservation_stream();
    if let Ok(req) = inbound_hop::fuzz_reservation_req(stream) {
        relay.on_connection_handler_event(
            peer,
            cid,
            Either::Left(handler::Event::ReservationReqReceived {
                inbound_reservation_req: req,
                endpoint,
                renewed: false,
            }),
        );
    }
}

fn inject_circuit_req(
    relay: &mut Behaviour,
    peers: &[PeerId],
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
    src_slot: u8,
    dst_slot: u8,
) {
    let peer = peers[(src_slot as usize) % PEER_POOL];
    let dst = peers[(dst_slot as usize) % PEER_POOL];
    let Some((cid, endpoint)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
        return;
    };
    let stream = circuit_stream(dst_slot);
    if let Ok(req) = inbound_hop::fuzz_circuit_req(dst, stream) {
        relay.on_connection_handler_event(
            peer,
            cid,
            Either::Left(handler::Event::CircuitReqReceived {
                inbound_circuit_req: req,
                endpoint,
            }),
        );
    }
}

/// Resolve which [`CircuitId`] an [`FuzzAction::InjectCircuitClosed`] should use.
///
/// - `mismatch` → ghost id never issued by the Behaviour (must not panic)
/// - else `circuit_slot == 0` → newest; higher slots walk older entries
fn resolve_circuit_id(
    active: &[CircuitId],
    circuit_slot: u8,
    mismatch: bool,
) -> Option<CircuitId> {
    if mismatch {
        return Some(CircuitId::fuzz_from_raw(
            0xF000_0000u64.wrapping_add(u64::from(circuit_slot)),
        ));
    }
    let n = active.len();
    if n == 0 {
        return None;
    }
    let from_end = (circuit_slot as usize) % n;
    Some(active[n - 1 - from_end])
}

fn drain_behaviour(
    relay: &mut Behaviour,
    handlers: &mut HashMap<PeerId, Handler>,
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match NetworkBehaviour::poll(relay, &mut cx) {
            Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                event,
                handler: _,
            }) => {
                let Some(h) = handlers.get_mut(&peer_id) else {
                    continue;
                };
                let Either::Left(in_ev) = event;
                h.on_behaviour_event(in_ev);
                if let Some((cid, _)) = conn_ids.get(&peer_id).and_then(|v| v.first()) {
                    for ev in pump_handler(h) {
                        relay.on_connection_handler_event(peer_id, *cid, Either::Left(ev));
                    }
                }
            }
            Poll::Ready(ToSwarm::GenerateEvent(_)) | Poll::Ready(_) => {}
            Poll::Pending => {
                // DenyReservationReq / circuit deny encode may need several
                // Pending→pump rounds under noop_waker (+ optional WriteFault).
                let mut progressed = false;
                for _ in 0..8 {
                    let mut round = false;
                    for (peer, h) in handlers.iter_mut() {
                        if let Some((cid, _)) = conn_ids.get(peer).and_then(|v| v.first()) {
                            let evs = pump_handler(h);
                            if !evs.is_empty() {
                                round = true;
                            }
                            for ev in evs {
                                relay.on_connection_handler_event(
                                    *peer,
                                    *cid,
                                    Either::Left(ev),
                                );
                            }
                        }
                    }
                    if !round {
                        break;
                    }
                    progressed = true;
                }
                let _ = progressed;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_relay_reservation_timedout_double_inject() {
        fuzz_behaviour([
            FuzzAction::ConfirmExternalAddr { slot: 0 },
            FuzzAction::SetStatusEnable,
            FuzzAction::Connect {
                peer_slot: 4,
                outbound: true,
            },
            FuzzAction::FloodReservations {
                peer_slot: 4,
                count: 1,
            },
            FuzzAction::InjectReservationTimedOut { peer_slot: 4 },
            FuzzAction::InjectReservationTimedOut { peer_slot: 4 },
        ]);
    }

    #[test]
    fn smoke_connect_reserve_external_status() {
        fuzz_behaviour([
            FuzzAction::ConfirmExternalAddr { slot: 0 },
            FuzzAction::SetStatusEnable,
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectReservationReq { peer_slot: 0 },
        ]);
    }

    #[test]
    fn smoke_disconnect_clears_reservation_tracking() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectReservationAccepted {
                peer_slot: 1,
                renewed: false,
            },
            FuzzAction::Disconnect { peer_slot: 1 },
        ]);
    }

    #[test]
    fn structured_hop_wire_roundtrip_decode() {
        use crate::fuzz_handler::decode_hop_wire;
        let wire = encode_structured_hop_wire(StructuredHopKind::Reserve, 3);
        decode_hop_wire(&wire).expect("reserve hop decode");
    }

    #[test]
    fn concurrent_teardown_and_ghost_circuit_close() {
        fuzz_behaviour([
            FuzzAction::ConfirmExternalAddr { slot: 0 },
            FuzzAction::SetStatusEnable,
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::InjectReservationReq { peer_slot: 0 },
            FuzzAction::InjectReservationReq { peer_slot: 1 },
            FuzzAction::FloodCircuits {
                src_slot: 0,
                dst_slot: 1,
                count: 4,
            },
            // Ghost CircuitId — Behaviour must ignore without panic.
            FuzzAction::InjectCircuitClosed {
                peer_slot: 0,
                dst_slot: 1,
                circuit_slot: 0,
                mismatch: true,
            },
            FuzzAction::ConcurrentTeardown {
                src_slot: 0,
                dst_slot: 1,
            },
        ]);
    }

    #[test]
    fn rate_limited_flood_denies_reservations() {
        use std::num::NonZeroU32;
        // Tight token bucket (limit=2) → the first two reservations per peer/IP
        // are allowed; the flood beyond that trips the `rate_limiter.rs` deny arm.
        fuzz_behaviour_rate_limited(
            [
                FuzzAction::ConfirmExternalAddr { slot: 0 },
                FuzzAction::SetStatusEnable,
                FuzzAction::Connect {
                    peer_slot: 0,
                    outbound: true,
                },
                FuzzAction::Connect {
                    peer_slot: 1,
                    outbound: true,
                },
                FuzzAction::Connect {
                    peer_slot: 2,
                    outbound: true,
                },
                FuzzAction::FloodReservations {
                    peer_slot: 0,
                    count: 7,
                },
                FuzzAction::FloodReservations {
                    peer_slot: 1,
                    count: 7,
                },
                FuzzAction::FloodReservations {
                    peer_slot: 2,
                    count: 7,
                },
            ],
            NonZeroU32::new(2).unwrap(),
        );
    }

    #[test]
    fn flood_reservations_hits_deny_under_tight_caps() {
        // Dual-conn peer0 + fill global max → DenyReservationReq / Event path.
        fuzz_behaviour([
            FuzzAction::ConfirmExternalAddr { slot: 0 },
            FuzzAction::SetStatusEnable,
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: false,
            },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 2,
                outbound: true,
            },
            FuzzAction::InjectReservationReq { peer_slot: 0 },
            FuzzAction::InjectReservationReq { peer_slot: 1 },
            FuzzAction::FloodReservations {
                peer_slot: 2,
                count: 7,
            },
            FuzzAction::FloodReservations {
                peer_slot: 0,
                count: 7,
            },
            FuzzAction::FloodReservations {
                peer_slot: 1,
                count: 7,
            },
        ]);
    }
}
