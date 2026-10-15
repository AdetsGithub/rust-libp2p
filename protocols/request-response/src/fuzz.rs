//! Action-sequence fuzz driver for request-response [`Behaviour`].
//!
//! Enabled with the `fuzzing` feature. Injects handler events and drives
//! [`Behaviour::send_request`] / response channels to reach QueryId-style
//! attribution bugs (ghost responses, stale timeouts, cross-request confusion).

use std::{
    collections::HashMap,
    io,
    task::{Context, Poll},
    time::Duration,
};

use futures::{channel::oneshot, task::noop_waker_ref};
use libp2p_core::{
    ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse,
};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionId, NetworkBehaviour, StreamProtocol, ToSwarm,
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
};

use crate::{
    Behaviour, Config, Event, InboundRequestId, Message, OutboundRequestId, ProtocolSupport,
    ResponseChannel,
    codec::Codec,
    fuzz_handler::pump_handler,
    handler::{Event as HandlerEvent, Handler},
};

/// Cap how many actions one fuzz input may drive.
pub const MAX_ACTIONS: usize = 64;
/// Cap length-prefixed frame payload size.
pub const MAX_MSG_BYTES: usize = 4 * 1024;
/// Fixed peer pool so connect / inject / disconnect correlate.
pub const PEER_POOL: usize = 8;
fn fuzz_protocol() -> StreamProtocol {
    StreamProtocol::new("/fuzz/reqres/1.0.0")
}

/// Fuzz protocol name (full duplex req/res).
pub fn fuzz_protocol_name() -> StreamProtocol {
    fuzz_protocol()
}
const MAX_POLL_DRAIN: usize = 256;

/// Length-prefixed u32-BE [`Codec`] for arbitrary bytes (req/res).
#[derive(Clone, Debug, Default)]
pub struct FuzzCodec;

pub(crate) fn max_payload_len() -> usize {
    MAX_MSG_BYTES
}

pub(crate) fn encode_payload(data: &[u8]) -> Vec<u8> {
    let body = truncate(data);
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = len.to_be_bytes().to_vec();
    out.extend(body);
    out
}

fn truncate(data: &[u8]) -> Vec<u8> {
    if data.len() > MAX_MSG_BYTES {
        data[..MAX_MSG_BYTES].to_vec()
    } else {
        data.to_vec()
    }
}

async fn read_payload<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: futures::AsyncRead + Unpin,
{
    use futures::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_MSG_BYTES",
        ));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        io.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn write_payload<T>(io: &mut T, data: &[u8]) -> io::Result<()>
where
    T: futures::AsyncWrite + Unpin,
{
    use futures::AsyncWriteExt;
    let frame = encode_payload(data);
    io.write_all(&frame).await?;
    io.close().await?;
    Ok(())
}

impl Codec for FuzzCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_payload(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_payload(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_payload(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_payload(io, &res).await
    }
}

/// Actions for the request-response behaviour harness.
#[derive(Clone, Debug)]
pub enum FuzzAction {
    Connect {
        peer_slot: u8,
        outbound: bool,
    },
    Disconnect {
        peer_slot: u8,
    },
    SendRequest {
        peer_slot: u8,
        data: Vec<u8>,
    },
    /// Answer a pending inbound request (`inbound_slot` indexes pending vec).
    SendResponse {
        peer_slot: u8,
        inbound_slot: u8,
        data: Vec<u8>,
    },
    /// Inject handler `Response` with Kad-style attribution:
    /// - `request_slot == 0` → newest active outbound
    /// - `request_slot > 0` → walk older ring entries
    /// - `mismatch` → ghost [`OutboundRequestId`] never issued
    InjectResponse {
        peer_slot: u8,
        request_slot: u8,
        mismatch: bool,
        data: Vec<u8>,
    },
    InjectOutboundTimeout {
        peer_slot: u8,
        request_slot: u8,
        mismatch: bool,
    },
    InjectInboundTimeout {
        peer_slot: u8,
        /// Index from newest pending inbound; `mismatch` → ghost inbound id.
        request_slot: u8,
        mismatch: bool,
    },
    InjectResponseOmission {
        peer_slot: u8,
        inbound_slot: u8,
    },
    InjectOutboundStreamFailed {
        peer_slot: u8,
        request_slot: u8,
        mismatch: bool,
    },
    /// Drop a pending inbound [`ResponseChannel`] without calling [`Behaviour::send_response`].
    BlackholeResponse {
        peer_slot: u8,
        inbound_slot: u8,
    },
    /// Inject handler `Request` (seeds pending inbound channels).
    InjectRequest {
        peer_slot: u8,
        inbound_slot: u8,
        data: Vec<u8>,
    },
}

struct PendingInbound {
    request_id: InboundRequestId,
    channel: ResponseChannel<Vec<u8>>,
}

struct PeerTrack {
    active_outbound: Vec<(OutboundRequestId, ConnectionId)>,
    pending_inbound: Vec<PendingInbound>,
}

pub fn fuzz_local_peer_id() -> PeerId {
    let mut bytes = [0x71u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("local ed25519")
            .public(),
    )
}

fn peer_pool() -> Vec<PeerId> {
    (0..PEER_POOL)
        .map(|i| {
            let mut bytes = [0x90u8.wrapping_add(i as u8); 32];
            bytes[0] = 0xD0u8.wrapping_add(i as u8);
            PeerId::from(
                Keypair::ed25519_from_bytes(&mut bytes)
                    .expect("pool ed25519")
                    .public(),
            )
        })
        .collect()
}

fn peer_addr(slot: u8) -> Multiaddr {
    let mut a = Multiaddr::empty();
    a.push(Protocol::Ip4(std::net::Ipv4Addr::new(10, 20, 0, 1 + slot % 200)));
    a.push(Protocol::Tcp(7000 + slot as u16));
    a
}

/// Resolve which [`OutboundRequestId`] to attribute (Kad `query_slot` / `mismatch`).
///
/// - `mismatch` → ghost id never issued by the Behaviour
/// - else `request_slot == 0` → newest; higher slots walk older ring entries
fn resolve_outbound_id(
    track: Option<&PeerTrack>,
    request_slot: u8,
    mismatch: bool,
    fallback_cid: ConnectionId,
) -> Option<(OutboundRequestId, ConnectionId)> {
    if mismatch {
        return Some((
            OutboundRequestId::fuzz(0xF000_0000u64.wrapping_add(u64::from(request_slot))),
            fallback_cid,
        ));
    }
    let t = track?;
    let n = t.active_outbound.len();
    if n == 0 {
        return None;
    }
    let from_end = (request_slot as usize) % n;
    Some(t.active_outbound[n - 1 - from_end])
}

/// Resolve which [`InboundRequestId`] to attribute (same ring / ghost rules).
fn resolve_inbound_id(
    track: Option<&PeerTrack>,
    request_slot: u8,
    mismatch: bool,
) -> Option<InboundRequestId> {
    if mismatch {
        return Some(InboundRequestId::fuzz(
            0xF000_0000u64.wrapping_add(u64::from(request_slot)),
        ));
    }
    let t = track?;
    let n = t.pending_inbound.len();
    if n == 0 {
        return None;
    }
    let from_end = (request_slot as usize) % n;
    Some(t.pending_inbound[n - 1 - from_end].request_id)
}

/// Drive [`Behaviour`] with a sequence of actions.
///
/// Invariants: never panics; always terminates; active outbound ids per peer ≤ [`MAX_ACTIONS`];
/// after [`FuzzAction::Disconnect`] no pending outbound for that peer.
pub fn fuzz_behaviour(actions: impl IntoIterator<Item = FuzzAction>) {
    let config = Config::default()
        .with_request_timeout(Duration::from_millis(50))
        .with_max_concurrent_streams(4);

    let mut behaviour = Behaviour::with_codec(
        FuzzCodec,
        [(fuzz_protocol(), ProtocolSupport::Full)],
        config,
    );

    let peers = peer_pool();
    let mut conn_ids: HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>> = HashMap::new();
    let mut handlers: HashMap<PeerId, Handler<FuzzCodec>> = HashMap::new();
    let mut tracks: HashMap<PeerId, PeerTrack> = HashMap::new();
    let mut next_conn: usize = 1;
    // Inbound request ids are synthesized by the harness; they must be unique
    // within the Behaviour (its ConnectionHandler uses a monotonic counter
    // `next_inbound_id`, so real ids never collide). A deterministic id from
    // `inbound_slot` (a u8) would reuse an id still pending on the same
    // connection and trip `debug_assert!("Expect id of new request to be
    // unknown")`.
    let mut next_inbound: u64 = 0;

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

                let handler = if outbound {
                    behaviour.handle_established_outbound_connection(
                        cid,
                        peer,
                        &remote,
                        Endpoint::Dialer,
                        PortUse::Reuse,
                    )
                } else {
                    behaviour.handle_established_inbound_connection(
                        cid,
                        peer,
                        &Multiaddr::empty(),
                        &remote,
                    )
                };

                let endpoint = if outbound {
                    ConnectedPoint::Dialer {
                        address: remote.clone(),
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
                behaviour.on_swarm_event(FromSwarm::ConnectionEstablished(
                    ConnectionEstablished {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        failed_addresses: &[],
                        other_established: other,
                    },
                ));
                conn_ids.entry(peer).or_default().push((cid, endpoint));

                if let Ok(mut h) = handler {
                    let _ = pump_handler(&mut h);
                    handlers.insert(peer, h);
                }
                tracks.entry(peer).or_insert_with(|| PeerTrack {
                    active_outbound: Vec::new(),
                    pending_inbound: Vec::new(),
                });
            }
            FuzzAction::Disconnect { peer_slot } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let snapshot = tracks.remove(&peer);
                let Some(ids) = conn_ids.remove(&peer) else {
                    continue;
                };
                handlers.remove(&peer);
                let mut remaining = ids.len();
                for (cid, endpoint) in ids {
                    remaining = remaining.saturating_sub(1);
                    behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id: peer,
                        connection_id: cid,
                        endpoint: &endpoint,
                        remaining_established: remaining,
                        cause: None,
                    }));
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
                if let Some(t) = snapshot {
                    for (id, _) in t.active_outbound {
                        assert!(
                            !behaviour.is_pending_outbound(&peer, &id),
                            "outbound still pending after disconnect: {id} peer={peer}"
                        );
                    }
                }
            }
            FuzzAction::SendRequest { peer_slot, data } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let id = behaviour.send_request(&peer, truncate(&data));
                // Record the connection the request is sent over so later
                // responses/timeouts are injected on the SAME connection. The
                // behaviour tracks pending outbound responses per connection
                // (try_send_request picks connections[id.0 % len]); injecting
                // on conn_ids[peer].first() instead trips the production
                // `request_id pending` debug_assert under connection churn.
                let track = tracks.entry(peer).or_insert_with(|| PeerTrack {
                    active_outbound: Vec::new(),
                    pending_inbound: Vec::new(),
                });
                if let Some(ids) = conn_ids.get(&peer) {
                    if !ids.is_empty() {
                        let ix = (id.0 as usize) % ids.len();
                        let conn = ids[ix].0;
                        track.active_outbound.push((id, conn));
                    }
                }
                if track.active_outbound.len() > MAX_ACTIONS {
                    track.active_outbound.drain(0..1);
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::SendResponse {
                peer_slot,
                inbound_slot,
                data,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(track) = tracks.get_mut(&peer) else {
                    continue;
                };
                if track.pending_inbound.is_empty() {
                    continue;
                }
                let ix = (inbound_slot as usize) % track.pending_inbound.len();
                let pending = track.pending_inbound.remove(ix);
                let _ = behaviour.send_response(pending.channel, truncate(&data));
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectRequest {
                peer_slot,
                inbound_slot: _,
                data,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let request_id = InboundRequestId::fuzz(next_inbound);
                next_inbound = next_inbound.wrapping_add(1);
                let (tx, _rx) = oneshot::channel();
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::Request {
                        request_id,
                        request: truncate(&data),
                        sender: tx,
                    },
                );
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectResponse {
                peer_slot,
                request_slot,
                mismatch,
                data,
            } => {
                // Ghost ids trip Behaviour `debug_assert!`; keep for release soaks.
                if mismatch && cfg!(debug_assertions) {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((fallback_cid, _)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                let Some((request_id, cid)) =
                    resolve_outbound_id(tracks.get(&peer), request_slot, mismatch, fallback_cid)
                else {
                    continue;
                };
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::Response {
                        request_id,
                        response: truncate(&data),
                    },
                );
                if !mismatch {
                    if let Some(t) = tracks.get_mut(&peer) {
                        t.active_outbound.retain(|(id, _)| *id != request_id);
                    }
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectOutboundTimeout {
                peer_slot,
                request_slot,
                mismatch,
            } => {
                if mismatch && cfg!(debug_assertions) {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((fallback_cid, _)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                let Some((request_id, cid)) =
                    resolve_outbound_id(tracks.get(&peer), request_slot, mismatch, fallback_cid)
                else {
                    continue;
                };
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::OutboundTimeout(request_id),
                );
                if !mismatch {
                    if let Some(t) = tracks.get_mut(&peer) {
                        t.active_outbound.retain(|(id, _)| *id != request_id);
                    }
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectInboundTimeout {
                peer_slot,
                request_slot,
                mismatch,
            } => {
                if mismatch && cfg!(debug_assertions) {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let Some(request_id) =
                    resolve_inbound_id(tracks.get(&peer), request_slot, mismatch)
                else {
                    continue;
                };
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::InboundTimeout(request_id),
                );
                if !mismatch {
                    if let Some(t) = tracks.get_mut(&peer) {
                        t.pending_inbound
                            .retain(|p| p.request_id != request_id);
                    }
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectResponseOmission {
                peer_slot,
                inbound_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((cid, _)) = conn_ids.get(&peer).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let Some(request_id) =
                    resolve_inbound_id(tracks.get(&peer), inbound_slot, false)
                else {
                    continue;
                };
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::ResponseOmission(request_id),
                );
                if let Some(t) = tracks.get_mut(&peer) {
                    t.pending_inbound
                        .retain(|p| p.request_id != request_id);
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::InjectOutboundStreamFailed {
                peer_slot,
                request_slot,
                mismatch,
            } => {
                if mismatch && cfg!(debug_assertions) {
                    continue;
                }
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some((fallback_cid, _)) =
                    conn_ids.get(&peer).and_then(|v| v.first()).cloned()
                else {
                    continue;
                };
                let Some((request_id, cid)) =
                    resolve_outbound_id(tracks.get(&peer), request_slot, mismatch, fallback_cid)
                else {
                    continue;
                };
                behaviour.on_connection_handler_event(
                    peer,
                    cid,
                    HandlerEvent::OutboundStreamFailed {
                        request_id,
                        error: io::Error::new(io::ErrorKind::Other, "fuzz io"),
                    },
                );
                if !mismatch {
                    if let Some(t) = tracks.get_mut(&peer) {
                        t.active_outbound.retain(|(id, _)| *id != request_id);
                    }
                }
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
            FuzzAction::BlackholeResponse {
                peer_slot,
                inbound_slot,
            } => {
                let peer = peers[(peer_slot as usize) % PEER_POOL];
                let Some(track) = tracks.get_mut(&peer) else {
                    continue;
                };
                if track.pending_inbound.is_empty() {
                    continue;
                }
                let ix = (inbound_slot as usize) % track.pending_inbound.len();
                drop(track.pending_inbound.remove(ix));
                drain_behaviour(
                    &mut behaviour,
                    &mut handlers,
                    &conn_ids,
                    &mut tracks,
                );
            }
        }

        for t in tracks.values() {
            assert!(
                t.active_outbound.len() <= MAX_ACTIONS.saturating_add(2),
                "active outbound ids unbounded: {}",
                t.active_outbound.len()
            );
            assert!(
                t.pending_inbound.len() <= MAX_ACTIONS.saturating_add(2),
                "pending inbound channels unbounded: {}",
                t.pending_inbound.len()
            );
        }
    }

    let mut total_outbound = 0usize;
    let mut total_inbound = 0usize;
    for t in tracks.values() {
        total_outbound = total_outbound.saturating_add(t.active_outbound.len());
        total_inbound = total_inbound.saturating_add(t.pending_inbound.len());
        assert!(
            t.active_outbound.len() <= MAX_ACTIONS.saturating_add(2),
            "end-of-run outbound unbounded"
        );
        assert!(
            t.pending_inbound.len() <= MAX_ACTIONS.saturating_add(2),
            "end-of-run pending inbound unbounded"
        );
    }
    assert!(
        total_outbound <= MAX_ACTIONS.saturating_mul(PEER_POOL).saturating_add(8),
        "end-of-run total outbound unbounded: {total_outbound}"
    );
    assert!(
        total_inbound <= MAX_ACTIONS.saturating_mul(PEER_POOL).saturating_add(8),
        "end-of-run total pending inbound unbounded: {total_inbound}"
    );
}

fn drain_behaviour(
    behaviour: &mut Behaviour<FuzzCodec>,
    handlers: &mut HashMap<PeerId, Handler<FuzzCodec>>,
    conn_ids: &HashMap<PeerId, Vec<(ConnectionId, ConnectedPoint)>>,
    tracks: &mut HashMap<PeerId, PeerTrack>,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_POLL_DRAIN {
        match NetworkBehaviour::poll(behaviour, &mut cx) {
            Poll::Ready(ToSwarm::NotifyHandler {
                peer_id,
                event,
                handler: _,
            }) => {
                let Some(h) = handlers.get_mut(&peer_id) else {
                    continue;
                };
                h.on_behaviour_event(event);
                if let Some((cid, _)) = conn_ids.get(&peer_id).and_then(|v| v.first()) {
                    for ev in pump_handler(h) {
                        behaviour.on_connection_handler_event(peer_id, *cid, ev);
                    }
                }
            }
            Poll::Ready(ToSwarm::GenerateEvent(ev)) => {
                capture_event(ev, tracks);
            }
            Poll::Ready(_) => {}
            Poll::Pending => {
                for (peer, h) in handlers.iter_mut() {
                    if let Some((cid, _)) = conn_ids.get(peer).and_then(|v| v.first()) {
                        for ev in pump_handler(h) {
                            behaviour.on_connection_handler_event(*peer, *cid, ev);
                        }
                    }
                }
                if let Poll::Ready(ToSwarm::GenerateEvent(ev)) =
                    NetworkBehaviour::poll(behaviour, &mut cx)
                {
                    capture_event(ev, tracks);
                    continue;
                }
                break;
            }
        }
    }
}

fn capture_event(ev: Event<Vec<u8>, Vec<u8>>, tracks: &mut HashMap<PeerId, PeerTrack>) {
    match ev {
        Event::Message { peer, message, .. } => match message {
            Message::Request {
                request_id,
                channel,
                ..
            } => {
                let t = tracks.entry(peer).or_insert_with(|| PeerTrack {
                    active_outbound: Vec::new(),
                    pending_inbound: Vec::new(),
                });
                if t.pending_inbound.len() < MAX_ACTIONS {
                    t.pending_inbound.push(PendingInbound {
                        request_id,
                        channel,
                    });
                }
            }
            Message::Response { request_id, .. } => {
                if let Some(t) = tracks.get_mut(&peer) {
                    t.active_outbound.retain(|(id, _)| *id != request_id);
                }
            }
        },
        Event::OutboundFailure { peer, request_id, .. } => {
            if let Some(t) = tracks.get_mut(&peer) {
                t.active_outbound.retain(|(id, _)| *id != request_id);
            }
        }
        Event::InboundFailure { peer, request_id, .. } => {
            if let Some(t) = tracks.get_mut(&peer) {
                t.pending_inbound
                    .retain(|p| p.request_id != request_id);
            }
        }
        Event::ResponseSent { peer, request_id, .. } => {
            if let Some(t) = tracks.get_mut(&peer) {
                t.pending_inbound
                    .retain(|p| p.request_id != request_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_send_inject_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 1,
                outbound: false,
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![1, 2, 3],
            },
            FuzzAction::InjectResponse {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
                data: vec![4, 5],
            },
        ]);
    }

    #[test]
    fn outbound_timeout_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![7],
            },
            FuzzAction::InjectOutboundTimeout {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
            },
        ]);
    }

    #[test]
    fn query_slot_older_ring() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![1],
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![2],
            },
            // Older ring entry (slot 1 from newest) then newest.
            FuzzAction::InjectResponse {
                peer_slot: 0,
                request_slot: 1,
                mismatch: false,
                data: vec![8],
            },
            FuzzAction::InjectOutboundTimeout {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
            },
        ]);
    }

    #[test]
    fn inbound_request_duplicate_slot_unique_ids() {
        // Two InjectRequest with the same `inbound_slot` must still produce
        // unique inbound request ids (the harness synthesizes them with a
        // monotonic counter), otherwise the second insert trips
        // `debug_assert!("Expect id of new request to be unknown.")`.
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: false,
            },
            FuzzAction::InjectRequest {
                peer_slot: 0,
                inbound_slot: 0,
                data: vec![1],
            },
            FuzzAction::InjectRequest {
                peer_slot: 0,
                inbound_slot: 0,
                data: vec![2],
            },
        ]);
    }

    /// Regression: connection churn must not trip the per-connection
    /// `debug_assert!` in the OutboundTimeout arm. The behaviour tracks
    /// pending outbound responses per connection and `try_send_request`
    /// distributes requests via `connections[id.0 % len]`. The harness must
    /// therefore inject the timeout on the SAME connection the request was
    /// sent over, not `conn_ids[peer].first()`.
    #[test]
    fn outbound_timeout_connection_churn() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            // id 0 -> connections[0], id 1 -> connections[1].
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![1],
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![2],
            },
            // Newest request (id 1) lives on connections[1]; a `.first()`
            // injection would hit the debug_assert before the fix.
            FuzzAction::InjectOutboundTimeout {
                peer_slot: 0,
                request_slot: 0,
                mismatch: false,
            },
        ]);
    }

    /// Ghost ids trip `debug_assert!` in Behaviour; exercise under release soaks.
    #[test]
    #[cfg(not(debug_assertions))]
    fn query_slot_mismatch_release() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::InjectResponse {
                peer_slot: 0,
                request_slot: 3,
                mismatch: true,
                data: vec![8],
            },
            FuzzAction::InjectOutboundTimeout {
                peer_slot: 0,
                request_slot: 1,
                mismatch: true,
            },
        ]);
    }

    #[test]
    fn inbound_request_response_omission_smoke() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 2,
                outbound: false,
            },
            FuzzAction::InjectRequest {
                peer_slot: 2,
                inbound_slot: 0,
                data: vec![9, 9],
            },
            FuzzAction::InjectResponseOmission {
                peer_slot: 2,
                inbound_slot: 0,
            },
            FuzzAction::InjectRequest {
                peer_slot: 2,
                inbound_slot: 1,
                data: vec![2],
            },
            FuzzAction::BlackholeResponse {
                peer_slot: 2,
                inbound_slot: 0,
            },
        ]);
    }

    #[test]
    fn disconnect_clears_pending_outbound() {
        fuzz_behaviour([
            FuzzAction::Connect {
                peer_slot: 0,
                outbound: true,
            },
            FuzzAction::SendRequest {
                peer_slot: 0,
                data: vec![1],
            },
            FuzzAction::Disconnect { peer_slot: 0 },
        ]);
    }

    #[test]
    fn encode_payload_roundtrip_len() {
        let frame = encode_payload(&vec![0xAB; 100]);
        assert_eq!(frame.len(), 4 + 100);
    }
}
