//! QUIC fuzz driver (feature `fuzzing`).
//!
//! Arms (byte0 selector, biased toward structured handshake):
//!   0 — Multiaddr parse (`quic` / `quic-v1` + optional `/p2p/...`)
//!   1 — [`Config::new`] from deterministic seed (+ timeout / draft-29 knobs)
//!   2 — `quinn_proto::PartialDecode` on raw UDP payload (blackhole inbound)
//!   3..=4 — structured mutual handshake via in-memory `quinn_proto::Endpoint`
//!   5 — structured + corrupt peer cert DER before handshake
//!   6 — structured + flip one mid-handshake wire byte
//!   7 — post-handshake bi-stream R/W (bounded)
//!   8 — hole-punch via mock [`Provider`] (timeout / send_to error; no real UDP I/O)
//!   9 — [`HolePunchBook`] register/cancel/complete races
//!
//! No live network I/O for handshake/hole-punch arms: packet exchange is an
//! in-process Pair; Provider `send_to` is stubbed. Structured arms assert remote
//! [`PeerId`] matches the peer identity cert binding.

use std::{
    cell::Cell,
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use libp2p_core::{Multiaddr, multiaddr::Protocol};
use libp2p_identity::{Keypair, PeerId};
use libp2p_tls::certificate;
use quinn::rustls::pki_types::CertificateDer;
use quinn_proto::{
    ClientConfig, Connection, ConnectionEvent, ConnectionHandle, DatagramEvent, Dir, Endpoint,
    EndpointConfig, EndpointEvent, Event, FixedLengthConnectionIdParser, Incoming, PartialDecode,
    ServerConfig, StreamEvent, Transmit, TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};

use crate::{
    Config, Error,
    hole_punching::{fuzz_book::fuzz_hole_punch_book, hole_puncher},
    provider::{Provider, Runtime},
    transport::multiaddr_to_socketaddr,
};

const STEP_BUDGET: usize = 256;
const MAX_DATAGRAMS: usize = 8;
const STREAM_RW_BUDGET: usize = 64;
const HOLE_PUNCH_POLL_BUDGET: usize = 64;
/// Same placeholder SNI used by [`crate::GenTransport::dial`].
const SERVER_NAME: &str = "l";

thread_local! {
    /// Mock Provider knobs for hole-punch arms (associated-fn Provider API).
    static FUZZ_HP: Cell<FuzzHpMode> = const { Cell::new(FuzzHpMode::InstantTimeout) };
}

#[derive(Clone, Copy)]
enum FuzzHpMode {
    /// All sleeps complete immediately → timeout wins `select`.
    InstantTimeout,
    /// Short sleeps ready; long (timeout) sleep pending; `send_to` fails.
    SendFail,
}

/// Drive QUIC multiaddr parse, Config, packet decode, TLS-over-QUIC handshake,
/// and hole-punch state.
///
/// Invariants: never panics; always terminates (step / poll budgets).
pub fn fuzz_quic(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let arm = data[0] % 10;
    let payload = &data[1..];

    match arm {
        0 => fuzz_parse_multiaddr(payload),
        1 => fuzz_config_from_seed(payload),
        2 => fuzz_partial_decode_raw(payload),
        3 | 4 => fuzz_structured_handshake(payload, CorruptMode::None, false),
        5 => fuzz_structured_handshake(payload, CorruptMode::CertDer, false),
        6 => fuzz_structured_handshake(payload, CorruptMode::MidWire, false),
        7 => fuzz_structured_handshake(payload, CorruptMode::None, true),
        8 => fuzz_hole_punch_provider(payload),
        _ => fuzz_hole_punch_book(payload),
    }
}

#[derive(Clone, Copy)]
enum CorruptMode {
    None,
    CertDer,
    MidWire,
}

fn fuzz_parse_multiaddr(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let support_draft_29 = flags & 1 != 0;

    let ip_slot = data.get(1).copied().unwrap_or(127);
    let port = u16::from_le_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0x30),
    ]);
    let use_v1 = flags & 2 == 0;
    let with_p2p = flags & 4 != 0;
    let use_ip6 = flags & 8 != 0;

    let mut addr = Multiaddr::empty();
    if use_ip6 {
        addr.push(Protocol::Ip6(std::net::Ipv6Addr::LOCALHOST));
    } else {
        addr.push(Protocol::Ip4(Ipv4Addr::new(ip_slot, 0, 0, 1)));
    }
    addr.push(Protocol::Udp(port));
    if use_v1 {
        addr.push(Protocol::QuicV1);
    } else {
        addr.push(Protocol::Quic);
    }
    if with_p2p {
        let mut seed = [0x51u8; 32]; // 'Q'
        seed[31] = flags;
        if let Ok(kp) = Keypair::ed25519_from_bytes(&mut seed) {
            addr.push(Protocol::P2p(kp.public().to_peer_id()));
        }
    }
    let _ = multiaddr_to_socketaddr(&addr, support_draft_29);

    if let Ok(s) = std::str::from_utf8(data.get(4..).unwrap_or(&[])) {
        if let Ok(ma) = s.parse::<Multiaddr>() {
            let _ = multiaddr_to_socketaddr(&ma, support_draft_29);
        }
    }
}

#[expect(deprecated)]
fn fuzz_config_from_seed(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let mut seed = [0x43u8; 32]; // 'C'
    seed[31] = flags;
    let Ok(kp) = Keypair::ed25519_from_bytes(&mut seed) else {
        return;
    };
    let mut cfg = Config::new(&kp);
    cfg.handshake_timeout = Duration::from_millis(1 + u64::from(flags));
    cfg.max_idle_timeout = 1 + u32::from(flags).saturating_mul(10);
    cfg.keep_alive_interval = Duration::from_millis(u64::from(flags).saturating_add(1));
    cfg.support_draft_29 = flags & 0x80 != 0;
    if flags & 0x40 != 0 {
        cfg = cfg.disable_path_mtu_discovery();
    }
    if flags & 0x20 != 0 {
        cfg = cfg.mtu_upper_bound(1200 + u16::from(flags));
    }
    // Force QuinnConfig conversion (TLS wrap + transport knobs).
    let _: crate::config::QuinnConfig = cfg.into();
}

fn fuzz_partial_decode_raw(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut bytes = BytesMut::from(data);
    if bytes.len() > 4096 {
        bytes.truncate(4096);
    }
    let _ = PartialDecode::new(
        bytes,
        &FixedLengthConnectionIdParser::new(8),
        &[1u32],
        true,
    );
}

fn fuzz_structured_handshake(data: &[u8], corrupt: CorruptMode, post_stream: bool) {
    let flags = data.first().copied().unwrap_or(0);
    let flip_idx = data.get(1).copied().unwrap_or(flags) as usize;
    let body = data.get(2..).unwrap_or(&[]);

    let mut server_seed = [0x53u8; 32]; // 'S'
    server_seed[31] = flags;
    let Ok(server_id) = Keypair::ed25519_from_bytes(&mut server_seed) else {
        return;
    };
    let mut client_seed = [0x63u8; 32]; // 'c'
    client_seed[31] = flags.wrapping_add(1);
    let Ok(client_id) = Keypair::ed25519_from_bytes(&mut client_seed) else {
        return;
    };

    let expected_server = server_id.public().to_peer_id();
    let expected_client = client_id.public().to_peer_id();

    let corrupt_server = matches!(corrupt, CorruptMode::CertDer) && flags & 1 == 0;
    let corrupt_client = matches!(corrupt, CorruptMode::CertDer) && flags & 1 != 0;

    let Ok(server_crypto) = server_quic_crypto(&server_id, corrupt_server) else {
        return;
    };
    let Ok(client_crypto) =
        client_quic_crypto(&client_id, Some(expected_server), corrupt_client)
    else {
        return;
    };

    let mut pair = MatchPair::new(server_crypto, client_crypto);
    let flip = matches!(corrupt, CorruptMode::MidWire).then_some(flip_idx);
    match pair.handshake(flip) {
        HandshakeOutcome::Connected {
            server_saw,
            client_saw,
        } => {
            if matches!(corrupt, CorruptMode::None) {
                assert_eq!(server_saw, Some(expected_client), "server PeerId binding");
                assert_eq!(client_saw, Some(expected_server), "client PeerId binding");
            }
            if post_stream {
                pair.stream_rw(body);
            }
        }
        HandshakeOutcome::Failed | HandshakeOutcome::Timeout => {}
    }
}

fn server_quic_crypto(
    identity: &Keypair,
    corrupt_cert: bool,
) -> Result<Arc<QuicServerConfig>, ()> {
    let (mut cert, key) = certificate::generate(identity).map_err(|_| ())?;
    if corrupt_cert {
        flip_cert_byte(&mut cert);
    }
    let tls = libp2p_tls::make_server_config_with_material(cert, &key).map_err(|_| ())?;
    QuicServerConfig::try_from(tls).map(Arc::new).map_err(|_| ())
}

fn client_quic_crypto(
    identity: &Keypair,
    remote: Option<PeerId>,
    corrupt_cert: bool,
) -> Result<Arc<QuicClientConfig>, ()> {
    let (mut cert, key) = certificate::generate(identity).map_err(|_| ())?;
    if corrupt_cert {
        flip_cert_byte(&mut cert);
    }
    let tls =
        libp2p_tls::make_client_config_with_material(identity, cert, &key, remote).map_err(|_| ())?;
    QuicClientConfig::try_from(tls).map(Arc::new).map_err(|_| ())
}

fn flip_cert_byte(cert: &mut CertificateDer<'static>) {
    let mut v = cert.as_ref().to_vec();
    let mid = v.len() / 2;
    if let Some(b) = v.get_mut(mid) {
        *b ^= 0x5A;
    }
    *cert = CertificateDer::from(v);
}

enum HandshakeOutcome {
    Connected {
        server_saw: Option<PeerId>,
        client_saw: Option<PeerId>,
    },
    Failed,
    Timeout,
}

/// In-memory client↔server packet Pair (no UDP).
struct MatchPair {
    server_ep: Endpoint,
    client_ep: Endpoint,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    server_conns: HashMap<ConnectionHandle, Connection>,
    client_conns: HashMap<ConnectionHandle, Connection>,
    server_inbound: VecDeque<BytesMut>,
    client_inbound: VecDeque<BytesMut>,
    server_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    client_events: HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    now: Instant,
    client_config: ClientConfig,
    client_connected: bool,
    server_connected: bool,
    client_lost: bool,
    server_lost: bool,
}

impl MatchPair {
    fn new(server_crypto: Arc<QuicServerConfig>, client_crypto: Arc<QuicClientConfig>) -> Self {
        let mut server_cfg = ServerConfig::with_crypto(server_crypto);
        server_cfg.migration(false);
        let mut transport = TransportConfig::default();
        transport.max_concurrent_uni_streams(0u32.into());
        transport.max_idle_timeout(Some(VarInt::from_u32(5_000).into()));
        transport.keep_alive_interval(None);
        let transport = Arc::new(transport);
        server_cfg.transport = Arc::clone(&transport);

        let mut endpoint_cfg = EndpointConfig::default();
        endpoint_cfg.supported_versions(vec![1]);
        let endpoint_cfg = Arc::new(endpoint_cfg);

        let server_ep = Endpoint::new(
            Arc::clone(&endpoint_cfg),
            Some(Arc::new(server_cfg)),
            true,
            Some([0x51u8; 32]),
        );
        let client_ep = Endpoint::new(endpoint_cfg, None, true, Some([0x43u8; 32]));

        let mut client_config = ClientConfig::new(client_crypto);
        client_config.transport_config(transport);

        Self {
            server_ep,
            client_ep,
            server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4443),
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444),
            server_conns: HashMap::new(),
            client_conns: HashMap::new(),
            server_inbound: VecDeque::new(),
            client_inbound: VecDeque::new(),
            server_events: HashMap::new(),
            client_events: HashMap::new(),
            now: Instant::now(),
            client_config,
            client_connected: false,
            server_connected: false,
            client_lost: false,
            server_lost: false,
        }
    }

    fn handshake(&mut self, flip_idx: Option<usize>) -> HandshakeOutcome {
        let Ok((ch, conn)) = self.client_ep.connect(
            self.now,
            self.client_config.clone(),
            self.server_addr,
            SERVER_NAME,
        ) else {
            return HandshakeOutcome::Failed;
        };
        self.client_conns.insert(ch, conn);

        let mut flips_left = if flip_idx.is_some() { 1u8 } else { 0 };
        let flip_at = flip_idx.unwrap_or(0);

        for step in 0..STEP_BUDGET {
            self.drive_client(&mut flips_left, flip_at, step);
            self.drive_server(&mut flips_left, flip_at, step);
            self.poll_appside_events();

            if self.client_lost || self.server_lost {
                return HandshakeOutcome::Failed;
            }
            if self.client_connected && self.server_connected {
                let client_saw = self.client_conns.values().find_map(peer_id_from_conn);
                let server_saw = self.server_conns.values().find_map(peer_id_from_conn);
                return HandshakeOutcome::Connected {
                    server_saw,
                    client_saw,
                };
            }
            self.now += Duration::from_millis(1);
        }
        HandshakeOutcome::Timeout
    }

    fn drive_client(&mut self, flips_left: &mut u8, flip_at: usize, step: usize) {
        let mut buf = Vec::with_capacity(2048);
        while let Some(packet) = self.client_inbound.pop_front() {
            if let Some(ev) =
                self.client_ep
                    .handle(self.now, self.server_addr, None, None, packet, &mut buf)
            {
                match ev {
                    DatagramEvent::NewConnection(incoming) => {
                        // Client endpoint has no server_config; ignore.
                        self.client_ep.ignore(incoming);
                    }
                    DatagramEvent::ConnectionEvent(ch, event) => {
                        self.client_events.entry(ch).or_default().push_back(event);
                    }
                    DatagramEvent::Response(transmit) => {
                        deliver_transmit(
                            &mut self.server_inbound,
                            transmit,
                            &buf,
                            flips_left,
                            flip_at,
                            step,
                        );
                        buf.clear();
                    }
                }
            }
        }

        drain_conn_events(
            &mut self.client_ep,
            &mut self.client_conns,
            &mut self.client_events,
            &mut self.server_inbound,
            self.now,
            flips_left,
            flip_at,
            step,
            &mut buf,
        );
    }

    fn drive_server(&mut self, flips_left: &mut u8, flip_at: usize, step: usize) {
        let mut buf = Vec::with_capacity(2048);
        while let Some(packet) = self.server_inbound.pop_front() {
            if let Some(ev) =
                self.server_ep
                    .handle(self.now, self.client_addr, None, None, packet, &mut buf)
            {
                match ev {
                    DatagramEvent::NewConnection(incoming) => {
                        accept_incoming(
                            &mut self.server_ep,
                            &mut self.server_conns,
                            incoming,
                            self.now,
                            &mut buf,
                        );
                    }
                    DatagramEvent::ConnectionEvent(ch, event) => {
                        self.server_events.entry(ch).or_default().push_back(event);
                    }
                    DatagramEvent::Response(transmit) => {
                        deliver_transmit(
                            &mut self.client_inbound,
                            transmit,
                            &buf,
                            flips_left,
                            flip_at,
                            step,
                        );
                        buf.clear();
                    }
                }
            }
        }

        drain_conn_events(
            &mut self.server_ep,
            &mut self.server_conns,
            &mut self.server_events,
            &mut self.client_inbound,
            self.now,
            flips_left,
            flip_at,
            step,
            &mut buf,
        );
    }

    fn poll_appside_events(&mut self) {
        for conn in self.client_conns.values_mut() {
            while let Some(ev) = conn.poll() {
                match ev {
                    Event::Connected => self.client_connected = true,
                    Event::ConnectionLost { .. } => self.client_lost = true,
                    Event::HandshakeDataReady | Event::Stream(_) | Event::DatagramReceived
                    | Event::DatagramsUnblocked => {}
                }
            }
        }
        for conn in self.server_conns.values_mut() {
            while let Some(ev) = conn.poll() {
                match ev {
                    Event::Connected => self.server_connected = true,
                    Event::ConnectionLost { .. } => self.server_lost = true,
                    Event::HandshakeDataReady | Event::Stream(_) | Event::DatagramReceived
                    | Event::DatagramsUnblocked => {}
                }
            }
        }
    }

    fn stream_rw(&mut self, body: &[u8]) {
        let Some(client_ch) = self.client_conns.keys().next().copied() else {
            return;
        };
        let Some(server_ch) = self.server_conns.keys().next().copied() else {
            return;
        };

        let Some(stream_id) = self
            .client_conns
            .get_mut(&client_ch)
            .and_then(|c| c.streams().open(Dir::Bi))
        else {
            return;
        };

        let payload = if body.is_empty() {
            &[0x51u8][..]
        } else {
            &body[..body.len().min(1024)]
        };
        if let Some(conn) = self.client_conns.get_mut(&client_ch) {
            let mut send = conn.send_stream(stream_id);
            let _ = send.write(payload);
            let _ = send.finish();
        }

        for _ in 0..STREAM_RW_BUDGET {
            let mut flips = 0u8;
            self.drive_client(&mut flips, 0, 0);
            self.drive_server(&mut flips, 0, 0);

            if let Some(conn) = self.server_conns.get_mut(&server_ch) {
                while let Some(ev) = conn.poll() {
                    match ev {
                        Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                            if let Some(sid) = conn.streams().accept(Dir::Bi) {
                                drain_recv(conn, sid);
                            }
                        }
                        Event::Stream(StreamEvent::Readable { id }) => {
                            drain_recv(conn, id);
                        }
                        _ => {}
                    }
                }
            }
            self.now += Duration::from_millis(1);
        }
    }
}

fn drain_recv(conn: &mut Connection, id: quinn_proto::StreamId) {
    let mut recv = conn.recv_stream(id);
    if let Ok(mut chunks) = recv.read(true) {
        while let Ok(Some(_)) = chunks.next(2048) {}
        let _ = chunks.finalize();
    }
}

fn drain_conn_events(
    ep: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, Connection>,
    events: &mut HashMap<ConnectionHandle, VecDeque<ConnectionEvent>>,
    peer_inbound: &mut VecDeque<BytesMut>,
    now: Instant,
    flips_left: &mut u8,
    flip_at: usize,
    step: usize,
    buf: &mut Vec<u8>,
) {
    let mut endpoint_events: Vec<(ConnectionHandle, EndpointEvent)> = Vec::new();
    let chs: Vec<_> = conns.keys().copied().collect();
    for ch in chs {
        if let Some(queue) = events.get_mut(&ch) {
            while let Some(ev) = queue.pop_front() {
                if let Some(conn) = conns.get_mut(&ch) {
                    conn.handle_event(ev);
                }
            }
        }
        let Some(conn) = conns.get_mut(&ch) else {
            continue;
        };
        while let Some(ev) = conn.poll_endpoint_events() {
            endpoint_events.push((ch, ev));
        }
        while let Some(transmit) = conn.poll_transmit(now, MAX_DATAGRAMS, buf) {
            deliver_transmit(peer_inbound, transmit, buf, flips_left, flip_at, step);
            buf.clear();
        }
    }
    for (ch, ev) in endpoint_events {
        if let Some(cev) = ep.handle_event(ch, ev) {
            if let Some(conn) = conns.get_mut(&ch) {
                conn.handle_event(cev);
            }
        }
    }
}

fn accept_incoming(
    ep: &mut Endpoint,
    conns: &mut HashMap<ConnectionHandle, Connection>,
    incoming: Incoming,
    now: Instant,
    buf: &mut Vec<u8>,
) {
    match ep.accept(incoming, now, buf, None) {
        Ok((ch, conn)) => {
            conns.insert(ch, conn);
        }
        Err(_) => {}
    }
}

fn deliver_transmit(
    inbound: &mut VecDeque<BytesMut>,
    transmit: Transmit,
    buf: &[u8],
    flips_left: &mut u8,
    flip_at: usize,
    step: usize,
) {
    let size = transmit.size.min(buf.len());
    if size == 0 {
        return;
    }
    let mut packet = BytesMut::from(&buf[..size]);
    if *flips_left > 0 && step >= 1 {
        let idx = flip_at % packet.len();
        if let Some(b) = packet.get_mut(idx) {
            *b ^= 0xFF;
        }
        *flips_left = flips_left.saturating_sub(1);
    }
    inbound.push_back(packet);
}

fn peer_id_from_conn(conn: &Connection) -> Option<PeerId> {
    let identity = conn.crypto_session().peer_identity()?;
    let certs = identity.downcast_ref::<Vec<CertificateDer<'static>>>()?;
    let end_entity = certs.first()?;
    certificate::parse(end_entity)
        .ok()
        .map(|p| p.peer_id())
}

/// Mock Provider: no real UDP I/O; sleep/send controlled by [`FUZZ_HP`].
struct FuzzProvider;

impl Provider for FuzzProvider {
    type IfWatcher = ();

    fn runtime() -> Runtime {
        Runtime::Dummy
    }

    fn new_if_watcher() -> io::Result<Self::IfWatcher> {
        Ok(())
    }

    fn poll_if_event(
        _watcher: &mut Self::IfWatcher,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<if_watch::IfEvent>> {
        Poll::Pending
    }

    fn sleep(duration: Duration) -> futures::future::BoxFuture<'static, ()> {
        Box::pin(async move {
            let mode = FUZZ_HP.get();
            match mode {
                FuzzHpMode::InstantTimeout => {}
                FuzzHpMode::SendFail => {
                    // Punch-interval sleeps complete; handshake timeout stays pending
                    // so `send_to` error can win `select`.
                    if duration >= Duration::from_millis(500) {
                        futures::future::pending::<()>().await;
                    }
                }
            }
        })
    }

    fn send_to<'a>(
        _udp_socket: &'a UdpSocket,
        buf: &'a [u8],
        _target: SocketAddr,
    ) -> futures::future::BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            match FUZZ_HP.get() {
                FuzzHpMode::SendFail => Err(io::Error::other("fuzz send_to")),
                FuzzHpMode::InstantTimeout => Ok(buf.len()),
            }
        })
    }
}

fn fuzz_hole_punch_provider(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let mode = if flags & 1 == 0 {
        FuzzHpMode::InstantTimeout
    } else {
        FuzzHpMode::SendFail
    };
    FUZZ_HP.set(mode);

    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return;
    };
    // Socket is only a typed handle — Provider::send_to never touches it.
    let remote = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1 + flags % 200), 4443));
    let timeout = Duration::from_secs(5);

    let fut = hole_puncher::<FuzzProvider>(socket, remote, timeout);
    match poll_budget(fut, HOLE_PUNCH_POLL_BUDGET) {
        Some(Error::HandshakeTimedOut) | Some(Error::Io(_)) => {}
        Some(_) => {}
        None => {
            // SendFail + pending timeout should complete on first send error.
            // InstantTimeout should complete on first poll. Budget miss is soft.
        }
    }
}

fn poll_budget<F: Future>(fut: F, budget: usize) -> Option<F::Output> {
    let waker = futures::task::noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(fut);
    for _ in 0..budget {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_multiaddr_and_config() {
        fuzz_quic(&[0, 0x03, 127, 0x39, 0x30]);
        fuzz_quic(&[1, 0x01]);
        fuzz_quic(&[2, 0xc0, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn smoke_structured_handshake_identity() {
        fuzz_quic(&[3, 0x00, 0x00]);
    }

    #[test]
    fn smoke_corrupt_and_post_stream() {
        fuzz_quic(&[5, 0x01, 0x00]);
        fuzz_quic(&[6, 0x07, 0x00]);
        fuzz_quic(&[7, 0x00, b'h', b'i']);
    }

    #[test]
    fn smoke_hole_punch_timeout_and_book() {
        fuzz_quic(&[8, 0x00]); // InstantTimeout
        fuzz_quic(&[8, 0x01]); // SendFail
        fuzz_quic(&[9, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }
}
