//! ConnectionHandler mock-stream driver for Kademlia (feature = `"fuzzing"`).
//!
//! Drives [`Handler`] with [`Stream::from_async_rw`] so libFuzzer reaches inbound
//! request decode, ProtocolConfirmed, outbound substream request/response, and
//! response encode — paths the Behaviour inject harness skips.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use asynchronous_codec::Framed;
use futures::{
    AsyncRead, AsyncWrite,
    future::Either,
    task::noop_waker_ref,
};
use libp2p_core::{ConnectedPoint, Endpoint, Multiaddr, multiaddr::Protocol, transport::PortUse};
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, StreamUpgradeError,
    handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound},
};

use crate::{
    Mode, QueryId,
    handler::{Handler, HandlerEvent, HandlerIn, HandlerQueryErr},
    protocol::{Codec, KadRequestMsg, KadResponseMsg, ProtocolConfig},
};

/// Bound polls in a single driver invocation.
pub const MAX_HANDLER_POLLS: usize = 256;
const MAX_PACKET: usize = 4 * 1024;

/// How to drive the outbound substream after `OutboundSubstreamRequest`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutboundDrive {
    /// Inject a mock FindNode response (happy path).
    #[default]
    MockResponse,
    /// Inject [`DialUpgradeError`] with [`StreamUpgradeError::Timeout`].
    ///
    /// Hits `StreamUpgradeError::Timeout → Io(TimedOut)` inside `queue_new_stream`.
    DialUpgradeTimeout,
    /// Leave the outbound pending; use a near-zero substreams timeout so
    /// `FuturesTupleSet` emits the idle TimedOut arm.
    SubstreamIdleTimeout,
    /// [`DialUpgradeError::NegotiationFailed`] → `Io(ConnectionRefused)`.
    DialUpgradeNegotiationFailed,
    /// [`DialUpgradeError::Apply`] → mapped Apply `io::Error` (InvalidData).
    DialUpgradeApply,
    /// [`DialUpgradeError::Io`] → passthrough `Io(ConnectionReset)`.
    DialUpgradeIo,
}

/// Outbound write-side faults for mock [`AsyncWrite`] (request/response encode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFault {
    /// Max bytes accepted per `poll_write` (`0` = unlimited).
    pub write_cap: usize,
    /// Every Nth write returns `Pending` once (`0` = never).
    pub stall_every: usize,
    /// Every Nth write returns `ConnectionReset` (`0` = never).
    pub err_every: usize,
    /// Every Nth flush returns `Pending` once (`0` = never).
    pub flush_stall_every: usize,
    /// Emit `Ok(0)` once (the AsyncWrite zero-progress trap) before resuming.
    pub zero_progress_once: bool,
}

impl Default for WriteFault {
    fn default() -> Self {
        Self {
            write_cap: 0,
            stall_every: 0,
            err_every: 0,
            flush_stall_every: 0,
            zero_progress_once: false,
        }
    }
}

impl WriteFault {
    pub const NONE: Self = Self {
        write_cap: 0,
        stall_every: 0,
        err_every: 0,
        flush_stall_every: 0,
        zero_progress_once: false,
    };

    pub fn is_stressed(self) -> bool {
        self.write_cap > 0
            || self.stall_every > 0
            || self.err_every > 0
            || self.flush_stall_every > 0
            || self.zero_progress_once
    }
}

#[derive(Clone)]
struct WriteCtrl {
    inner: Arc<Mutex<WriteState>>,
}

struct WriteState {
    writes: usize,
    flushes: usize,
    write_cap: usize,
    stall_every: usize,
    err_every: usize,
    flush_stall_every: usize,
    resume: bool,
    flush_resume: bool,
    zero_progress_once: bool,
}

impl WriteCtrl {
    fn new(fault: WriteFault) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WriteState {
                writes: 0,
                flushes: 0,
                write_cap: fault.write_cap,
                stall_every: fault.stall_every,
                err_every: fault.err_every,
                flush_stall_every: fault.flush_stall_every,
                resume: false,
                flush_resume: false,
                zero_progress_once: fault.zero_progress_once,
            })),
        }
    }

    fn poll_write(&self, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut st = self.inner.lock().expect("write ctrl");
        // Zero-progress trap: report Ok(0) once (AsyncWrite sink underflow).
        if st.zero_progress_once {
            st.zero_progress_once = false;
            return Poll::Ready(Ok(0));
        }
        if st.resume {
            st.resume = false;
        } else if st.stall_every != 0 {
            let next = st.writes.wrapping_add(1);
            if next % st.stall_every == 0 {
                st.writes = next;
                st.resume = true;
                return Poll::Pending;
            }
        }
        st.writes = st.writes.wrapping_add(1);
        if st.err_every != 0 && st.writes % st.err_every == 0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let n = if st.write_cap == 0 {
            buf.len()
        } else {
            buf.len().min(st.write_cap.max(1))
        };
        Poll::Ready(Ok(n))
    }

    fn poll_flush(&self) -> Poll<io::Result<()>> {
        let mut st = self.inner.lock().expect("write ctrl");
        if st.flush_stall_every == 0 {
            return Poll::Ready(Ok(()));
        }
        if st.flush_resume {
            st.flush_resume = false;
            return Poll::Ready(Ok(()));
        }
        let next = st.flushes.wrapping_add(1);
        st.flushes = next;
        if next % st.flush_stall_every == 0 {
            st.flush_resume = true;
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

/// Shared byte feed for partial / reset inbound reads.
#[derive(Clone)]
pub(crate) struct ChunkFeed {
    inner: Arc<Mutex<ChunkState>>,
}

struct ChunkState {
    q: VecDeque<u8>,
    chunk_cap: usize,
    reads: usize,
    reset_every: usize,
    pending_once: bool,
    closed: bool,
    /// Reorder window: pop from the back instead of the front on even reads.
    reorder_window: usize,
    /// Re-emit the previous read's bytes on every Nth read (duplication).
    dup_every: usize,
    /// Drain `reorder_window` bytes as lost on every Nth read (drop).
    drop_every: usize,
    /// Bytes held for the next duplicate read.
    dup_buf: Vec<u8>,
}

impl ChunkFeed {
    pub(crate) fn new(
        bytes: impl IntoIterator<Item = u8>,
        chunk_cap: usize,
        reset_every: usize,
    ) -> Self {
        Self::faulty(bytes, chunk_cap, reset_every, 0, 0, 0)
    }

    /// Feed with read-side reorder / duplication / drop faults.
    ///
    /// - `reorder_window > 1`: every even read pops up to `chunk_cap` bytes from
    ///   the back of the window instead of the front (out-of-order delivery).
    /// - `dup_every > 0`: every Nth read re-emits the previous read's bytes.
    /// - `drop_every > 0`: every Nth read drains `reorder_window` bytes as lost.
    pub(crate) fn faulty(
        bytes: impl IntoIterator<Item = u8>,
        chunk_cap: usize,
        reset_every: usize,
        reorder_window: usize,
        dup_every: usize,
        drop_every: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChunkState {
                q: bytes.into_iter().collect(),
                chunk_cap: chunk_cap.max(1),
                reads: 0,
                reset_every,
                pending_once: false,
                closed: false,
                reorder_window,
                dup_every,
                drop_every,
                dup_buf: Vec::new(),
            })),
        }
    }

    pub(crate) fn push(&self, bytes: &[u8]) {
        self.inner
            .lock()
            .expect("chunk feed")
            .q
            .extend(bytes.iter().copied());
    }

    pub(crate) fn close(&self) {
        self.inner.lock().expect("chunk feed").closed = true;
    }

    pub(crate) fn into_io_with_write(self, write: WriteFault) -> ChunkIo {
        ChunkIo {
            feed: self,
            write: WriteCtrl::new(write),
        }
    }

    pub(crate) fn clone_feed(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub(crate) struct ChunkIo {
    feed: ChunkFeed,
    write: WriteCtrl,
}

impl AsyncRead for ChunkIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.feed.inner.lock().expect("chunk feed");
        if st.pending_once {
            st.pending_once = false;
            return Poll::Pending;
        }
        st.reads = st.reads.wrapping_add(1);
        if st.reset_every != 0 && st.reads % st.reset_every == 0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        // Duplication fault: replay the previous read's bytes.
        if st.dup_every != 0 && st.reads % st.dup_every == 0 && !st.dup_buf.is_empty() {
            let n = st.dup_buf.len().min(buf.len());
            buf[..n].copy_from_slice(&st.dup_buf[..n]);
            return Poll::Ready(Ok(n));
        }
        // Drop fault: lose a window of bytes (simulate packet loss).
        if st.drop_every != 0 && st.reads % st.drop_every == 0 {
            for _ in 0..st.reorder_window {
                st.q.pop_front();
            }
        }
        if st.q.is_empty() {
            st.dup_buf.clear();
            return if st.closed {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
            };
        }
        let n = st.q.len().min(buf.len()).min(st.chunk_cap);
        let reorder = st.reorder_window > 1 && st.reads % 2 == 0;
        st.dup_buf.clear();
        st.dup_buf.reserve(n);
        for b in buf.iter_mut().take(n) {
            // Reorder fault: pull from the back of the window instead of the front.
            let src = if reorder {
                st.q.pop_back()
            } else {
                st.q.pop_front()
            };
            let byte = src.expect("len checked");
            *b = byte;
            st.dup_buf.push(byte);
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for ChunkIo {
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

/// Outbound mock: preloaded response bytes for reads; writes honor [`WriteFault`].
struct OutboundMockIo {
    response: Vec<u8>,
    pos: usize,
    write: WriteCtrl,
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
        Poll::Ready(Ok(n)) // 0 → EOF after response consumed
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

fn fuzz_peer_id() -> PeerId {
    let mut bytes = [0xC0u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed kad ed25519 seed")
            .public(),
    )
}

fn fuzz_endpoint() -> ConnectedPoint {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST));
    addr.push(Protocol::Tcp(4001));
    ConnectedPoint::Dialer {
        address: addr,
        role_override: Endpoint::Dialer,
        port_use: PortUse::Reuse,
    }
}

fn fuzz_protocol_config(outbound: OutboundDrive) -> ProtocolConfig {
    let mut cfg = ProtocolConfig::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
    cfg.set_max_packet_size(MAX_PACKET);
    // Idle-timeout arm: zero-duration Delay is already due, so the global
    // futures-timer thread fires it on its next tick without any wall-clock
    // sleep in the poll loop (deterministic vs `Duration::from_millis(1)`).
    let timeout = match outbound {
        OutboundDrive::SubstreamIdleTimeout => Duration::ZERO,
        _ => Duration::from_secs(60),
    };
    cfg.set_substreams_timeout(timeout);
    cfg
}

fn inbound_codec() -> Codec<KadResponseMsg, KadRequestMsg> {
    Codec::new(MAX_PACKET)
}

fn outbound_codec() -> Codec<KadRequestMsg, KadResponseMsg> {
    Codec::new(MAX_PACKET)
}

pub(crate) fn inject_inbound(handler: &mut Handler, feed: ChunkFeed, write: WriteFault) {
    let stream = Stream::from_async_rw(feed.into_io_with_write(write));
    let framed = Framed::new(stream, inbound_codec());
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: Either::Left(framed),
            info: (),
        },
    ));
}

pub(crate) fn inject_outbound(
    handler: &mut Handler,
    response_wire: Vec<u8>,
    write: WriteFault,
) {
    let stream = Stream::from_async_rw(OutboundMockIo {
        response: response_wire,
        pos: 0,
        write: WriteCtrl::new(write),
    });
    let framed = Framed::new(stream, outbound_codec());
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedOutbound(
        FullyNegotiatedOutbound {
            protocol: framed,
            info: (),
        },
    ));
}

/// Poll handler; fulfill outbound requests per [`OutboundDrive`].
///
/// When `auto_respond` is true (standalone driver), answer inbound RPCs that
/// wait on Behaviour so the response-encode path runs without a Behaviour.
pub(crate) fn drain_handler(
    handler: &mut Handler,
    events: &mut Vec<HandlerEvent>,
    outbound_response: &[u8],
    auto_respond: bool,
    outbound: OutboundDrive,
    write: WriteFault,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    // Idle-timeout path: Delay(1ms) may need a real tick before Ready.
    let mut idle_waits = 0u8;
    // Partial writes + stalls need many Handler polls under noop_waker.
    let poll_limit = if write.is_stressed() {
        MAX_HANDLER_POLLS.saturating_mul(8)
    } else {
        MAX_HANDLER_POLLS
    };
    let mut pending_retries = if write.is_stressed() {
        poll_limit
    } else {
        0
    };
    for _ in 0..poll_limit {
        match ConnectionHandler::poll(handler, &mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => {
                if auto_respond {
                    match &ev {
                        HandlerEvent::FindNodeReq { request_id, .. } => {
                            handler.on_behaviour_event(HandlerIn::FindNodeRes {
                                closer_peers: Vec::new(),
                                request_id: *request_id,
                            });
                        }
                        HandlerEvent::GetProvidersReq { request_id, .. } => {
                            handler.on_behaviour_event(HandlerIn::GetProvidersRes {
                                closer_peers: Vec::new(),
                                provider_peers: Vec::new(),
                                request_id: *request_id,
                            });
                        }
                        HandlerEvent::GetRecord { request_id, .. } => {
                            handler.on_behaviour_event(HandlerIn::GetRecordRes {
                                record: None,
                                closer_peers: Vec::new(),
                                request_id: *request_id,
                            });
                        }
                        HandlerEvent::PutRecord { request_id, record } => {
                            handler.on_behaviour_event(HandlerIn::PutRecordRes {
                                key: record.key.clone(),
                                value: record.value.clone(),
                                request_id: *request_id,
                            });
                        }
                        _ => {}
                    }
                }
                events.push(ev);
            }
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. }) => {
                match outbound {
                    OutboundDrive::MockResponse => {
                        inject_outbound(handler, outbound_response.to_vec(), write);
                    }
                    OutboundDrive::DialUpgradeTimeout => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::Timeout,
                            },
                        ));
                    }
                    OutboundDrive::DialUpgradeNegotiationFailed => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::NegotiationFailed,
                            },
                        ));
                    }
                    OutboundDrive::DialUpgradeApply => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::Apply(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "fuzz Apply",
                                )),
                            },
                        ));
                    }
                    OutboundDrive::DialUpgradeIo => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::Io(
                                    io::ErrorKind::ConnectionReset.into(),
                                ),
                            },
                        ));
                    }
                    OutboundDrive::SubstreamIdleTimeout => {
                        // Leave pending_streams / oneshot unsettled so Delay wins.
                    }
                }
            }
            Poll::Ready(_) => {}
            Poll::Pending => {
                if outbound == OutboundDrive::SubstreamIdleTimeout && idle_waits < 8 {
                    idle_waits = idle_waits.saturating_add(1);
                    // The zero-duration Delay is already due; the global
                    // futures-timer thread fires it within a millisecond. Sleep
                    // (bounded) instead of spin-yield so it fires reliably even
                    // under scheduler contention (yield_now flakes in CI).
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                if pending_retries > 0 {
                    pending_retries -= 1;
                    continue;
                }
                break;
            }
        }
    }
}

/// Standalone driver: inbound wire chunks (+ optional outbound FindNodeReq).
pub fn fuzz_handler_io(
    wire_chunks: impl IntoIterator<Item = Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    enqueue_outbound_find_node: bool,
    outbound: OutboundDrive,
    write: WriteFault,
) -> Vec<HandlerEvent> {
    let feed = collect_feed(wire_chunks, chunk_cap, reset_every);
    fuzz_handler_io_with_feed(feed, enqueue_outbound_find_node, outbound, write)
}

/// Like [`fuzz_handler_io`] but with reorder / duplication / drop read faults and
/// an optional AsyncWrite zero-progress trap, so the mock transport exercises
/// out-of-order delivery, duplication, packet loss, and sink underflow.
pub fn fuzz_handler_io_faulty(
    wire_chunks: impl IntoIterator<Item = Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    reorder_window: usize,
    dup_every: usize,
    drop_every: usize,
    enqueue_outbound_find_node: bool,
    outbound: OutboundDrive,
    write: WriteFault,
) -> Vec<HandlerEvent> {
    let mut bytes = Vec::new();
    for chunk in wire_chunks {
        let take = chunk.len().min(MAX_PACKET);
        bytes.extend_from_slice(&chunk[..take]);
    }
    let feed = ChunkFeed::faulty(
        bytes,
        chunk_cap.max(1),
        reset_every,
        reorder_window.max(1),
        dup_every,
        drop_every,
    );
    feed.close();
    fuzz_handler_io_with_feed(feed, enqueue_outbound_find_node, outbound, write)
}

fn collect_feed(
    wire_chunks: impl IntoIterator<Item = Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
) -> ChunkFeed {
    let mut bytes = Vec::new();
    for chunk in wire_chunks {
        let take = chunk.len().min(MAX_PACKET);
        bytes.extend_from_slice(&chunk[..take]);
    }
    let feed = ChunkFeed::new(bytes, chunk_cap.max(1), reset_every);
    feed.close();
    feed
}

fn fuzz_handler_io_with_feed(
    feed: ChunkFeed,
    enqueue_outbound_find_node: bool,
    outbound: OutboundDrive,
    write: WriteFault,
) -> Vec<HandlerEvent> {
    let peer = fuzz_peer_id();
    let mut handler = Handler::new(
        fuzz_protocol_config(outbound),
        fuzz_endpoint(),
        peer,
        Mode::Server,
    );

    // Fault / timeout arms require an outbound request so DialUpgradeError / idle Delay apply.
    let enqueue = enqueue_outbound_find_node
        || matches!(
            outbound,
            OutboundDrive::DialUpgradeTimeout
                | OutboundDrive::SubstreamIdleTimeout
                | OutboundDrive::DialUpgradeNegotiationFailed
                | OutboundDrive::DialUpgradeApply
                | OutboundDrive::DialUpgradeIo
        )
        || write.is_stressed();
    if enqueue {
        handler.on_behaviour_event(HandlerIn::FindNodeReq {
            key: vec![0xAB; 32],
            query_id: QueryId::fuzz(1),
        });
    }

    // Dial/idle fault arms never reach encode — keep writes unlimited there.
    let write_for_io = match outbound {
        OutboundDrive::MockResponse => write,
        _ => WriteFault::NONE,
    };

    // Keep inbound writes unlimited so auto-respond encode cannot starve the
    // outbound request path; WriteFault applies to OutboundMockIo only.
    inject_inbound(&mut handler, feed, WriteFault::NONE);

    // Empty FindNode response: length-delimited empty closer_peers list.
    let outbound_resp = encode_empty_find_node_response();

    let mut events = Vec::new();
    drain_handler(
        &mut handler,
        &mut events,
        &outbound_resp,
        true,
        outbound,
        write_for_io,
    );
    events
}

/// True if any event is `QueryError` with `Io` kind TimedOut.
pub fn events_contain_io_timed_out(events: &[HandlerEvent]) -> bool {
    events_contain_io_kind(events, io::ErrorKind::TimedOut)
}

/// True if any event is `QueryError` with the given `Io` kind.
pub fn events_contain_io_kind(events: &[HandlerEvent], kind: io::ErrorKind) -> bool {
    events.iter().any(|e| {
        matches!(
            e,
            HandlerEvent::QueryError {
                error: HandlerQueryErr::Io(err),
                ..
            } if err.kind() == kind
        )
    })
}

fn encode_empty_find_node_response() -> Vec<u8> {
    use asynchronous_codec::Encoder;
    use bytes::BytesMut;
    // Response wire uses the same prost framing; encode via response-as-A codec.
    let mut codec = inbound_codec();
    let mut buf = BytesMut::new();
    let _ = codec.encode(
        KadResponseMsg::FindNode {
            closer_peers: Vec::new(),
        },
        &mut buf,
    );
    buf.to_vec()
}

/// Attach a live inbound feed (Pending when empty) for Behaviour wiring.
#[allow(dead_code)] // Convenience wrapper; Behaviour uses `_ex`.
pub(crate) fn attach_live_inbound(handler: &mut Handler) -> ChunkFeed {
    attach_live_inbound_ex(handler, WriteFault::NONE)
}

/// Like [`attach_live_inbound`] with write-side backpressure on the inbound duplex
/// (Behaviour→Handler response encode under stall).
pub(crate) fn attach_live_inbound_ex(handler: &mut Handler, write: WriteFault) -> ChunkFeed {
    let feed = ChunkFeed::new(std::iter::empty::<u8>(), 64, 0);
    let for_push = feed.clone_feed();
    inject_inbound(handler, feed, write);
    let mut events = Vec::new();
    drain_handler(
        handler,
        &mut events,
        &[],
        false,
        OutboundDrive::MockResponse,
        WriteFault::NONE,
    );
    for_push
}

/// Pump without auto-respond (Behaviour delivers `HandlerIn` via NotifyHandler).
pub fn pump_handler(handler: &mut Handler) -> Vec<HandlerEvent> {
    let mut events = Vec::new();
    drain_handler(
        handler,
        &mut events,
        &encode_empty_find_node_response(),
        false,
        OutboundDrive::MockResponse,
        WriteFault::NONE,
    );
    events
}
