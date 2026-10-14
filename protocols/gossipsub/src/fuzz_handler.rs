//! ConnectionHandler mock-stream driver for Gossipsub (feature = `"fuzzing"`).
//!
//! Drives [`Handler`] with [`Stream::from_async_rw`] mock I/O so libFuzzer can
//! reach encode/flush, inbound codec framing (including partial reads), and
//! outbound queue drain — paths the Behaviour-only inject harness never polls.

use std::{
    collections::{HashMap, VecDeque},
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
use futures_timer::Delay;
use libp2p_identity::Keypair;
use libp2p_swarm::{
    ConnectionHandler, ConnectionHandlerEvent, Stream, StreamUpgradeError,
    handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound},
};

use crate::{
    MessageId, TopicHash, ValidationMode,
    handler::{Handler, HandlerEvent},
    protocol::{GOSSIPSUB_1_1_0_PROTOCOL, GossipsubCodec, ProtocolConfig},
    queue::Queue,
    types::{PeerKind, RawMessage, RpcOut},
};

/// Matches `handler::MAX_SUBSTREAM_ATTEMPTS` (crate-private).
const MAX_SUBSTREAM_ATTEMPTS: usize = 5;

/// Structured ConnectionEvent / queue faults for the standalone handler driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HandlerFault {
    /// Default mock I/O path (inbound wire + optional Subscribe encode).
    #[default]
    None,
    /// [`DialUpgradeError`] Timeout (outbound).
    DialUpgradeTimeout,
    /// NegotiationFailed → `Disabled(ProtocolUnsupported)` → `PeerKind::NotSupported`.
    DialUpgradeNegotiationFailed,
    /// [`DialUpgradeError`] Io (outbound; logged, handler stays Enabled).
    DialUpgradeIo,
    /// Flood inbound FullyNegotiated → `Disabled(MaxSubstreamAttempts)`.
    MaxSubstreamAttemptsInbound,
    /// Flood outbound FullyNegotiated → `Disabled(MaxSubstreamAttempts)`.
    MaxSubstreamAttemptsOutbound,
    /// Enqueue Publish with zero timeout → `HandlerEvent::MessageDropped`.
    MessageDroppedTimedOut,
}

/// Outbound write-side faults for mock [`AsyncWrite`] (encode / flush depth).
///
/// Partial accepts (`write_cap`) keep the Framed encoder in-flight across polls.
/// `stall_every` returns `Pending` once per Nth write (drain retries under noop_waker).
/// `err_every` injects `ConnectionReset` on the Nth write.
/// `flush_stall_every` returns `Pending` once per Nth `poll_flush` (Framed flush depth).
/// `drop_every` simulates packet loss by dropping every Nth write.
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
    /// Simulate packet loss by dropping every Nth write.
    pub drop_every: usize,
}

impl Default for WriteFault {
    fn default() -> Self {
        Self {
            write_cap: 0,
            stall_every: 0,
            err_every: 0,
            flush_stall_every: 0,
        }
    }
}

impl WriteFault {
    pub const NONE: Self = Self {
        write_cap: 0,
        stall_every: 0,
        err_every: 0,
        flush_stall_every: 0,
    };

    pub fn is_stressed(self) -> bool {
        self.write_cap > 0
            || self.stall_every > 0
            || self.err_every > 0
            || self.flush_stall_every > 0
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
    /// After returning Pending, next write proceeds without re-stalling.
    resume: bool,
    /// After returning Pending on flush, next flush proceeds.
    flush_resume: bool,
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
            })),
        }
    }

    fn poll_write(&self, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut st = self.inner.lock().expect("write ctrl");
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
        
        // Handle packet loss simulation
        if st.drop_every != 0 && st.writes.wrapping_add(1) % st.drop_every == 0 {
            // Drop the packet: return Ok with the number of bytes "sent".
            return Poll::Ready(Ok(n));
        }
        
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

const MAX_TRANSMIT_SIZE: usize = 256;
const MAX_RPC_BYTES: usize = 4 * 1024;
const MAX_PUBLISH_MESSAGES: usize = 64;
const MAX_CONTROL_MESSAGE_SIZE: usize = 2 * 1024;

fn fuzz_peer_id() -> libp2p_identity::PeerId {
    let mut bytes = [0x42u8; 32];
    libp2p_identity::PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed ed25519 seed")
            .public(),
    )
}

/// Bound polls in a single driver invocation.
pub const MAX_HANDLER_POLLS: usize = 256;

/// Shared byte feed for partial / reset inbound reads.
#[derive(Clone)]
pub struct ChunkFeed {
    inner: Arc<Mutex<ChunkState>>,
}

struct ChunkState {
    q: VecDeque<u8>,
    /// Max bytes returned from a single `poll_read` (partial frames across polls).
    chunk_cap: usize,
    reads: usize,
    /// If non-zero, every Nth read returns `ConnectionReset`.
    reset_every: usize,
    /// When true, the next read returns `Pending` once then clears the flag.
    pending_once: bool,
    /// When true, empty queue yields EOF (`Ok(0)`) instead of `Pending`.
    closed: bool,
}

impl ChunkFeed {
    pub fn new(bytes: impl IntoIterator<Item = u8>, chunk_cap: usize, reset_every: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChunkState {
                q: bytes.into_iter().collect(),
                chunk_cap: chunk_cap.max(1),
                reads: 0,
                reset_every,
                pending_once: false,
                closed: false,
            })),
        }
    }

    pub fn push(&self, bytes: &[u8]) {
        self.inner
            .lock()
            .expect("chunk feed")
            .q
            .extend(bytes.iter().copied());
    }

    pub fn arm_pending_once(&self) {
        self.inner.lock().expect("chunk feed").pending_once = true;
    }

    pub fn close(&self) {
        self.inner.lock().expect("chunk feed").closed = true;
    }

    pub fn into_io(self) -> ChunkIo {
        self.into_io_with_write(WriteFault::NONE)
    }

    pub fn into_io_with_write(self, write: WriteFault) -> ChunkIo {
        ChunkIo {
            feed: self,
            write: WriteCtrl::new(write),
        }
    }

    /// Clone the feed handle (same underlying buffer) for later `push`es.
    pub fn clone_feed(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Mock AsyncRead/AsyncWrite backed by [`ChunkFeed`] + optional write faults.
pub struct ChunkIo {
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
        if st.q.is_empty() {
            return if st.closed {
                Poll::Ready(Ok(0)) // EOF
            } else {
                Poll::Pending // keep inbound substream alive for later push
            };
        }
        let n = st.q.len().min(buf.len()).min(st.chunk_cap);
        for b in buf.iter_mut().take(n) {
            *b = st.q.pop_front().expect("len checked");
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

/// Blackhole outbound sink (reads EOF; writes honor [`WriteFault`]).
pub(crate) struct BlackholeIo {
    write: WriteCtrl,
}

impl BlackholeIo {
    fn new(write: WriteFault) -> Self {
        Self {
            write: WriteCtrl::new(write),
        }
    }
}

impl AsyncRead for BlackholeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for BlackholeIo {
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

fn fuzz_protocol_config() -> ProtocolConfig {
    ProtocolConfig {
        protocol_ids: vec![GOSSIPSUB_1_1_0_PROTOCOL],
        validation_mode: ValidationMode::Permissive,
        default_max_transmit_size: MAX_TRANSMIT_SIZE,
        max_transmit_sizes: HashMap::new(),
        max_publish_messages: MAX_PUBLISH_MESSAGES,
        max_control_message_size: MAX_CONTROL_MESSAGE_SIZE,
    }
}

fn fuzz_codec() -> GossipsubCodec {
    fuzz_codec_mode(ValidationMode::Permissive, HashMap::new())
}

fn fuzz_codec_mode(
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

/// Inject a negotiated inbound substream carrying `wire` bytes (optionally chunked).
pub(crate) fn inject_inbound(
    handler: &mut Handler,
    feed: ChunkFeed,
    peer_kind: PeerKind,
) {
    inject_inbound_mode(
        handler,
        feed,
        peer_kind,
        ValidationMode::Permissive,
        HashMap::new(),
        WriteFault::NONE,
    );
}

/// Like [`inject_inbound`], but with an explicit validation mode / topic maxes
/// (needed so Strict behaviour InjectWire does not decode under Permissive).
pub(crate) fn inject_inbound_mode(
    handler: &mut Handler,
    feed: ChunkFeed,
    peer_kind: PeerKind,
    mode: ValidationMode,
    topic_maxes: HashMap<TopicHash, usize>,
    write: WriteFault,
) {
    let stream = Stream::from_async_rw(feed.into_io_with_write(write));
    let framed = Framed::new(stream, fuzz_codec_mode(mode, topic_maxes));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: Either::Left((framed, peer_kind)),
            info: (),
        },
    ));
}

/// Inject a negotiated outbound substream (blackhole writer ± write faults).
pub(crate) fn inject_outbound(handler: &mut Handler, peer_kind: PeerKind, write: WriteFault) {
    let stream = Stream::from_async_rw(BlackholeIo::new(write));
    let framed = Framed::new(stream, fuzz_codec());
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedOutbound(
        FullyNegotiatedOutbound {
            protocol: (framed, peer_kind),
            info: (),
        },
    ));
}

/// Poll the handler, fulfilling outbound substream requests and collecting events.
pub(crate) fn drain_handler(
    handler: &mut Handler,
    events: &mut Vec<HandlerEvent>,
) {
    drain_handler_ex(handler, events, HandlerFault::None, WriteFault::NONE);
}

/// Like [`drain_handler`], but fulfills `OutboundSubstreamRequest` per [`HandlerFault`].
pub(crate) fn drain_handler_ex(
    handler: &mut Handler,
    events: &mut Vec<HandlerEvent>,
    fault: HandlerFault,
    write: WriteFault,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    // Write stalls return Pending without a real waker; retry so Framed can finish.
    let mut pending_retries = if write.is_stressed() {
        MAX_HANDLER_POLLS
    } else {
        0
    };
    for _ in 0..MAX_HANDLER_POLLS {
        match ConnectionHandler::poll(handler, &mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => {
                events.push(ev);
            }
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. }) => {
                match fault {
                    HandlerFault::DialUpgradeTimeout => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::Timeout,
                            },
                        ));
                    }
                    HandlerFault::DialUpgradeNegotiationFailed => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::NegotiationFailed,
                            },
                        ));
                    }
                    HandlerFault::DialUpgradeIo => {
                        handler.on_connection_event(ConnectionEvent::DialUpgradeError(
                            DialUpgradeError {
                                info: (),
                                error: StreamUpgradeError::Io(
                                    io::ErrorKind::ConnectionReset.into(),
                                ),
                            },
                        ));
                    }
                    // Do not inject Apply: gossipsub maps it to unreachable!().
                    _ => inject_outbound(handler, PeerKind::Gossipsubv1_1, write),
                }
            }
            Poll::Ready(_) => {}
            Poll::Pending => {
                if pending_retries > 0 {
                    pending_retries -= 1;
                    continue;
                }
                break;
            }
        }
    }
}

fn inject_dial_fault(handler: &mut Handler, fault: HandlerFault) {
    let error = match fault {
        HandlerFault::DialUpgradeTimeout => StreamUpgradeError::Timeout,
        HandlerFault::DialUpgradeNegotiationFailed => StreamUpgradeError::NegotiationFailed,
        HandlerFault::DialUpgradeIo => {
            StreamUpgradeError::Io(io::ErrorKind::ConnectionReset.into())
        }
        _ => return,
    };
    handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
        info: (),
        error,
    }));
}

fn flood_max_substream_attempts(handler: &mut Handler, inbound: bool) {
    for _ in 0..MAX_SUBSTREAM_ATTEMPTS {
        if inbound {
            // Repeated inbound FullyNegotiated replaces the prior inbound stream.
            let feed = ChunkFeed::new(std::iter::empty::<u8>(), 64, 0);
            feed.close();
            inject_inbound(handler, feed, PeerKind::Gossipsubv1_1);
        } else {
            // Do not inject FullyNegotiatedOutbound repeatedly — handler asserts
            // if an outbound stream already exists. DialUpgradeError is outbound
            // and still increments `outbound_substream_attempts`.
            handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
                info: (),
                error: StreamUpgradeError::Timeout,
            }));
        }
    }
}

fn write_fault_or_none(fault: HandlerFault, write: WriteFault) -> WriteFault {
    // Fault arms that never reach encode keep unlimited writes.
    match fault {
        HandlerFault::None | HandlerFault::MessageDroppedTimedOut => write,
        _ => WriteFault::NONE,
    }
}

fn timed_out_publish_rpc() -> RpcOut {
    RpcOut::Publish {
        message_id: MessageId::from(vec![0xFFu8; 8]),
        message: RawMessage {
            source: None,
            data: vec![0x41; 16],
            sequence_number: Some(1),
            topic: TopicHash::from_raw("fuzz-topic-0"),
            signature: None,
            key: None,
            validated: false,
        },
        // Zero duration is Ready on first poll under noop_waker (no wall sleep).
        timeout: Delay::new(Duration::ZERO),
    }
}

/// Standalone driver: feed wire chunks into a fresh Handler and poll.
///
/// Also optionally enqueues a Subscribe RpcOut so the encode/flush path runs.
/// [`HandlerFault`] drives DialUpgradeError / MaxSubstreamAttempts / MessageDropped.
/// [`WriteFault`] stresses outbound (and inbound duplex) encode under backpressure.
/// 
/// This function now incorporates structure-aware fuzzing and invariant checking.
pub fn fuzz_handler_io(
    wire_chunks: impl IntoIterator<Item = Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    enqueue_subscribe: bool,
    fault: HandlerFault,
    write: WriteFault,
) -> Vec<HandlerEvent> {
    let peer = fuzz_peer_id();
    let mut queue = Queue::new(8);
    let need_outbound_request = matches!(
        fault,
        HandlerFault::DialUpgradeTimeout
            | HandlerFault::DialUpgradeNegotiationFailed
            | HandlerFault::DialUpgradeIo
    );
    if matches!(fault, HandlerFault::MessageDroppedTimedOut) {
        let _ = queue.try_push(timed_out_publish_rpc());
    } else if enqueue_subscribe || need_outbound_request {
        let _ = queue.try_push(RpcOut::Subscribe {
            topic: TopicHash::from_raw("fuzz-topic-0"),
            requests_partial: false,
            supports_partial: false,
        });
    }
    let mut handler = Handler::new(peer, fuzz_protocol_config(), queue);
    let write = write_fault_or_none(fault, write);

    match fault {
        HandlerFault::MaxSubstreamAttemptsInbound => {
            flood_max_substream_attempts(&mut handler, true);
            let mut events = Vec::new();
            drain_handler_ex(&mut handler, &mut events, HandlerFault::None, WriteFault::NONE);
            return events;
        }
        HandlerFault::MaxSubstreamAttemptsOutbound => {
            flood_max_substream_attempts(&mut handler, false);
            let mut events = Vec::new();
            drain_handler_ex(&mut handler, &mut events, HandlerFault::None, WriteFault::NONE);
            return events;
        }
        HandlerFault::DialUpgradeTimeout
        | HandlerFault::DialUpgradeNegotiationFailed
        | HandlerFault::DialUpgradeIo => {
            let mut events = Vec::new();
            // Subscribe in queue → OutboundSubstreamRequest → DialUpgradeError.
            drain_handler_ex(&mut handler, &mut events, fault, WriteFault::NONE);
            // Fallback if no outbound request was emitted (queue empty edge).
            if matches!(fault, HandlerFault::DialUpgradeNegotiationFailed)
                && !events
                    .iter()
                    .any(|e| matches!(e, HandlerEvent::PeerKind(PeerKind::NotSupported)))
            {
                inject_dial_fault(&mut handler, fault);
                drain_handler_ex(&mut handler, &mut events, HandlerFault::None, WriteFault::NONE);
            }
            return events;
        }
        HandlerFault::MessageDroppedTimedOut => {
            // Need WaitingOutput: fulfill outbound, then poll pops timed-out Publish.
            inject_outbound(&mut handler, PeerKind::Gossipsubv1_1, WriteFault::NONE);
            handler.fuzz_expire_publish_timeouts();
            let mut events = Vec::new();
            drain_handler_ex(&mut handler, &mut events, HandlerFault::None, WriteFault::NONE);
            return events;
        }
        HandlerFault::None => {}
    }

    let mut bytes = Vec::new();
    for chunk in wire_chunks {
        let take = chunk.len().min(MAX_RPC_BYTES);
        bytes.extend_from_slice(&chunk[..take]);
    }
    let feed = ChunkFeed::new(bytes, chunk_cap.max(1), reset_every);
    // Standalone: close after initial bytes so framing can complete / EOF cleanly.
    feed.close();
    inject_inbound_mode(
        &mut handler,
        feed,
        PeerKind::Gossipsubv1_1,
        ValidationMode::Permissive,
        HashMap::new(),
        write,
    );

    let mut events = Vec::new();
    drain_handler_ex(&mut handler, &mut events, fault, write);
    
    // Assert protocol invariants after processing
    #[cfg(feature = "fuzzing")]
    {
        use crate::fuzz_invariants::assert_gossipsub_invariants;
        assert_gossipsub_invariants(&handler);
    }
    
    events
}

/// Drive an existing Handler: fulfill outbound requests, then poll to drain queues.
pub fn pump_handler(handler: &mut Handler) -> Vec<HandlerEvent> {
    let mut events = Vec::new();
    drain_handler(handler, &mut events);
    events
}

/// Attach a live inbound feed (Pending when empty) so Behaviour can push wire later.
#[allow(dead_code)] // Permissive convenience wrapper; Strict uses `_mode`.
pub(crate) fn attach_live_inbound(handler: &mut Handler) -> ChunkFeed {
    attach_live_inbound_mode(
        handler,
        ValidationMode::Permissive,
        HashMap::new(),
        WriteFault::NONE,
    )
}

/// Like [`attach_live_inbound`] with codec mode matching Behaviour validation.
///
/// `write` stresses duplex encode/flush on the inbound Framed (Behaviour→Handler
/// queue drain under backpressure).
pub(crate) fn attach_live_inbound_mode(
    handler: &mut Handler,
    mode: ValidationMode,
    topic_maxes: HashMap<TopicHash, usize>,
    write: WriteFault,
) -> ChunkFeed {
    let feed = ChunkFeed::new(std::iter::empty::<u8>(), 64, 0);
    let for_push = feed.clone_feed();
    inject_inbound_mode(
        handler,
        feed,
        PeerKind::Gossipsubv1_1,
        mode,
        topic_maxes,
        write,
    );
    let _ = pump_handler(handler);
    for_push
}
