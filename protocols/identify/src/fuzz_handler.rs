//! ConnectionHandler mock-stream driver for Identify (feature = `"fuzzing"`).
//!
//! Drives [`Handler`] with [`Stream::from_async_rw`] so libFuzzer reaches:
//! - outbound `/ipfs/id/1.0.0` recv (parse Identify Info)
//! - inbound `/ipfs/id/push/1.0.0` recv (parse PushInfo + merge)
//! - inbound identify send / outbound push send (encode path)
//! - [`DialUpgradeError`] → IdentificationError

use std::{
    collections::{HashSet, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{
    AsyncRead, AsyncWrite,
    future::Either as FutEither,
    task::noop_waker_ref,
};
use libp2p_core::Multiaddr;
use libp2p_identity::{Keypair, PeerId};
use libp2p_swarm::{
    ConnectionHandler, ConnectionHandlerEvent, Stream, StreamUpgradeError,
    handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound},
};

use crate::{
    behaviour::KeyType,
    handler::{Event as HandlerEvent, Handler, InEvent},
};

/// Bound polls in a single driver invocation.
pub const MAX_HANDLER_POLLS: usize = 256;

/// Outbound write-side faults for mock [`AsyncWrite`] (identify/push encode).
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

/// Which negotiated stream role to inject with mock I/O.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamRole {
    /// Outbound identify: remote replies with an Identify message (parse path).
    #[default]
    OutboundIdentify,
    /// Inbound push: remote pushes Identify/PushInfo (parse + merge path).
    InboundPush,
    /// Inbound identify: we reply with our Info (encode/send path).
    InboundIdentify,
    /// Outbound push: we push our Info (encode/send path).
    OutboundPush,
}

/// How to fulfill [`OutboundSubstreamRequest`] from the handler.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutboundDrive {
    /// Inject a mock negotiated outbound carrying wire bytes (or blackhole for push).
    #[default]
    MockNegotiated,
    /// Inject [`DialUpgradeError`] with [`StreamUpgradeError::Timeout`].
    DialUpgradeTimeout,
    /// Inject negotiation-failed upgrade error.
    DialUpgradeNegotiationFailed,
}

/// Shared byte feed for partial / reset reads.
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
}

impl ChunkFeed {
    pub(crate) fn new(
        bytes: impl IntoIterator<Item = u8>,
        chunk_cap: usize,
        reset_every: usize,
    ) -> Self {
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

    #[allow(dead_code)] // Convenience; stressed paths use `into_io_with_write`.
    pub(crate) fn into_io(self) -> ChunkIo {
        self.into_io_with_write(WriteFault::NONE)
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
        if st.q.is_empty() {
            return if st.closed {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
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

/// Blackhole sink (reads EOF; writes honor [`WriteFault`]).
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

fn fuzz_local_key() -> Arc<KeyType> {
    let mut bytes = [0x41u8; 32];
    let kp = Keypair::ed25519_from_bytes(&mut bytes).expect("fixed ed25519 seed");
    Arc::new(KeyType::from(&kp))
}

/// Fixed remote peer used by the standalone handler driver.
pub(crate) fn fuzz_remote_peer() -> PeerId {
    let mut bytes = [0x42u8; 32];
    PeerId::from(
        Keypair::ed25519_from_bytes(&mut bytes)
            .expect("fixed remote ed25519 seed")
            .public(),
    )
}

/// Keypair matching [`fuzz_remote_peer`] (for structured Info that passes peer-id check).
#[cfg(test)]
fn fuzz_remote_keypair() -> Keypair {
    let mut bytes = [0x42u8; 32];
    Keypair::ed25519_from_bytes(&mut bytes).expect("fixed remote ed25519 seed")
}

fn fuzz_observed_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/4001"
        .parse()
        .expect("static multiaddr")
}

pub(crate) fn new_fuzz_handler(remote: PeerId) -> Handler {
    Handler::new(
        // Long interval: first poll still fires (Delay::ZERO at construction).
        Duration::from_secs(3600),
        remote,
        fuzz_local_key(),
        "fuzz/1.0.0".into(),
        "fuzz-agent/0".into(),
        fuzz_observed_addr(),
        HashSet::new(),
    )
}

pub(crate) fn inject_inbound_identify(handler: &mut Handler, write: WriteFault) {
    let stream = Stream::from_async_rw(BlackholeIo::new(write));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: FutEither::Left(stream),
            info: (),
        },
    ));
}

pub(crate) fn inject_inbound_push(handler: &mut Handler, feed: ChunkFeed, write: WriteFault) {
    let stream = Stream::from_async_rw(feed.into_io_with_write(write));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: FutEither::Right(stream),
            info: (),
        },
    ));
}

pub(crate) fn inject_outbound_identify(handler: &mut Handler, feed: ChunkFeed, write: WriteFault) {
    let stream = Stream::from_async_rw(feed.into_io_with_write(write));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedOutbound(
        FullyNegotiatedOutbound {
            protocol: FutEither::Left(stream),
            info: (),
        },
    ));
}

pub(crate) fn inject_outbound_push(handler: &mut Handler, write: WriteFault) {
    let stream = Stream::from_async_rw(BlackholeIo::new(write));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedOutbound(
        FullyNegotiatedOutbound {
            protocol: FutEither::Right(stream),
            info: (),
        },
    ));
}

/// Poll the handler, fulfilling outbound substream requests per [`OutboundDrive`].
///
/// When `fulfill_outbound_requests` is false, outbound requests are ignored so a
/// previously injected negotiated stream can finish without an empty second inject.
#[allow(dead_code)] // Convenience wrapper; stressed paths use `drain_handler_ex`.
pub(crate) fn drain_handler(
    handler: &mut Handler,
    events: &mut Vec<HandlerEvent>,
    outbound_wire: &[u8],
    outbound: OutboundDrive,
) {
    drain_handler_ex(
        handler,
        events,
        outbound_wire,
        outbound,
        true,
        WriteFault::NONE,
    );
}

pub(crate) fn drain_handler_ex(
    handler: &mut Handler,
    events: &mut Vec<HandlerEvent>,
    outbound_wire: &[u8],
    outbound: OutboundDrive,
    fulfill_outbound_requests: bool,
    write: WriteFault,
) {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    for _ in 0..MAX_HANDLER_POLLS {
        match ConnectionHandler::poll(handler, &mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => {
                events.push(ev);
            }
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol }) => {
                if fulfill_outbound_requests {
                    let is_push = matches!(protocol.upgrade(), either::Either::Right(_));
                    fulfill_outbound(handler, is_push, outbound_wire, outbound, write);
                }
                // else: drop the request; keep polling active_streams
            }
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
}

fn fulfill_outbound(
    handler: &mut Handler,
    is_push: bool,
    outbound_wire: &[u8],
    outbound: OutboundDrive,
    write: WriteFault,
) {
    match outbound {
        OutboundDrive::MockNegotiated => {
            if is_push {
                inject_outbound_push(handler, write);
            } else {
                let feed = ChunkFeed::new(outbound_wire.iter().copied(), 64, 0);
                feed.close();
                inject_outbound_identify(handler, feed, write);
            }
        }
        OutboundDrive::DialUpgradeTimeout => {
            handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
                info: (),
                error: StreamUpgradeError::Timeout,
            }));
        }
        OutboundDrive::DialUpgradeNegotiationFailed => {
            handler.on_connection_event(ConnectionEvent::DialUpgradeError(DialUpgradeError {
                info: (),
                error: StreamUpgradeError::NegotiationFailed,
            }));
        }
    }
}

/// Standalone driver: inject stream role + optional wire chunks, then poll.
pub fn fuzz_handler_io(
    wire_chunks: impl IntoIterator<Item = Vec<u8>>,
    chunk_cap: usize,
    reset_every: usize,
    role: StreamRole,
    outbound: OutboundDrive,
    trigger_push: bool,
) -> Vec<HandlerEvent> {
    let remote = fuzz_remote_peer();
    let mut handler = new_fuzz_handler(remote);

    if trigger_push {
        handler.on_behaviour_event(InEvent::Push);
    }

    let mut bytes = Vec::new();
    for chunk in wire_chunks {
        bytes.extend_from_slice(&chunk);
    }
    // Soft cap so oversized frames still exercise the codec limit path.
    if bytes.len() > 8 * 1024 {
        bytes.truncate(8 * 1024);
    }

    // Bias encode-path roles toward write_cap=1 so identify/push flush stalls warm.
    let write = match role {
        // write_cap only here — flush_stall on encode-only roles can starve
        // Identification under noop_waker; Behaviour Connect uses flush stalls.
        StreamRole::InboundIdentify | StreamRole::OutboundPush => WriteFault {
            write_cap: 1,
            stall_every: 0,
            err_every: 0,
            flush_stall_every: 0,
        },
        _ => WriteFault::NONE,
    };

    match role {
        StreamRole::OutboundIdentify => {
            match outbound {
                OutboundDrive::MockNegotiated => {
                    // Inject directly so framing/parse runs without the timer round-trip.
                    let feed = ChunkFeed::new(bytes, chunk_cap.max(1), reset_every);
                    feed.close();
                    inject_outbound_identify(&mut handler, feed, WriteFault::NONE);
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
            }
        }
        StreamRole::InboundPush => {
            let feed = ChunkFeed::new(bytes, chunk_cap.max(1), reset_every);
            feed.close();
            inject_inbound_push(&mut handler, feed, WriteFault::NONE);
        }
        StreamRole::InboundIdentify => {
            inject_inbound_identify(&mut handler, write);
        }
        StreamRole::OutboundPush => {
            handler.on_behaviour_event(InEvent::Push);
            let mut events = Vec::new();
            drain_handler_ex(
                &mut handler,
                &mut events,
                &[],
                outbound,
                true,
                write,
            );
            return events;
        }
    }

    let mut events = Vec::new();
    // Drain active_streams; do not fulfill the timer outbound (would inject empty wire).
    drain_handler_ex(
        &mut handler,
        &mut events,
        &[],
        OutboundDrive::MockNegotiated,
        false,
        WriteFault::NONE,
    );
    events
}

/// Drive an existing Handler: fulfill outbound requests, then poll.
pub fn pump_handler(handler: &mut Handler) -> Vec<HandlerEvent> {
    pump_handler_ex(handler, WriteFault::NONE)
}

/// Like [`pump_handler`] with write-side backpressure on fulfilled outbound streams.
pub(crate) fn pump_handler_ex(handler: &mut Handler, write: WriteFault) -> Vec<HandlerEvent> {
    let mut events = Vec::new();
    drain_handler_ex(
        handler,
        &mut events,
        &[],
        OutboundDrive::MockNegotiated,
        true,
        write,
    );
    events
}

/// Attach a live inbound push feed (Pending when empty) for Behaviour wire inject.
#[allow(dead_code)] // Convenience wrapper; Behaviour uses `_ex`.
pub(crate) fn attach_live_inbound_push(handler: &mut Handler) -> ChunkFeed {
    attach_live_inbound_push_ex(handler, WriteFault::NONE)
}

/// Like [`attach_live_inbound_push`] with write-side backpressure on the push duplex.
pub(crate) fn attach_live_inbound_push_ex(
    handler: &mut Handler,
    write: WriteFault,
) -> ChunkFeed {
    let feed = ChunkFeed::new(std::iter::empty::<u8>(), 64, 0);
    let for_push = feed.clone_feed();
    inject_inbound_push(handler, feed, write);
    let _ = pump_handler_ex(handler, write);
    for_push
}

#[cfg(test)]
mod tests {
    use asynchronous_codec::Encoder;
    use bytes::BytesMut;

    use super::*;
    use crate::proto;

    fn encode_info_for_remote() -> Vec<u8> {
        let kp = fuzz_remote_keypair();
        let msg = proto::Identify {
            protocol_version: Some("fuzz/1.0.0".into()),
            agent_version: Some("fuzz-agent/0".into()),
            public_key: Some(kp.public().encode_protobuf()),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/4001"
                .parse::<Multiaddr>()
                .unwrap()
                .to_vec()],
            observed_addr: Some(
                "/ip4/198.51.100.1/tcp/1234"
                    .parse::<Multiaddr>()
                    .unwrap()
                    .to_vec(),
            ),
            protocols: vec!["/ipfs/ping/1.0.0".into(), "/ipfs/id/1.0.0".into()],
            signed_peer_record: None,
        };
        let mut codec = prost_codec::Codec::<proto::Identify>::new(4096);
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).expect("encode");
        buf.to_vec()
    }

    #[test]
    fn outbound_identify_parses_matching_peer() {
        let wire = encode_info_for_remote();
        let events = fuzz_handler_io(
            vec![wire],
            64,
            0,
            StreamRole::OutboundIdentify,
            OutboundDrive::MockNegotiated,
            false,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::Identified(_))),
            "expected Identified, got {events:?}"
        );
    }

    #[test]
    fn dial_upgrade_timeout_emits_error() {
        let events = fuzz_handler_io(
            Vec::<Vec<u8>>::new(),
            64,
            0,
            StreamRole::OutboundIdentify,
            OutboundDrive::DialUpgradeTimeout,
            false,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::IdentificationError(_))),
            "expected IdentificationError, got {events:?}"
        );
    }

    #[test]
    fn inbound_identify_sends() {
        let events = fuzz_handler_io(
            Vec::<Vec<u8>>::new(),
            64,
            0,
            StreamRole::InboundIdentify,
            OutboundDrive::MockNegotiated,
            false,
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, HandlerEvent::Identification)),
            "expected Identification, got {events:?}"
        );
    }
}
