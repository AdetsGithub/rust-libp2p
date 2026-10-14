//! ConnectionHandler / codec helpers for relay (feature = `"fuzzing"`).
//!
//! Decodes length-delimited Hop / Stop frames and provides mock [`Stream`] I/O
//! for inbound hop negotiation, including write-side backpressure / flush stalls.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use asynchronous_codec::Decoder;
use bytes::BytesMut;
use futures::{
    future::Either as FutEither,
    AsyncRead, AsyncWrite,
    task::noop_waker_ref,
};
use libp2p_swarm::{
    ConnectionHandler, ConnectionHandlerEvent, Stream,
    handler::{ConnectionEvent, FullyNegotiatedInbound},
};

use crate::{
    behaviour::handler::{self, Handler},
    proto,
    protocol::MAX_MESSAGE_SIZE,
};

pub const MAX_HANDLER_POLLS: usize = 256;

type HopCodec = prost_codec::Codec<proto::HopMessage>;
type StopCodec = prost_codec::Codec<proto::StopMessage>;

/// Outbound write-side faults for mock [`AsyncWrite`] (status / reservation encode).
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

/// Shared byte feed for partial reads into a mock inbound hop stream.
#[derive(Clone)]
pub struct ChunkFeed {
    inner: Arc<Mutex<ChunkState>>,
}

struct ChunkState {
    q: VecDeque<u8>,
    chunk_cap: usize,
    closed: bool,
}

impl ChunkFeed {
    pub fn new(bytes: impl IntoIterator<Item = u8>, chunk_cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChunkState {
                q: bytes.into_iter().collect(),
                chunk_cap: chunk_cap.max(1),
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
}

pub struct ChunkIo {
    feed: ChunkFeed,
    write: WriteCtrl,
}

impl AsyncRead for ChunkIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.feed.inner.lock().expect("chunk feed");
        if st.q.is_empty() {
            return if st.closed {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending
            };
        }
        let n = buf.len().min(st.chunk_cap).min(st.q.len());
        for (d, s) in buf.iter_mut().zip(st.q.drain(..n)) {
            *d = s;
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for ChunkIo {
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

/// Blackhole write side (honors [`WriteFault`]).
pub(crate) struct BlackholeIo {
    write: WriteCtrl,
}

impl BlackholeIo {
    pub(crate) fn new(write: WriteFault) -> Self {
        Self {
            write: WriteCtrl::new(write),
        }
    }
}

impl AsyncRead for BlackholeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for BlackholeIo {
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

pub(crate) struct RW<R, W>(pub R, pub W);

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for RW<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for RW<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.1).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.1).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.1).poll_close(cx)
    }
}

/// Decode one length-delimited [`proto::HopMessage`] frame.
pub fn decode_hop_wire(wire: &[u8]) -> Option<proto::HopMessage> {
    let mut codec = HopCodec::new(MAX_MESSAGE_SIZE);
    let mut buf = BytesMut::from(wire);
    codec.decode(&mut buf).ok().flatten()
}

/// Decode one length-delimited [`proto::StopMessage`] frame.
pub fn decode_stop_wire(wire: &[u8]) -> Option<proto::StopMessage> {
    let mut codec = StopCodec::new(MAX_MESSAGE_SIZE);
    let mut buf = BytesMut::from(wire);
    codec.decode(&mut buf).ok().flatten()
}

/// Inject a fully negotiated inbound hop substream carrying `wire` bytes.
pub fn inject_inbound_hop(handler: &mut Handler, wire: Vec<u8>) {
    inject_inbound_hop_ex(handler, wire, WriteFault::NONE);
}

/// Like [`inject_inbound_hop`] with write-side backpressure / flush stalls on
/// the hop duplex (status / reservation replies).
pub fn inject_inbound_hop_ex(handler: &mut Handler, wire: Vec<u8>, write: WriteFault) {
    let feed = ChunkFeed::new(wire, 64);
    feed.close();
    let stream = Stream::from_async_rw(RW(feed.into_io(), BlackholeIo::new(write)));
    handler.on_connection_event(ConnectionEvent::FullyNegotiatedInbound(
        FullyNegotiatedInbound {
            protocol: FutEither::Left(stream),
            info: (),
        },
    ));
}

/// Poll the relay [`Handler`] and collect behaviour-bound events.
pub fn pump_handler(handler: &mut Handler) -> Vec<handler::Event> {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    let mut out = Vec::new();
    for _ in 0..MAX_HANDLER_POLLS {
        match handler.poll(&mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => out.push(ev),
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::{StructuredHopKind, encode_structured_hop_wire};
    use futures::task::noop_waker_ref;
    use std::task::Context;

    #[test]
    fn decode_structured_reserve_wire() {
        let wire = encode_structured_hop_wire(StructuredHopKind::Reserve, 0);
        let msg = decode_hop_wire(&wire).expect("decode hop");
        assert_eq!(msg.r#type, proto::HopMessageType::Reserve as i32);
    }

    #[test]
    fn write_fault_partial_and_flush_stall() {
        let mut io = BlackholeIo::new(WriteFault {
            write_cap: 1,
            stall_every: 0,
            err_every: 0,
            flush_stall_every: 1,
        });
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        match Pin::new(&mut io).poll_write(&mut cx, &[0xAA, 0xBB]) {
            Poll::Ready(Ok(1)) => {}
            other => panic!("expected partial write, got {other:?}"),
        }
        match Pin::new(&mut io).poll_flush(&mut cx) {
            Poll::Pending => {}
            other => panic!("expected flush Pending, got {other:?}"),
        }
        match Pin::new(&mut io).poll_flush(&mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected flush Ready after stall, got {other:?}"),
        }
    }
}
