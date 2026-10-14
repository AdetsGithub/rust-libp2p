#![no_main]

//! Fuzz target for the **multistream-select** negotiation stack.
//!
//! Arms (selected by `data[0]` low bits):
//!   0 — listener negotiation (`listener_select_proto`) over interactive mock
//!   1 — dialer negotiation (`dialer_select_proto`, V1 / V1Lazy)
//!   2 — `Message::decode` on raw frame payloads (no outer length prefix)
//!   3 — `LengthDelimited` streaming frame reader
//!
//! Negotiation uses an interactive mock: remote fuzz bytes are readable first;
//! optionally (ctrl bit), local writes are looped back after remote drains so
//! half-close / echo paths see traffic. Poll budget exhaustion is a hard panic.
//!
//! Dict: `dicts/multistream.dict`. Seeds: `seeds/multistream_select_negotiation/`.
//!
//! Invariants: never panics on malformed input; always terminates within budget.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    io::{AsyncRead, AsyncWrite},
    pin_mut,
    task::noop_waker_ref,
};
use libfuzzer_sys::fuzz_target;
use multistream_select::{
    Version, dialer_select_proto, fuzz_length_delimited, fuzz_message_decode, listener_select_proto,
};

const POLL_BUDGET: usize = 100_000;

/// Interactive mock duplex:
/// 1. Drain `remote` (fuzzer-controlled peer traffic).
/// 2. If `echo`, then drain bytes previously written locally (loopback).
/// Writes always succeed immediately (discarded unless echo).
struct InteractiveMock {
    remote: VecDeque<u8>,
    echo_buf: VecDeque<u8>,
    echo: bool,
}

impl InteractiveMock {
    fn new(remote: &[u8], echo: bool) -> Self {
        Self {
            remote: remote.iter().copied().collect(),
            echo_buf: VecDeque::new(),
            echo,
        }
    }
}

impl AsyncRead for InteractiveMock {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(b) = this.remote.pop_front() {
            buf[0] = b;
            let mut n = 1;
            while n < buf.len() {
                match this.remote.pop_front() {
                    Some(x) => {
                        buf[n] = x;
                        n += 1;
                    }
                    None => break,
                }
            }
            return Poll::Ready(Ok(n));
        }
        if this.echo {
            if let Some(b) = this.echo_buf.pop_front() {
                buf[0] = b;
                let mut n = 1;
                while n < buf.len() {
                    match this.echo_buf.pop_front() {
                        Some(x) => {
                            buf[n] = x;
                            n += 1;
                        }
                        None => break,
                    }
                }
                return Poll::Ready(Ok(n));
            }
        }
        // EOF once both queues are empty.
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for InteractiveMock {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.echo {
            this.echo_buf.extend(buf.iter().copied());
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Poll a future to completion. Exhausting the budget is a hard failure —
/// MockIo is always Ready, so a Pending loop would mean a logic hang.
fn drive_to_completion<F: Future>(fut: F) {
    pin_mut!(fut);
    let mut cx = Context::from_waker(noop_waker_ref());
    for _ in 0..POLL_BUDGET {
        if fut.as_mut().poll(&mut cx).is_ready() {
            return;
        }
    }
    panic!("multistream negotiation exceeded poll budget ({POLL_BUDGET})");
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let ctrl = data[0];
    let payload = &data[1..];
    let arm = ctrl & 0b11;
    let echo = ctrl & 0b100 != 0;

    match arm {
        0 => {
            let protocols = [
                "/ipfs/id/1.0.0",
                "/libp2p/circuit/relay/0.2.0/hop",
                "/a/1.0.0",
            ];
            drive_to_completion(listener_select_proto(
                InteractiveMock::new(payload, echo),
                protocols,
            ));
        }
        1 => {
            let protocols = [
                "/ipfs/id/1.0.0",
                "/libp2p/circuit/relay/0.2.0/hop",
                "/a/1.0.0",
            ];
            let version = if ctrl & 0b1000 == 0 {
                Version::V1
            } else {
                Version::V1Lazy
            };
            drive_to_completion(dialer_select_proto(
                InteractiveMock::new(payload, echo),
                protocols,
                version,
            ));
        }
        2 => fuzz_message_decode(payload),
        _ => fuzz_length_delimited(payload),
    }
});
