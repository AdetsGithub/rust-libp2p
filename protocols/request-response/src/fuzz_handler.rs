//! ConnectionHandler helpers for request-response fuzzing (feature = `"fuzzing"`).
//!
//! Provides a simple [`pump_handler`] poll loop and [`fuzz_codec_roundtrip`] over
//! mock duplex streams.

use std::{
    io,
    task::{Context, Poll},
};

use futures::{AsyncWriteExt, task::noop_waker_ref};
use libp2p_swarm::{ConnectionHandler, ConnectionHandlerEvent};

use crate::{
    FuzzCodec, codec::Codec,
    fuzz::{fuzz_protocol_name, max_payload_len},
    handler::{Event as HandlerEvent, Handler},
};

/// Bound polls in a single driver invocation.
pub(crate) const MAX_HANDLER_POLLS: usize = 256;

/// Poll a [`Handler`] until pending or cap, collecting `NotifyBehaviour` events.
pub fn pump_handler(handler: &mut Handler<FuzzCodec>) -> Vec<HandlerEvent<FuzzCodec>> {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    let mut out = Vec::new();
    for _ in 0..MAX_HANDLER_POLLS {
        match handler.poll(&mut cx) {
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev)) => out.push(ev),
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. }) => break,
            Poll::Ready(_) => {}
            Poll::Pending => break,
        }
    }
    out
}

/// Encode request + response through [`FuzzCodec`] on a mock duplex (no handler).
pub fn fuzz_codec_roundtrip(request: &[u8], response: &[u8]) -> io::Result<()> {
    use futures::executor::block_on;
    use futures_ringbuf::Endpoint;

    let req = truncate_payload(request);
    let res = truncate_payload(response);
    let (mut a, mut b) = Endpoint::pair(64, 64);

    let mut codec = FuzzCodec::default();
    let protocol = fuzz_protocol_name();

    block_on(async {
        codec
            .write_request(&protocol, &mut a, req.clone())
            .await?;
        a.close().await?;

        let read_req = codec.read_request(&protocol, &mut b).await?;
        assert_eq!(read_req, req);

        codec.write_response(&protocol, &mut b, res.clone()).await?;
        b.close().await?;

        let read_res = codec.read_response(&protocol, &mut a).await?;
        assert_eq!(read_res, res);
        Ok::<(), io::Error>(())
    })
}

fn truncate_payload(data: &[u8]) -> Vec<u8> {
    let max = max_payload_len();
    if data.len() > max {
        data[..max].to_vec()
    } else {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip_smoke() {
        fuzz_codec_roundtrip(b"req", b"resp").expect("roundtrip");
    }
}
