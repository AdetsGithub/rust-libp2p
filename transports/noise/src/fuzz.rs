//! Noise fuzz driver (feature `fuzzing`).
//!
//! Arms (byte0 selector, biased toward structured XX):
//!   0 — protobuf [`NoiseHandshakePayload`] decode
//!   1 — u16-BE length-prefixed frame decode (wire framing)
//!   2 — inbound XX upgrade over a blackhole mock (raw fuzz bytes as remote)
//!   3..=4 — structured XX inbound (SUT responder) via snow initiator peer
//!   5..=6 — structured XX outbound (SUT initiator) via snow responder peer
//!   7 — structured XX (inbound) + post-handshake [`Output`] read/write
//!
//! Structured arms build valid Noise_XX ciphertext frames with snow so
//! `handshake.rs` finish / identity paths warm. Identity `verify` is stubbed
//! under `--cfg fuzzing` unless built with `fuzzing-real-verify` (dual-lane CI).
//! Extension fields (certhash / muxer) are fuzz-biased inside the encrypted
//! identity payload protobuf. Flag bit7 flips one ciphertext byte to warm
//! `AuthFailed` / decrypt errors on the real-verify lane.

use std::{
    collections::HashSet,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{
    Future,
    io::{AsyncRead, AsyncWrite},
    pin_mut,
    task::noop_waker_ref,
};
use libp2p_core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade};
use libp2p_identity::Keypair;
use multihash::Multihash;
use prost::Message;

use crate::{
    Config, Output,
    io::fuzz_length_prefixed,
    io::handshake::proto::{NoiseExtensions, NoiseHandshakePayload},
    protocol::{Keypair as DhKeypair, PARAMS_XX, noise_params_into_builder},
};

const POLL_BUDGET: usize = 50_000;
const PIPE_CAP: usize = 1 << 20;
const SNOW_BUF_SLACK: usize = 1024;
const SHA_256_MH: u64 = 0x12;

/// Encode a minimal handshake payload (optional identity key bytes + extensions).
pub fn encode_structured_payload(
    identity_key: &[u8],
    identity_sig: &[u8],
    with_extensions: bool,
) -> Vec<u8> {
    let pb = NoiseHandshakePayload {
        identity_key: identity_key.to_vec(),
        identity_sig: identity_sig.to_vec(),
        extensions: with_extensions.then(|| NoiseExtensions {
            webtransport_certhashes: vec![vec![0x12, 0x20]],
            stream_muxers: vec!["/yamux/1.0.0".into()],
        }),
    };
    pb.encode_to_vec()
}

/// Prefix `payload` with a big-endian u16 length (Noise wire framing).
pub fn encode_length_prefixed_frame(payload: &[u8]) -> Vec<u8> {
    let len = (payload.len().min(u16::MAX as usize)) as u16;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload[..len as usize]);
    out
}

/// Drive Noise decode / handshake / transport surfaces against attacker-controlled bytes.
///
/// Invariants: never panics; always terminates (bounded poll budget).
pub fn fuzz_noise(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // Bias toward structured XX (arms 3–7) so finish/identity/io warm.
    let arm = data[0] % 8;
    let payload = &data[1..];

    match arm {
        0 => {
            let _ = NoiseHandshakePayload::decode(payload);
        }
        1 => fuzz_length_prefixed(payload),
        2 => fuzz_inbound_upgrade_raw(payload),
        3 | 4 => fuzz_xx_structured(payload, XxRole::Inbound, false),
        5 | 6 => fuzz_xx_structured(payload, XxRole::Outbound, false),
        _ => fuzz_xx_structured(payload, XxRole::Inbound, true),
    }
}

#[derive(Clone, Copy)]
enum XxRole {
    /// SUT is responder (`upgrade_inbound`); peer is Noise initiator.
    Inbound,
    /// SUT is initiator (`upgrade_outbound`); peer is Noise responder.
    Outbound,
}

fn fuzz_inbound_upgrade_raw(data: &[u8]) {
    let identity = Keypair::generate_ed25519();
    let Ok(config) = Config::new(&identity) else {
        return;
    };
    let fut = config.upgrade_inbound(MockIo::new(data.to_vec()), "/noise");
    let _ = drive_future(fut);
}

fn fuzz_xx_structured(data: &[u8], role: XxRole, post_io: bool) {
    let flags = data.first().copied().unwrap_or(0);
    let ext_fuzz = data.get(1..).unwrap_or(&[]);
    // bit7: corrupt one ciphertext byte after snow encrypt (AuthFailed / decrypt).
    let corrupt_cipher = flags & 0x80 != 0;

    let (mut peer_io, sut_io) = futures_ringbuf::Endpoint::pair(PIPE_CAP, PIPE_CAP);

    // Deterministic seeds for corpus-stable minimization (distinct SUT vs peer).
    let mut sut_seed = [0x4Eu8; 32]; // 'N'
    sut_seed[31] = flags;
    let Ok(sut_id) = Keypair::ed25519_from_bytes(&mut sut_seed) else {
        return;
    };
    let Ok(mut sut_cfg) = Config::new(&sut_id) else {
        return;
    };

    let expected_certhash = stable_certhash(b"fuzz-wt-1");
    // bit0: SUT cares about / reports WebTransport certhashes
    if flags & 1 != 0 {
        sut_cfg = sut_cfg.with_webtransport_certhashes(HashSet::from([expected_certhash]));
    }

    let mut peer_seed = [0x50u8; 32]; // 'P'
    peer_seed[31] = flags.wrapping_add(1);
    let Ok(peer_id) = Keypair::ed25519_from_bytes(&mut peer_seed) else {
        return;
    };
    let peer_dh = DhKeypair::new();
    let Ok(peer_auth) = peer_dh.clone().into_authentic(&peer_id) else {
        return;
    };
    let Ok(builder) = noise_params_into_builder(PARAMS_XX.clone(), &[], peer_dh.secret(), None)
    else {
        return;
    };

    let mut cx = Context::from_waker(noop_waker_ref());
    let mut unread = Vec::new();

    match role {
        XxRole::Inbound => {
            let Ok(mut session) = builder.build_initiator() else {
                return;
            };
            let sut_fut = sut_cfg.upgrade_inbound(sut_io, "/noise");
            pin_mut!(sut_fut);

            // XX msg1: e (+ empty payload)
            let Ok(msg1) = snow_hs_write_frame(&mut session, &[]) else {
                return;
            };
            if write_all(&mut peer_io, &msg1, &mut cx).is_err() {
                return;
            }

            // SUT → msg2; peer consumes it
            let pump = pump_until_frame(&mut sut_fut, &mut peer_io, &mut unread, &mut cx);
            let Some(msg2) = pump.frame else {
                return;
            };
            if snow_hs_read_frame(&mut session, &msg2).is_err() {
                return;
            }
            // Responder should still be waiting for msg3.
            if pump.done.is_some() {
                return;
            }

            // XX msg3: s, se (+ identity payload; extensions from fuzz)
            let payload_pb = build_peer_identity_payload(
                &peer_id,
                &peer_auth.identity.signature,
                ext_fuzz,
                flags,
                Some(expected_certhash),
            );
            let Ok(mut msg3) = snow_hs_write_frame(&mut session, &payload_pb) else {
                return;
            };
            maybe_corrupt_frame(&mut msg3, corrupt_cipher, flags);
            if write_all(&mut peer_io, &msg3, &mut cx).is_err() {
                return;
            }

            let Some(result) = drive_pinned(&mut sut_fut, &mut cx) else {
                return;
            };
            maybe_post_io(
                post_io,
                result,
                session,
                &mut peer_io,
                &mut unread,
                ext_fuzz,
                &mut cx,
            );
        }
        XxRole::Outbound => {
            let Ok(mut session) = builder.build_responder() else {
                return;
            };
            let sut_fut = sut_cfg.upgrade_outbound(sut_io, "/noise");
            pin_mut!(sut_fut);

            // SUT → msg1
            let pump = pump_until_frame(&mut sut_fut, &mut peer_io, &mut unread, &mut cx);
            let Some(msg1) = pump.frame else {
                return;
            };
            if snow_hs_read_frame(&mut session, &msg1).is_err() {
                return;
            }
            if pump.done.is_some() {
                return;
            }

            // Peer → msg2 with identity (+ optional certhash match/mismatch)
            let include_expected = flags & 2 == 0; // bit1 clear → include expected certhash
            let payload_pb = build_peer_identity_payload(
                &peer_id,
                &peer_auth.identity.signature,
                ext_fuzz,
                flags,
                include_expected.then_some(expected_certhash),
            );
            let Ok(mut msg2) = snow_hs_write_frame(&mut session, &payload_pb) else {
                return;
            };
            maybe_corrupt_frame(&mut msg2, corrupt_cipher, flags);
            if write_all(&mut peer_io, &msg2, &mut cx).is_err() {
                return;
            }

            // SUT → msg3 (often completes the upgrade in the same poll as the write)
            let pump = pump_until_frame(&mut sut_fut, &mut peer_io, &mut unread, &mut cx);
            let Some(msg3) = pump.frame else {
                return;
            };
            if snow_hs_read_frame(&mut session, &msg3).is_err() {
                return;
            }
            let result = match pump.done {
                Some(r) => r,
                None => match drive_pinned(&mut sut_fut, &mut cx) {
                    Some(r) => r,
                    None => return,
                },
            };
            maybe_post_io(
                post_io,
                result,
                session,
                &mut peer_io,
                &mut unread,
                ext_fuzz,
                &mut cx,
            );
        }
    }
}

fn maybe_post_io<T>(
    post_io: bool,
    result: Result<(libp2p_identity::PeerId, Output<T>), crate::Error>,
    session: snow::HandshakeState,
    peer_io: &mut futures_ringbuf::Endpoint,
    unread: &mut Vec<u8>,
    ext_fuzz: &[u8],
    cx: &mut Context<'_>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if !post_io {
        return;
    }
    let Ok((_peer, output)) = result else {
        return;
    };
    let Ok(transport) = session.into_transport_mode() else {
        return;
    };
    drive_post_handshake(output, peer_io, unread, transport, ext_fuzz, cx);
}

fn drive_post_handshake<T>(
    mut output: Output<T>,
    peer_io: &mut futures_ringbuf::Endpoint,
    unread: &mut Vec<u8>,
    mut transport: snow::TransportState,
    data: &[u8],
    cx: &mut Context<'_>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Peer → SUT: encrypt a slice of fuzz bytes as one transport frame.
    let plain = &data[..data.len().min(1024)];
    if let Ok(frame) = snow_ts_write_frame(&mut transport, plain) {
        let _ = write_all(peer_io, &frame, cx);
        let mut buf = vec![0u8; plain.len().saturating_add(64)];
        let _ = poll_read_some(&mut output, &mut buf, cx);
    }

    // SUT → peer: write fuzz bytes through Output, then decrypt on peer.
    let to_send = &data[..data.len().min(512)];
    if !to_send.is_empty() {
        let _ = poll_write_all(&mut output, to_send, cx);
        let _ = poll_flush_io(&mut output, cx);
        for _ in 0..1024 {
            fill_unread(peer_io, unread, cx);
            if let Some(frame) = take_frame(unread) {
                let _ = snow_ts_read_frame(&mut transport, &frame);
                break;
            }
        }
    }
}

fn build_peer_identity_payload(
    id: &Keypair,
    signature: &[u8],
    ext_fuzz: &[u8],
    flags: u8,
    preferred_certhash: Option<Multihash<64>>,
) -> Vec<u8> {
    let mut pb = NoiseHandshakePayload {
        identity_key: id.public().encode_protobuf(),
        identity_sig: signature.to_vec(),
        extensions: None,
    };

    // bit2: include extensions; bit3: prefer muxer strings; else certhashes
    if flags & 4 != 0 || !ext_fuzz.is_empty() {
        let mut ext = NoiseExtensions::default();
        if flags & 8 != 0 {
            let name = if ext_fuzz.is_empty() {
                "/yamux/1.0.0".to_string()
            } else {
                String::from_utf8_lossy(&ext_fuzz[..ext_fuzz.len().min(48)]).into_owned()
            };
            ext.stream_muxers.push(name);
            if let Some(h) = preferred_certhash {
                ext.webtransport_certhashes.push(h.to_bytes());
            }
        } else if let Some(h) = preferred_certhash {
            ext.webtransport_certhashes.push(h.to_bytes());
            // Also append a fuzz-derived / garbage certhash for decode filtering.
            if ext_fuzz.len() >= 4 {
                ext.webtransport_certhashes
                    .push(ext_fuzz[..ext_fuzz.len().min(40)].to_vec());
            }
        } else if !ext_fuzz.is_empty() {
            ext.webtransport_certhashes
                .push(ext_fuzz[..ext_fuzz.len().min(40)].to_vec());
            ext.stream_muxers.push("/yamux/1.0.0".into());
        }
        pb.extensions = Some(ext);
    }

    pb.encode_to_vec()
}

fn stable_certhash(seed: &[u8]) -> Multihash<64> {
    Multihash::wrap(SHA_256_MH, seed).expect("short digest fits Multihash<64>")
}

fn maybe_corrupt_frame(frame: &mut Vec<u8>, corrupt: bool, flags: u8) {
    if !corrupt || frame.is_empty() {
        return;
    }
    // Flip a payload byte (skip u16 length prefix when present).
    let len = frame.len();
    let start = if len > 2 { 2 } else { 0 };
    let idx = start + (flags as usize % (len - start).max(1));
    let idx = idx.min(len - 1);
    frame[idx] ^= 0xFF;
}

fn snow_hs_write_frame(
    session: &mut snow::HandshakeState,
    payload: &[u8],
) -> Result<Vec<u8>, snow::Error> {
    let mut buf = vec![0u8; payload.len() + SNOW_BUF_SLACK];
    let n = session.write_message(payload, &mut buf)?;
    Ok(length_prefix(&buf[..n]))
}

fn snow_hs_read_frame(
    session: &mut snow::HandshakeState,
    frame: &[u8],
) -> Result<Vec<u8>, snow::Error> {
    let cipher = strip_length_prefix(frame).ok_or(snow::Error::Input)?;
    let mut out = vec![0u8; cipher.len()];
    let n = session.read_message(cipher, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn snow_ts_write_frame(
    session: &mut snow::TransportState,
    payload: &[u8],
) -> Result<Vec<u8>, snow::Error> {
    let mut buf = vec![0u8; payload.len() + SNOW_BUF_SLACK];
    let n = session.write_message(payload, &mut buf)?;
    Ok(length_prefix(&buf[..n]))
}

fn snow_ts_read_frame(
    session: &mut snow::TransportState,
    frame: &[u8],
) -> Result<Vec<u8>, snow::Error> {
    let cipher = strip_length_prefix(frame).ok_or(snow::Error::Input)?;
    let mut out = vec![0u8; cipher.len()];
    let n = session.read_message(cipher, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn length_prefix(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn strip_length_prefix(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    if frame.len() < 2 + len {
        return None;
    }
    Some(&frame[2..2 + len])
}

fn write_all(
    io: &mut futures_ringbuf::Endpoint,
    data: &[u8],
    cx: &mut Context<'_>,
) -> Result<(), ()> {
    let mut off = 0;
    for _ in 0..POLL_BUDGET {
        if off >= data.len() {
            return match Pin::new(&mut *io).poll_flush(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => Ok(()),
                Poll::Ready(Err(_)) => Err(()),
            };
        }
        match Pin::new(&mut *io).poll_write(cx, &data[off..]) {
            Poll::Ready(Ok(0)) => return Err(()),
            Poll::Ready(Ok(n)) => off += n,
            Poll::Ready(Err(_)) => return Err(()),
            Poll::Pending => return Err(()), // large PIPE_CAP should avoid this
        }
    }
    Err(())
}

struct PumpResult<O> {
    frame: Option<Vec<u8>>,
    /// Set when the SUT future completed (do not poll it again).
    done: Option<O>,
}

/// Poll `sut` until a full length-prefixed frame is readable on `peer_io`, or `sut` completes.
fn pump_until_frame<F>(
    sut: &mut Pin<&mut F>,
    peer_io: &mut futures_ringbuf::Endpoint,
    unread: &mut Vec<u8>,
    cx: &mut Context<'_>,
) -> PumpResult<F::Output>
where
    F: Future,
{
    for _ in 0..POLL_BUDGET {
        fill_unread(peer_io, unread, cx);
        if let Some(frame) = take_frame(unread) {
            return PumpResult {
                frame: Some(frame),
                done: None,
            };
        }
        match sut.as_mut().poll(cx) {
            Poll::Ready(out) => {
                fill_unread(peer_io, unread, cx);
                return PumpResult {
                    frame: take_frame(unread),
                    done: Some(out),
                };
            }
            Poll::Pending => continue,
        }
    }
    PumpResult {
        frame: None,
        done: None,
    }
}

fn fill_unread(
    io: &mut futures_ringbuf::Endpoint,
    unread: &mut Vec<u8>,
    cx: &mut Context<'_>,
) {
    let mut tmp = [0u8; 8192];
    for _ in 0..64 {
        match Pin::new(&mut *io).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) | Poll::Pending => return,
            Poll::Ready(Ok(n)) => unread.extend_from_slice(&tmp[..n]),
        }
    }
}

fn take_frame(unread: &mut Vec<u8>) -> Option<Vec<u8>> {
    if unread.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([unread[0], unread[1]]) as usize;
    if unread.len() < 2 + len {
        return None;
    }
    Some(unread.drain(..2 + len).collect())
}

fn drive_future<F: Future>(fut: F) -> Option<F::Output> {
    pin_mut!(fut);
    let mut cx = Context::from_waker(noop_waker_ref());
    drive_pinned(&mut fut, &mut cx)
}

fn drive_pinned<F: Future>(fut: &mut Pin<&mut F>, cx: &mut Context<'_>) -> Option<F::Output> {
    for _ in 0..POLL_BUDGET {
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Some(out);
        }
    }
    panic!("noise future exceeded poll budget ({POLL_BUDGET})");
}

fn poll_read_some<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut [u8],
    cx: &mut Context<'_>,
) -> usize {
    for _ in 0..1024 {
        match Pin::new(&mut *io).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => return n,
            Poll::Ready(Err(_)) => return 0,
            Poll::Pending => continue,
        }
    }
    0
}

fn poll_write_all<W: AsyncWrite + Unpin>(
    io: &mut W,
    data: &[u8],
    cx: &mut Context<'_>,
) -> Result<(), ()> {
    let mut off = 0;
    for _ in 0..POLL_BUDGET {
        if off >= data.len() {
            return Ok(());
        }
        match Pin::new(&mut *io).poll_write(cx, &data[off..]) {
            Poll::Ready(Ok(0)) => return Err(()),
            Poll::Ready(Ok(n)) => off += n,
            Poll::Ready(Err(_)) => return Err(()),
            Poll::Pending => continue,
        }
    }
    Err(())
}

fn poll_flush_io<W: AsyncWrite + Unpin>(io: &mut W, cx: &mut Context<'_>) {
    for _ in 0..1024 {
        match Pin::new(&mut *io).poll_flush(cx) {
            Poll::Ready(_) => return,
            Poll::Pending => continue,
        }
    }
}

struct MockIo {
    data: Vec<u8>,
    pos: usize,
}

impl MockIo {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl AsyncRead for MockIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let remaining = &this.data[this.pos..];
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        this.pos += n;
        Poll::Ready(Ok(n)) // 0 → EOF
    }
}

impl AsyncWrite for MockIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_xx_inbound_and_outbound_smoke() {
        // flags=0, empty ext — should complete without panic.
        fuzz_xx_structured(&[], XxRole::Inbound, false);
        fuzz_xx_structured(&[], XxRole::Outbound, false);
        fuzz_xx_structured(&[0x05, 0x01, 0x02, 0x03], XxRole::Inbound, true);
        // Arm selector path
        fuzz_noise(&[3]); // inbound structured
        fuzz_noise(&[5]); // outbound structured
        fuzz_noise(&[7, 0x04, b'x', b'y']); // post-io
    }
}
