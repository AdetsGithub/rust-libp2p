//! TLS fuzz driver (feature `fuzzing`).
//!
//! Arms (byte0 selector, biased toward structured mutual handshake):
//!   0 — [`certificate::parse`] on fuzz bytes
//!   1 — [`certificate::generate`] + parse roundtrip (deterministic ed25519 seed)
//!   2 — inbound upgrade raw ( [`Config::new`] + `upgrade_inbound` on mock I/O)
//!   3..=4 — structured mutual TLS over `futures_ringbuf` (inbound server + outbound client)
//!   5..=6 — structured + corrupt (flip peer cert DER byte / mid-handshake wire flip)
//!   7 — generate cert, mutate extension/signature region, parse (expect `Err`)
//!
//! Structured arms complete valid libp2p TLS 1.3 handshakes and assert remote
//! [`PeerId`] matches the peer identity public key (identity binding).
//! TLS uses [`verifier::Libp2pCertificateVerifier`] for cert checks; libp2p-identity
//! `verify` is only relevant when identity keys are exercised elsewhere — dual-lane CI
//! may still pass `--features fuzzing-real-verify` on the fuzz crate for other targets.

use std::{
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
use libp2p_identity::{Keypair, PeerId};
use rustls::pki_types::CertificateDer;

use crate::{certificate, upgrade::Config};

const POLL_BUDGET: usize = 50_000;
const PIPE_CAP: usize = 1 << 20;
const TLS_INFO: &str = "/tls/1.0.0";

/// Drive TLS certificate parsing, handshake upgrade, and identity-binding paths.
///
/// Invariants: never panics; always terminates (bounded poll budget).
pub fn fuzz_tls(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let arm = data[0] % 8;
    let payload = &data[1..];

    match arm {
        0 => fuzz_parse_raw(payload),
        1 => fuzz_generate_parse_roundtrip(payload),
        2 => fuzz_inbound_upgrade_raw(payload),
        3 | 4 => fuzz_mutual_structured(payload, CorruptMode::None),
        5 => fuzz_mutual_structured(payload, CorruptMode::CertDer),
        6 => fuzz_mutual_structured(payload, CorruptMode::MidWire),
        _ => fuzz_mutated_cert_parse(payload),
    }
}

fn fuzz_parse_raw(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let cert = CertificateDer::from(data.to_vec());
    let _ = certificate::parse(&cert);
}

fn fuzz_generate_parse_roundtrip(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let mut seed = [0x54u8; 32]; // 'T'
    seed[31] = flags;
    let Ok(identity) = Keypair::ed25519_from_bytes(&mut seed) else {
        return;
    };
    let Ok((cert, _key)) = certificate::generate(&identity) else {
        return;
    };
    let _ = certificate::parse(&cert);
}

fn fuzz_inbound_upgrade_raw(data: &[u8]) {
    let identity = Keypair::generate_ed25519();
    let Ok(config) = Config::new(&identity) else {
        return;
    };
    let fut = config.upgrade_inbound(MockIo::new(data.to_vec()), TLS_INFO);
    let _ = drive_future(fut);
}

#[derive(Clone, Copy)]
enum CorruptMode {
    None,
    /// Flip one byte in the peer's certificate DER before the handshake.
    CertDer,
    /// Flip one byte on the wire after some handshake progress.
    MidWire,
}

fn fuzz_mutual_structured(data: &[u8], corrupt: CorruptMode) {
    let flags = data.first().copied().unwrap_or(0);
    let ext_fuzz = data.get(1..).unwrap_or(&[]);

    let mut server_seed = [0x53u8; 32]; // 'S'
    server_seed[31] = flags;
    let Ok(server_id) = Keypair::ed25519_from_bytes(&mut server_seed) else {
        return;
    };

    let mut client_seed = [0x43u8; 32]; // 'C'
    client_seed[31] = flags.wrapping_add(1);
    let Ok(client_id) = Keypair::ed25519_from_bytes(&mut client_seed) else {
        return;
    };

    let expected_server = server_id.public().to_peer_id();
    let expected_client = client_id.public().to_peer_id();

    let Ok(server_cfg) = config_for_identity(&server_id, false, flags, ext_fuzz) else {
        return;
    };
    let corrupt_client = matches!(corrupt, CorruptMode::CertDer) && flags & 1 == 0;
    let corrupt_server = matches!(corrupt, CorruptMode::CertDer) && flags & 1 != 0;
    let Ok(client_cfg) = config_for_identity(&client_id, corrupt_client, flags.wrapping_add(2), ext_fuzz)
    else {
        return;
    };
    let server_cfg = if corrupt_server {
        let Ok(cfg) = config_for_identity(&server_id, true, flags.wrapping_add(3), ext_fuzz) else {
            return;
        };
        cfg
    } else {
        server_cfg
    };

    let (server_io, client_io) = futures_ringbuf::Endpoint::pair(PIPE_CAP, PIPE_CAP);
    let server_fut = server_cfg.upgrade_inbound(server_io, TLS_INFO);
    let flip_idx = ext_fuzz.first().copied().unwrap_or(flags) as usize;
    let client_io = if matches!(corrupt, CorruptMode::MidWire) {
        MidFlipIo::new(client_io, POLL_BUDGET / 8 + (flip_idx % (POLL_BUDGET / 4)), flip_idx)
    } else {
        MidFlipIo::passthrough(client_io)
    };
    let client_fut = client_cfg.upgrade_outbound(client_io, TLS_INFO);

    match drive_mutual(server_fut, client_fut) {
        MutualOutcome::BothOk {
            inbound_peer,
            outbound_peer,
        } => {
            assert_eq!(inbound_peer, expected_client);
            assert_eq!(outbound_peer, expected_server);
        }
        MutualOutcome::Partial | MutualOutcome::Budget => {}
    }
}

fn config_for_identity(
    identity: &Keypair,
    corrupt_cert: bool,
    salt: u8,
    ext_fuzz: &[u8],
) -> Result<Config, certificate::GenError> {
    if !corrupt_cert {
        return Config::new(identity);
    }
    let (cert, private_key) = certificate::generate(identity)?;
    let mut der = cert.as_ref().to_vec();
    flip_der_byte(&mut der, salt, ext_fuzz);
    Config::from_cert_key(identity, CertificateDer::from(der), private_key)
}

fn flip_der_byte(der: &mut [u8], salt: u8, ext_fuzz: &[u8]) {
    if der.is_empty() {
        return;
    }
    // Bias toward extension/signature tail when possible.
    let base = der.len() / 3;
    let span = (der.len() - base).max(1);
    let idx = base + (salt as usize + ext_fuzz.len()) % span;
    let idx = idx.min(der.len() - 1);
    der[idx] ^= 0xFF;
}

fn fuzz_mutated_cert_parse(data: &[u8]) {
    let flags = data.first().copied().unwrap_or(0);
    let ext_fuzz = data.get(1..).unwrap_or(&[]);
    let mut seed = [0x4Du8; 32]; // 'M'
    seed[31] = flags;
    let Ok(identity) = Keypair::ed25519_from_bytes(&mut seed) else {
        return;
    };
    let Ok((cert, _key)) = certificate::generate(&identity) else {
        return;
    };
    let mut der = cert.as_ref().to_vec();
    flip_der_byte(&mut der, flags.wrapping_add(0xA5), ext_fuzz);
    let _ = certificate::parse(&CertificateDer::from(der));
}

enum MutualOutcome {
    BothOk {
        inbound_peer: PeerId,
        outbound_peer: PeerId,
    },
    Partial,
    Budget,
}

fn drive_mutual<Si, Ci>(server_fut: Si, client_fut: Ci) -> MutualOutcome
where
    Si: Future<Output = Result<(PeerId, crate::TlsStream<futures_ringbuf::Endpoint>), crate::UpgradeError>>,
    Ci: Future<Output = Result<(PeerId, crate::TlsStream<MidFlipIo>), crate::UpgradeError>>,
{
    pin_mut!(server_fut, client_fut);
    let mut cx = Context::from_waker(noop_waker_ref());
    let mut server_done = None;
    let mut client_done = None;

    for _ in 0..POLL_BUDGET {
        if server_done.is_some() && client_done.is_some() {
            break;
        }
        if server_done.is_none() {
            if let Poll::Ready(out) = server_fut.as_mut().poll(&mut cx) {
                server_done = Some(out);
            }
        }
        if client_done.is_none() {
            if let Poll::Ready(out) = client_fut.as_mut().poll(&mut cx) {
                client_done = Some(out);
            }
        }
    }

    match (server_done, client_done) {
        (Some(Ok((inbound_peer, _))), Some(Ok((outbound_peer, _)))) => MutualOutcome::BothOk {
            inbound_peer,
            outbound_peer,
        },
        (None, None) => MutualOutcome::Budget,
        _ => MutualOutcome::Partial,
    }
}

fn drive_future<F: Future>(fut: F) -> Option<F::Output> {
    pin_mut!(fut);
    let mut cx = Context::from_waker(noop_waker_ref());
    for _ in 0..POLL_BUDGET {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return Some(out);
        }
    }
    None
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
        Poll::Ready(Ok(n))
    }
}

enum MidFlipIo {
    Plain(futures_ringbuf::Endpoint),
    Flip {
        inner: futures_ringbuf::Endpoint,
        ops: usize,
        threshold: usize,
        flip_idx: usize,
    },
}

impl MidFlipIo {
    fn passthrough(inner: futures_ringbuf::Endpoint) -> Self {
        Self::Plain(inner)
    }

    fn new(inner: futures_ringbuf::Endpoint, threshold: usize, flip_idx: usize) -> Self {
        Self::Flip {
            inner,
            ops: 0,
            threshold,
            flip_idx,
        }
    }

    fn maybe_flip_write(buf: &mut [u8], flip_idx: usize) {
        if buf.is_empty() {
            return;
        }
        let idx = flip_idx % buf.len();
        buf[idx] ^= 0xFF;
    }
}

impl AsyncRead for MidFlipIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MidFlipIo::Plain(inner) => Pin::new(inner).poll_read(cx, buf),
            MidFlipIo::Flip {
                inner,
                ops,
                threshold,
                flip_idx,
            } => {
                let poll = Pin::new(inner).poll_read(cx, buf);
                if let Poll::Ready(Ok(n)) = &poll {
                    if *n > 0 {
                        *ops += 1;
                        if *ops == *threshold {
                            let end = (*n).min(buf.len());
                            Self::maybe_flip_write(&mut buf[..end], *flip_idx);
                        }
                    }
                }
                poll
            }
        }
    }
}

impl AsyncWrite for MidFlipIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().get_mut() {
            MidFlipIo::Plain(inner) => Pin::new(inner).poll_write(cx, buf),
            MidFlipIo::Flip {
                inner,
                ops,
                threshold,
                flip_idx,
            } => {
                let mut tmp = buf.to_vec();
                *ops += 1;
                if *ops == *threshold {
                    Self::maybe_flip_write(&mut tmp, *flip_idx);
                }
                Pin::new(inner).poll_write(cx, &tmp)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MidFlipIo::Plain(inner) => Pin::new(inner).poll_flush(cx),
            MidFlipIo::Flip { inner, .. } => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().get_mut() {
            MidFlipIo::Plain(inner) => Pin::new(inner).poll_close(cx),
            MidFlipIo::Flip { inner, .. } => Pin::new(inner).poll_close(cx),
        }
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
    fn structured_mutual_tls_smoke() {
        fuzz_mutual_structured(&[], CorruptMode::None);
        fuzz_mutual_structured(&[0x02, 0x01, 0x02], CorruptMode::None);
        fuzz_tls(&[3]);
        fuzz_tls(&[4, 0x00]);
        fuzz_tls(&[1, 0x05]);
        fuzz_tls(&[7, 0x11, 0x22]);
    }
}
