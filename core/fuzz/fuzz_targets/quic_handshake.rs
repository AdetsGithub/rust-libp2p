#![no_main]

//! Fuzz target for **libp2p-quic** multiaddr / Config / TLS-over-QUIC handshake
//! + hole-punch state.
//!
//! Arms (inside `libp2p_quic::fuzz_quic`, byte0 `% 10`):
//!   0 — Multiaddr parse (`quic` / `quic-v1` + optional `/p2p`)
//!   1 — `Config::new` from seed → QuinnConfig conversion
//!   2 — `quinn_proto::PartialDecode` on raw UDP payload
//!   3..=4 — structured mutual handshake (in-memory Endpoint Pair)
//!   5 — structured + corrupt peer cert DER
//!   6 — structured + mid-handshake wire flip
//!   7 — post-handshake bi-stream R/W (bounded)
//!   8 — hole-punch mock Provider (timeout / send_to error; no real UDP I/O)
//!   9 — `HolePunchBook` register/cancel/complete races
//!
//! Dual-lane: identity binding asserts PeerId from libp2p TLS certs.
//! Optional `--features fuzzing-real-verify` keeps cross-crate parity with
//! Noise / TLS / Strict Gossipsub. No live network I/O on Pair / hole-punch arms.
//!
//! Invariants: never panics; always terminates within step budgets.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libp2p_quic::fuzz_quic(data);
});
