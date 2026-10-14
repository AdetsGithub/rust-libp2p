#![no_main]

//! Fuzz target for **libp2p-tls** certificate parsing + TLS 1.3 upgrade.
//!
//! Arms (inside `libp2p_tls::fuzz_tls`, byte0 `% 8`):
//!   0 — `certificate::parse` on raw fuzz bytes
//!   1 — generate + parse roundtrip (deterministic ed25519 seed)
//!   2 — inbound upgrade over blackhole mock (raw fuzz bytes)
//!   3..=4 — structured mutual TLS (ringbuf server inbound + client outbound)
//!   5..=6 — structured + corrupt cert DER / mid-handshake wire flip
//!   7 — generate, mutate cert bytes, parse (expect `Err`)
//!
//! Dual-lane CI: TLS cert verification always runs; optional
//! `--features fuzzing-real-verify` keeps identity `PublicKey::verify` real
//! for cross-crate parity (Noise / Strict Gossipsub). Bias arms 5–6 for
//! cert-reject / mid-handshake abort density. Swarm compose: TLS is ~⅛ of
//! `swarm_orchestrator` meshes (see `COVERAGE-tls_handshake.md`).
//!
//! Invariants: never panics; always terminates within a poll budget.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libp2p_tls::fuzz_tls(data);
});
