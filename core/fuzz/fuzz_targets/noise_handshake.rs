#![no_main]

//! Fuzz target for **libp2p-noise** decode / XX handshake / transport surfaces.
//!
//! Arms (inside `libp2p_noise::fuzz_noise`, byte0 `% 8`):
//!   0 — `NoiseHandshakePayload` protobuf decode
//!   1 — u16-BE length-prefixed frame decode
//!   2 — inbound XX upgrade over blackhole mock (raw fuzz bytes)
//!   3..=4 — structured XX inbound (snow initiator peer, valid e / es / s frames)
//!   5..=6 — structured XX outbound (snow responder peer)
//!   7 — structured XX inbound + post-handshake `Output` read/write
//!
//! Dict: `dicts/noise.dict`. Seeds: `seeds/noise_handshake/`.
//! Identity `verify` is stubbed under `--cfg fuzzing` unless built with
//! `--features fuzzing-real-verify` (dual-lane CI). Structured arms honor
//! flags bit7 (flip one ciphertext byte) to warm `AuthFailed` on Lane B.
//!
//! Invariants: never panics; always terminates within a poll budget.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libp2p_noise::fuzz_noise(data);
});
