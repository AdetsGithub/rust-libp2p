#![no_main]

//! Combined multiaddr binary + text parsers (legacy / dual-arm target).
//! Prefer the split targets (`multiaddr_binary`, `multiaddr_text`,
//! `multiaddr_protocol_from_bytes`, `multiaddr_structured`) for undiluted coverage.

use libfuzzer_sys::fuzz_target;
use libp2p_core::multiaddr::Multiaddr;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    // --- Arm 1: binary wire-format parser ---
    if let Ok(addr) = Multiaddr::try_from(data.to_vec()) {
        common::assert_binary_roundtrip(&addr);
        // Soft text path by default (Finding #1); enable `hard_text_roundtrip` after fix.
        common::exercise_text_roundtrip(&addr);
    }

    // --- Arm 2: text-format parser ---
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(addr) = text.parse::<Multiaddr>() {
            common::assert_binary_roundtrip(&addr);
        }
    }
});
