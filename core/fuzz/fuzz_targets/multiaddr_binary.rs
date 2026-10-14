#![no_main]

//! Binary-only multiaddr wire parser. Undiluted coverage of `TryFrom<Vec<u8>>`
//! without the text arm competing for the same corpus.

use libfuzzer_sys::fuzz_target;
use libp2p_core::multiaddr::Multiaddr;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if let Ok(addr) = Multiaddr::try_from(data.to_vec()) {
        common::assert_binary_roundtrip(&addr);
        // Keep soft text exercise for Display coverage without asserting.
        common::exercise_text_roundtrip(&addr);
    }
});
