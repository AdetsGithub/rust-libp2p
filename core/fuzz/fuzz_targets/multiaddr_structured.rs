#![no_main]

//! Structured multiaddr wire assembly: co-generate protocol codes + payloads
//! instead of hoping bit-flips invent varints and magic codes.
//!
//! Dictionaries do not bias `Arbitrary` integer fields (entropy stream ≠ wire
//! bytes). Use explicit toggles such as `force_unix_arm` for rare protocol codes.

use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use libp2p_core::multiaddr::{Multiaddr, Protocol};
use unsigned_varint::encode;

#[path = "common.rs"]
mod common;

/// Unix multiaddr protocol code (multiformats protocols.csv).
const UNIX: u32 = 400;

#[derive(Debug)]
struct StructuredMultiaddr {
    /// Input bias: when true, force at least one component to protocol code 400.
    /// A bool flips quickly under libFuzzer; dict bytes cannot steer `code: u32`.
    /// Retained on the struct so corpus encodings keep the toggle bit.
    #[allow(dead_code)]
    force_unix_arm: bool,
    parts: Vec<(u32, Vec<u8>)>,
}

impl<'a> Arbitrary<'a> for StructuredMultiaddr {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let force_unix_arm = bool::arbitrary(u)?;
        let n = u.int_in_range(0..=common::MAX_STRUCTURED_PROTOCOLS)?;
        let mut parts = Vec::with_capacity(n.max(1));
        for _ in 0..n {
            let code = if u.ratio(7, 8)? {
                *u.choose(common::KNOWN_PROTOCOL_CODES)?
            } else {
                // Occasional unknown / multi-byte varint codes.
                u.arbitrary::<u32>()?
            };
            parts.push((code, payload_for_code(u, code)?));
        }

        if force_unix_arm {
            let unix_payload = payload_for_code(u, UNIX)?;
            if let Some(first) = parts.first_mut() {
                *first = (UNIX, unix_payload);
            } else {
                parts.push((UNIX, unix_payload));
            }
        }

        Ok(Self {
            force_unix_arm,
            parts,
        })
    }
}

fn payload_for_code(u: &mut Unstructured<'_>, code: u32) -> arbitrary::Result<Vec<u8>> {
    if common::is_length_prefixed(code) {
        // Prefer valid UTF-8 for string-valued protocols so Ok paths stay reachable;
        // still allow raw bytes often enough to stress from_utf8 Err.
        if code == UNIX || matches!(code, 53 | 54 | 55 | 56 | 42 | 449 | 481) {
            if u.ratio(3, 4)? {
                let s = String::arbitrary(u)?;
                let mut b = s.into_bytes();
                b.truncate(common::MAX_STRUCTURED_PAYLOAD);
                return Ok(b);
            }
        }
        let len = u.int_in_range(0..=common::MAX_STRUCTURED_PAYLOAD)?;
        Ok(u.bytes(len)?.to_vec())
    } else if let Some(fixed) = common::fixed_value_size(code) {
        // Pad to the protocol's fixed size so assemble→parse stays lossless.
        // Truncation / DataLessThanLen is delegated to raw-byte targets.
        let mut buf = u.bytes(fixed.min(u.len()))?.to_vec();
        buf.resize(fixed, 0);
        Ok(buf)
    } else {
        Ok(Vec::new())
    }
}

fn assemble_wire(s: &StructuredMultiaddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    let mut code_buf = encode::u32_buffer();
    let mut len_buf = encode::usize_buffer();
    for (code, payload) in &s.parts {
        out.extend_from_slice(encode::u32(*code, &mut code_buf));
        if common::is_length_prefixed(*code) {
            let len = payload.len().min(common::MAX_STRUCTURED_PAYLOAD);
            out.extend_from_slice(encode::usize(len, &mut len_buf));
            out.extend_from_slice(&payload[..len]);
        } else if common::fixed_value_size(*code).is_some() {
            out.extend_from_slice(payload);
        }
        // else: flag-only
    }
    out
}

fuzz_target!(|input: StructuredMultiaddr| {
    let wire = assemble_wire(&input);

    // Drive single-protocol decode on the assembled prefix (hits Unix arm even
    // when a later component makes full Multiaddr::try_from fail).
    let _ = Protocol::from_bytes(&wire);

    if let Ok(addr) = Multiaddr::try_from(wire) {
        common::assert_binary_roundtrip(&addr);
        common::exercise_text_roundtrip(&addr);
    }
});
