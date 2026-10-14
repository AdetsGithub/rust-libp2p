//! Shared helpers for multiaddr fuzz targets.

#![allow(dead_code)] // Not every target uses every helper.

use libp2p_core::multiaddr::Multiaddr;

/// HARD binary round-trip: parse → serialize → re-parse must be stable & canonical.
pub fn assert_binary_roundtrip(addr: &Multiaddr) {
    let bytes = addr.to_vec();
    let reparsed =
        Multiaddr::try_from(bytes.clone()).expect("re-parsing a serialized multiaddr must succeed");
    assert_eq!(addr, &reparsed, "binary round-trip changed the value");
    assert_eq!(bytes, reparsed.to_vec(), "serialization is not idempotent");
}

/// Exercise text Display→parse. Equality is soft unless `hard_text_roundtrip` is enabled.
pub fn exercise_text_roundtrip(addr: &Multiaddr) {
    let text = addr.to_string();
    match text.parse::<Multiaddr>() {
        Ok(parsed) => {
            #[cfg(feature = "hard_text_roundtrip")]
            {
                assert_eq!(
                    addr, &parsed,
                    "text round-trip changed the value (hard_text_roundtrip)"
                );
            }
            #[cfg(not(feature = "hard_text_roundtrip"))]
            {
                let _ = parsed;
            }
        }
        Err(_) => {
            // Soft path: Finding #1 — binary accepts Dns*/Unix labels that text cannot re-parse.
            #[cfg(feature = "hard_text_roundtrip")]
            panic!("text re-parse failed for Display of valid multiaddr: {text:?}");
        }
    }
}

/// Cap payload material assembled into wire buffers (avoid near-max length thrash).
pub const MAX_STRUCTURED_PAYLOAD: usize = 64;
pub const MAX_STRUCTURED_PROTOCOLS: usize = 8;

/// Known multiaddr protocol codes (from multiformats/multiaddr protocols.csv / multiaddr 0.19).
pub const KNOWN_PROTOCOL_CODES: &[u32] = &[
    4,    // ip4
    6,    // tcp
    33,   // dccp
    41,   // ip6
    42,   // ip6zone
    43,   // ipcidr
    53,   // dns
    54,   // dns4
    55,   // dns6
    56,   // dnsaddr
    132,  // sctp
    273,  // udp
    275,  // p2p-webrtc-star (deprecated)
    276,  // p2p-webrtc-direct (deprecated)
    277,  // p2p-stardust (deprecated)
    280,  // webrtc-direct
    281,  // webrtc
    290,  // p2p-circuit
    301,  // udt
    302,  // utp
    400,  // unix
    421,  // p2p
    443,  // https (deprecated alias)
    444,  // onion
    445,  // onion3
    446,  // garlic64
    447,  // garlic32
    448,  // tls
    449,  // sni
    454,  // noise
    460,  // quic
    461,  // quic-v1
    465,  // webtransport
    466,  // certhash
    477,  // ws
    478,  // wss (deprecated)
    479,  // p2p-websocket-star (deprecated)
    480,  // http
    481,  // http-path
    777,  // memory
    4770, // ws-with-path (non-standard)
    4780, // wss-with-path (non-standard)
];

/// Codes whose value is unsigned-varint length-prefixed bytes.
pub fn is_length_prefixed(code: u32) -> bool {
    matches!(
        code,
        53 | 54 | 55 | 56 | 42 | 400 | 421 | 446 | 447 | 449 | 466 | 481 | 4770 | 4780
    )
}

/// Fixed value size in bytes for protocols that are not length-prefixed / flag-only.
/// `None` means flag-only (no value) or length-prefixed (use [`is_length_prefixed`]).
pub fn fixed_value_size(code: u32) -> Option<usize> {
    match code {
        4 => Some(4),             // ip4
        6 | 33 | 132 | 273 => Some(2), // tcp/dccp/sctp/udp
        41 => Some(16),           // ip6
        43 => Some(1),            // ipcidr
        444 => Some(12),          // onion
        445 => Some(37),          // onion3
        777 => Some(8),           // memory
        _ => None,
    }
}
