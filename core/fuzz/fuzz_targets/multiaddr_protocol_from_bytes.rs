#![no_main]

//! Single-`Protocol` binary decode (`Protocol::from_bytes`) so coverage is not
//! diluted by full multiaddr chain parsing.

use libfuzzer_sys::fuzz_target;
use libp2p_core::multiaddr::Protocol;

fuzz_target!(|data: &[u8]| {
    // Cap input: one protocol value is small; avoid thrashing on huge slices.
    let data = if data.len() > 256 { &data[..256] } else { data };
    if let Ok((proto, _rest)) = Protocol::from_bytes(data) {
        let mut encoded = Vec::new();
        proto
            .write_bytes(&mut encoded)
            .expect("write_bytes of a decoded Protocol must succeed");
        let (again, rest) = Protocol::from_bytes(&encoded)
            .expect("re-parsing write_bytes output must succeed");
        assert!(rest.is_empty(), "write_bytes must emit exactly one Protocol");
        assert_eq!(proto, again, "Protocol binary round-trip changed the value");
    }
});
