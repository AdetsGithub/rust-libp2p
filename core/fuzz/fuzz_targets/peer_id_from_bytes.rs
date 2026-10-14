#![no_main]

//! Raw-byte fuzzer for `PeerId` (multihash) and `PublicKey` protobuf / ASN.1 decode.
//!
//! Goal: stress libp2p's decoding logic (malformed protobuf wrappers, RSA X.509
//! length prefixes), not the underlying curve math. Under cargo-fuzz
//! (`--cfg fuzzing`), Ed25519/Secp256k1/ECDSA key-material validation may
//! substitute a dummy key after a successful protobuf decode so `to_peer_id`
//! stays reachable; RSA ASN.1 parsing stays strict.

use libfuzzer_sys::fuzz_target;
use libp2p_identity::{PeerId, PublicKey};

/// Bound ASN.1 / protobuf length-prefix thrash under ASan.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = if data.len() > MAX_INPUT {
        &data[..MAX_INPUT]
    } else {
        data
    };

    // 1. Raw PeerId (identity multihash)
    let _ = PeerId::from_bytes(data);

    // 2. Public key protobuf (+ nested ASN.1 for RSA / ECDSA)
    match PublicKey::try_decode_protobuf(data) {
        Ok(key) => {
            let _ = key.to_peer_id();
            let _ = key.encode_protobuf();
            // Under `--cfg fuzzing`, verify always returns true (future Noise).
            let _ = key.verify(b"fuzz-msg", b"fuzz-sig");
        }
        Err(e) => {
            let _ = format!("{e}");
        }
    }
});
