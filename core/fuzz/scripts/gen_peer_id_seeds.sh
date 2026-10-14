#!/usr/bin/env bash
# Regenerate seeds/peer_id_from_bytes from valid key material (all key types).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_ROOT="$ROOT/seeds/peer_id_from_bytes"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$SEED_ROOT"

cat > "$WORKDIR/Cargo.toml" << EOF
[package]
name = "gen_peer_id_seeds"
version = "0.0.0"
edition = "2021"

[dependencies]
libp2p-identity = { path = "$ROOT/../../identity", features = ["peerid", "ed25519", "rsa", "secp256k1", "ecdsa", "rand"] }
EOF

mkdir -p "$WORKDIR/src"
cat > "$WORKDIR/src/main.rs" << 'EOF'
use std::path::PathBuf;

use libp2p_identity::{Keypair, PublicKey};

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("seed root"));

    // Ed25519
    let ed = Keypair::generate_ed25519();
    let ed_pk = ed.public();
    std::fs::write(root.join("seed_ed25519_protobuf"), ed_pk.encode_protobuf()).unwrap();
    std::fs::write(root.join("seed_ed25519_peerid"), ed_pk.to_peer_id().to_bytes()).unwrap();

    // Secp256k1
    let sec = Keypair::generate_secp256k1();
    let sec_pk = sec.public();
    std::fs::write(root.join("seed_secp256k1_protobuf"), sec_pk.encode_protobuf()).unwrap();
    std::fs::write(root.join("seed_secp256k1_peerid"), sec_pk.to_peer_id().to_bytes()).unwrap();

    // ECDSA (P-256)
    let ec = Keypair::generate_ecdsa();
    let ec_pk = ec.public();
    std::fs::write(root.join("seed_ecdsa_protobuf"), ec_pk.encode_protobuf()).unwrap();
    std::fs::write(root.join("seed_ecdsa_peerid"), ec_pk.to_peer_id().to_bytes()).unwrap();

    // RSA from checked-in PKCS#8 fixtures in identity/
    let identity_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../identity/src/test/rsa-2048.pk8");
    // When run from temp dir, resolve via absolute path passed as env.
    let rsa_path = std::env::var("RSA_PKCS8")
        .map(PathBuf::from)
        .unwrap_or(identity_src);
    let mut pkcs8 = std::fs::read(&rsa_path).expect("rsa-2048.pk8");
    let rsa = Keypair::rsa_from_pkcs8(&mut pkcs8).expect("rsa decode");
    let rsa_pk = rsa.public();
    std::fs::write(root.join("seed_rsa_protobuf"), rsa_pk.encode_protobuf()).unwrap();
    std::fs::write(root.join("seed_rsa_peerid"), rsa_pk.to_peer_id().to_bytes()).unwrap();

    // Tiny malformed protobuf (type=Ed25519, empty data) — reject path seed
    std::fs::write(root.join("seed_protobuf_empty_data"), [0x08u8, 0x01, 0x12, 0x00]).unwrap();

    println!("wrote seeds under {}", root.display());
}
EOF

RSA_PKCS8="$ROOT/../../identity/src/test/rsa-2048.pk8" \
  cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -- "$SEED_ROOT"
echo "regenerated seeds under $SEED_ROOT"
ls -la "$SEED_ROOT"
