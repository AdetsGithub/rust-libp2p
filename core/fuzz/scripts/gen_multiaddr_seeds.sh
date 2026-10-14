#!/usr/bin/env bash
# Regenerate seeds/multiaddr_* from known-good Multiaddr strings (multiaddr 0.19.x).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_ROOT="$ROOT/seeds"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$SEED_ROOT"/{multiaddr_binary,multiaddr_text,multiaddr_protocol_from_bytes,multiaddr_structured,multiaddr_roundtrip}

cat > "$WORKDIR/Cargo.toml" << 'EOF'
[package]
name = "gen_ma_seeds"
version = "0.0.0"
edition = "2021"
[dependencies]
multiaddr = "0.19.1"
EOF

mkdir -p "$WORKDIR/src"
cat > "$WORKDIR/src/main.rs" << 'EOF'
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("seed root"));
    let texts = [
        ("seed_ip4_tcp", "/ip4/127.0.0.1/tcp/4001"),
        ("seed_ip4_tcp_p2p", "/ip4/127.0.0.1/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"),
        ("seed_dnsaddr", "/dnsaddr/sjc-1.bootstrap.libp2p.io"),
        ("seed_dns4", "/dns4/example.com/tcp/443"),
        ("seed_unix", "/unix/stdio"),
        ("seed_onion3", "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234"),
        ("seed_certhash", "/ip4/127.0.0.1/udp/1234/webrtc-direct/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"),
        ("seed_quic_v1", "/ip4/127.0.0.1/udp/4001/quic-v1"),
        ("seed_ip6_tcp", "/ip6/::1/tcp/8080"),
        ("seed_p2p_circuit", "/ip4/127.0.0.1/tcp/9090/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"),
    ];

    for (name, text) in texts {
        let addr: multiaddr::Multiaddr = text.parse().unwrap_or_else(|e| panic!("parse {text}: {e}"));
        let bin = addr.to_vec();
        std::fs::write(root.join("multiaddr_text").join(name), text.as_bytes()).unwrap();
        std::fs::write(root.join("multiaddr_binary").join(name), &bin).unwrap();
        std::fs::write(root.join("multiaddr_roundtrip").join(format!("{name}_text")), text.as_bytes()).unwrap();
        std::fs::write(root.join("multiaddr_roundtrip").join(format!("{name}_bin")), &bin).unwrap();
        if let Some(p) = addr.iter().next() {
            let mut enc = Vec::new();
            p.write_bytes(&mut enc).unwrap();
            std::fs::write(root.join("multiaddr_protocol_from_bytes").join(name), &enc).unwrap();
            std::fs::write(root.join("multiaddr_structured").join(name), &bin).unwrap();
        }
    }

    for (name, text) in [
        ("seed_empty_reject", "/"),
        ("seed_dns6", "/dns6/example.com"),
        ("seed_memory", "/memory/1234"),
    ] {
        std::fs::write(root.join("multiaddr_text").join(name), text.as_bytes()).unwrap();
        std::fs::write(root.join("multiaddr_roundtrip").join(name), text.as_bytes()).unwrap();
    }
}
EOF

cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -- "$SEED_ROOT"
echo "regenerated seeds under $SEED_ROOT"
