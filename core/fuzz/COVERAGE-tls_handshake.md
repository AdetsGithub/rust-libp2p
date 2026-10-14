# Coverage: `tls_handshake`

Structured mutual TLS + certificate parse/generate for `libp2p-tls`.

Regenerate: `./scripts/coverage_hints.sh tls_handshake -- -max_len=4096`

## Arms (byte0 `% 8`)

| Arm | Surface |
|----:|---------|
| 0 | `certificate::parse` raw |
| 1 | generate + parse roundtrip |
| 2 | inbound upgrade mock |
| 3..=4 | structured mutual TLS |
| 5 | structured + corrupt peer cert DER |
| 6 | structured + mid-handshake wire flip |
| 7 | mutated cert parse (`Err`) |

## Dual-lane soak

TLS certificate verification runs via `Libp2pCertificateVerifier` on both lanes.
`--features fuzzing-real-verify` keeps identity `PublicKey::verify` real for
cross-crate CI consistency (Noise / Strict Gossipsub share the feature).

```bash
# Default (cert reject / mid-wire flip density)
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run tls_handshake -- \
  -print_funcs=0 -max_len=4096

# Dual-lane feature parity with Noise
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run tls_handshake --features fuzzing-real-verify -- \
  -print_funcs=0 -max_len=4096
```

Bias corpus toward arms 5–6 (flags after arm selector) to warm cert-reject /
handshake-abort density. Swarm compose: `swarm_orchestrator` selects TLS (~⅛)
as whole-mesh security (parallel to Noise).

## Remaining gaps

| Gap | Notes |
|-----|-------|
| Cert reject density | Arms 5/7; soak + llvm-cov on `verifier.rs` |
| Mid-wire AuthFailed | Arm 6 + swarm `TransportFault` on TLS meshes |
| ALPN mismatch | Not yet structured |
