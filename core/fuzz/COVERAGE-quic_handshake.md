# Coverage: `quic_handshake`

Fuzz target for **libp2p-quic** Multiaddr parse, `Config` → QuinnConfig, and
TLS-over-QUIC handshake via in-memory `quinn_proto::Endpoint` Pair (no live UDP).

## Arms (`fuzz_quic`, byte0 `% 10`)

| Arm | Surface |
|-----|---------|
| 0 | Multiaddr `quic` / `quic-v1` (+ `/p2p`) + text parse |
| 1 | Deterministic `Config::new` → QuinnConfig (timeouts / draft-29 / MTU) |
| 2 | `PartialDecode` on raw UDP payload |
| 3..=4 | Structured mutual handshake + PeerId cert binding |
| 5 | Structured + corrupt peer cert DER |
| 6 | Structured + mid-handshake wire flip |
| 7 | Post-handshake bi-stream R/W (bounded) |
| 8 | Hole-punch mock Provider (`HandshakeTimedOut` / `send_to` Io error) |
| 9 | `HolePunchBook` register / cancel / complete / `HolePunchInProgress` |

## Soft invariants

- Never panics; step budget ≤ 256 handshake / 64 stream R/W
- Clean handshake: remote PeerId matches identity cert (`certificate::parse`)
- Corrupt arms: Err / timeout only (no abort)

## Dual-lane

TLS cert verification always runs (libp2p verifier). Optional
`--features fuzzing-real-verify` keeps identity `PublicKey::verify` real for
cross-crate parity with Noise / TLS / Strict Gossipsub.

## Soak

```bash
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run quic_handshake -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
```

## Next llvm-cov targets

1. Draft-29 dial path (`support_draft_29` + `Protocol::Quic`).
2. Full `dial_as_listener` through `GenTransport` (needs listen socket; book +
   mock Provider cover map races and punch loop without live net I/O).
3. Mid-handshake flip density on Initial vs Handshake CRYPTO.
