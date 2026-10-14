# Coverage: `noise_handshake`

Last measured after Phase 16 structured XX land. Smoke: **5k** runs clean
(`cov: 2944`, was stub **1858**).

Regenerate: `./scripts/coverage_hints.sh noise_handshake -- -dict=dicts/noise.dict -max_len=4096`

## Totals (`llvm-cov report`, focused)

| File | Regions | Missed | Cover |
|------|--------:|-------:|------:|
| `transports/noise/src/io/framed.rs` | 132 | 13 | **90.15%** |
| `transports/noise/src/io/handshake.rs` | 111 | 11 | **90.09%** |
| `transports/noise/src/protocol.rs` | 126 | 21 | **83.33%** |
| `transports/noise/src/fuzz.rs` | 455 | 78 | **82.86%** |
| `transports/noise/src/lib.rs` | 91 | 28 | **69.23%** |
| `transports/noise/src/io.rs` | 94 | 32 | **65.96%** |

Prior stub: handshake **~40%**, `io.rs` **0%**.

## Arms

| Arm (byte0 `% 8`) | Surface |
|----:|---------|
| 0 | `NoiseHandshakePayload::decode` |
| 1 | `fuzz_length_prefixed` (u16-BE) |
| 2 | inbound XX + blackhole `MockIo` (raw fuzz bytes) |
| 3..=4 | structured XX **inbound** (SUT responder; snow initiator) |
| 5..=6 | structured XX **outbound** (SUT initiator; snow responder) |
| 7 | structured XX inbound + post-handshake `Output` R/W |

Structured payload flags (byte after arm): bit0 certhash on SUT, bit1 omit
expected certhash (outbound), bit2 include extensions, bit3 muxer-biased ext,
**bit7 flip one ciphertext byte** (warms decrypt / `AuthFailed` on real-verify).

## Dual-lane soak

| Lane | Build | Goal |
|------|-------|------|
| A (depth) | default (`--cfg fuzzing` stubs `PublicKey::verify`) | Post-auth handshake / framing / certhash |
| B (crypto) | `--features fuzzing-real-verify` | `BadSignature` / `AuthenticationFailed` / identity binding |

```bash
# Lane A
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run noise_handshake -- \
  -dict=dicts/noise.dict -print_funcs=0 -max_len=4096

# Lane B — warm BadSignature / AuthFailed (bit7 corrupt seeds)
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run noise_handshake --features fuzzing-real-verify -- \
  -dict=dicts/noise.dict -print_funcs=0 -max_len=4096
```

Seed `seeds/noise_handshake/seed_xx_inbound_corrupt_cipher` sets arm=3 + flags bit7.

## Remaining gaps

| Gap | Notes |
|-----|-------|
| `BadSignature` / `AuthenticationFailed` | Cold on Lane A (verify stubbed); FOCUS Lane B + bit7 corrupt |
| `recv_empty` non-empty reject | Sparse under structured empty msg1 |
| Transport `MAX_FRAME_LEN` flush | Large post-io writes |
| Certhash mismatch density | Seed present; soak further |

## Weight / input strategy

- Byte0 `% 8` biases 5/8 toward structured XX / post-io.
- Seeds: stub LP/payload + `seed_xx_*` inbound/outbound/certhash/muxer/post-io + **corrupt_cipher**.
- Dict: protobuf tags, LP edges, arm selectors, muxer/certhash fragments.
