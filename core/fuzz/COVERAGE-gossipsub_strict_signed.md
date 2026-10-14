# Coverage: `gossipsub_strict_signed`

Last deepened: Phase 30 + Phase 31b codec fix (Strict InjectWire mode + topic max order).
Last measured: 60s re-soak + `coverage_hints.sh` after codec fix (2026-10-13).

Regenerate: `./scripts/coverage_hints.sh gossipsub_strict_signed -- -dict=dicts/gossipsub.dict -max_len=4096`

## Soak

- First 90s (pre-fix): `#2474 DONE cov: 4614` — InvalidSignature only (InjectWire used Permissive codec)
- Post-fix 60s: `#1720 DONE cov: 4211 ft: 11631 corp: 161/25Kb lim: 4096 exec/s: 28`

## Totals (`llvm-cov report`, focused) — post-fix

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| `protocol.rs` | **58.90%** | 47.62% | **57.65%** |
| `fuzz.rs` | 58.06% | 51.22% | 53.98% |
| `behaviour.rs` | 28.06% | 32.21% | 32.94% |

## ValidationError hits (`protocol.rs`) — post-fix

| Error | Hits |
|-------|------|
| `InvalidSignature` | **334** |
| `EmptySequenceNumber` | **302** |
| `MessageSizeTooLargeForTopic` | **290** |

## Fixes that unlocked topic/seqno rejects

1. `attach_live_inbound_mode(validation, topic_maxes)` — InjectWire must not decode under Permissive.
2. No default topic max at Strict construction (signed MissingSeqno > 100b misclassified as oversize).
3. Setup: `SetTopicMaxSize(topic0=100)` then `PublishOversizedTopic`; re-attach feeds on SetTopicMaxSize.

## Optional

- `--features fuzzing-real-verify` for crypto-true InvalidSignature on GarbageSig
