# Coverage: `identify_handler`

Last deepened: Phase 29 — ConnectionHandler mock-stream driver.
Last measured: 90s soak + `coverage_hints.sh` (2026-10-13).

Regenerate: `./scripts/coverage_hints.sh identify_handler -- -dict=dicts/identify.dict -max_len=4096`

## Soak (90s)

- `#17667 DONE cov: 2827 ft: 7743 corp: 197/11152b lim: 4096 exec/s: 194 rss: 419Mb`

## Totals (`llvm-cov report`, focused)

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| `handler.rs` | **58.75%** | 58.82% | **62.17%** |
| `protocol.rs` | **72.79%** | 87.50% | **80.95%** |
| `fuzz_handler.rs` | 80.37% | 70.37% | 81.92% |

## Surface

- `protocols/identify/src/fuzz_handler.rs` → `fuzz_handler_io`
- `Stream::from_async_rw` (swarm `fuzzing`) + `ChunkFeed` partial/reset reads
- Roles: OutboundIdentify (parse), InboundPush (parse/merge), InboundIdentify / OutboundPush (encode)
- `OutboundDrive::{DialUpgradeTimeout, DialUpgradeNegotiationFailed}` → IdentificationError

## Cold residual

| Site | Notes |
|------|-------|
| `StreamUpgradeError::Timeout` (active_streams idle) | STREAM_TIMEOUT=60s; need short Delay arm like kad |
| ListenUpgradeError / Debug arms | Low ROI |

## Next

- Optional idle-timeout arm for FuturesSet Timeout
- Residual list: gossipsub Strict+Signed; handler upgrade-failure elsewhere
