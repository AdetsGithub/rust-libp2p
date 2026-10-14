# Coverage: `gossipsub_handler`

Last deepened: Phase 31 — DialUpgradeError / MaxSubstreamAttempts / MessageDropped.
Last measured: 90s soak + `coverage_hints.sh` (2026-10-13).

Regenerate: `./scripts/coverage_hints.sh gossipsub_handler`

## Soak (90s)

- `#128216 DONE cov: 2172 ft: 6048 corp: 352/15813b lim: 4096 exec/s: 1408`

## Totals (`llvm-cov report`, focused)

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| `handler.rs` | **67.93%** | 66.67% | **78.73%** (was 65%) |
| `fuzz_handler.rs` | 77.34% | 64.29% | 76.82% |
| `protocol.rs` | 46.32% | 42.86% | 47.45% |
| `queue.rs` | 67.59% | 73.33% | 65.41% |

## Fault-arm hits (`handler.rs`)

| Site | Hits |
|------|------|
| `MessageDropped` | **14** |
| `MaxSubstreamAttempts` (inbound disable) | **78** |
| `MaxSubstreamAttempts` (outbound disable) | **211** |
| DialUpgrade Timeout log | **224** |
| DialUpgrade NegotiationFailed → ProtocolUnsupported | **13** |
| DialUpgrade Io log | **620** |

## Surface

- `HandlerFault` (~⅜ Arbitrary): DialUpgrade Timeout/NegFailed/Io,
  MaxSubstream inbound (FullyNegotiated×5) / outbound (DialUpgradeError×5),
  MessageDroppedTimedOut (Publish + Delay(1ms) + sleep)
- Do not inject `DialUpgradeError::Apply` — maps to `unreachable!()`
