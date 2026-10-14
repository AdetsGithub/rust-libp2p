# Coverage: `kademlia_handler`

Last deepened: Phase 31 — DialUpgrade NegotiationFailed / Apply / Io.
Last measured: 90s soak + `coverage_hints.sh` (2026-10-13).

Regenerate: `./scripts/coverage_hints.sh kademlia_handler`

## Soak (90s)

- `#58021 DONE cov: 2060 ft: 5071 corp: 248/10626b lim: 4096 exec/s: 637`

## Totals (`llvm-cov report`, focused)

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| `handler.rs` | **52.66%** | 58.33% | **57.79%** (was 55.5%) |
| `fuzz_handler.rs` | 80.50% | 75.00% | 83.33% |
| `protocol.rs` | 54.15% | 48.78% | 58.84% |

## Fault-arm hits (`OutboundDrive` inject)

| Arm | Hits |
|-----|------|
| `DialUpgradeNegotiationFailed` | **209** |
| `DialUpgradeApply` | **10** |
| `DialUpgradeIo` | **2** |
| `DialUpgradeTimeout` / idle TimedOut | (prior Phase 28b) |

## Surface

- `OutboundDrive` (12-way, ~½ fault): Timeout, Idle, NegFailed, Apply, Io, Mock×6
- `events_contain_io_kind` helper for unit smokes
