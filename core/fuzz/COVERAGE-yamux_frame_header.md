# Coverage: `yamux_frame_header`

Last deepened: Phase 24 — credit-soak in `fuzz_connection_ex` + dedicated
credit-exhaust / RST Arbitrary arm (single bin; no header/connection split).

Regenerate:
`./scripts/coverage_hints.sh yamux_frame_header -- -dict=dicts/yamux.dict -max_len=65536`

## Totals (`llvm-cov report`, focused)

Prior (Phase 19): header **~77%**, connection **~65%**, closing **~91%**,
stream **~62%**, flow_control **~64%**. Re-measure after soak.

Smoke INIT after Phase 24: **cov 1555** ft 4944 (clean, ~1 s / 2000 runs).

## Weight / input strategy

| Arm | Weight | Intent |
|-----|-------:|--------|
| Header | 1/10 | short / raw 12-byte codec |
| Connection raw | 1/10 | blob wire |
| Closing-biased | 2/10 | SYN→FIN/RST + tiny WU; graceful close |
| **Credit / RST** | **3/10** | multi-stream SYN, RST edges, orphan RST, huge WU |
| Structured | 3/10 | type-correct frames; RST-biased Data flags |

Driver (`yamux` fuzzing feature): after wire drain under `graceful_close`,
**credit-soak** up to 64 write bursts until `poll_write` Pending (send window
exhausted). Fixes premature exit before DEFAULT_CREDIT (256 KiB) was consumed.

## RST / credit edges

- RST after SYN Data; FIN then RST; RST|ACK
- Orphan RST on never-opened stream id
- Tiny / zero WindowUpdate; huge WU (`u32::MAX/2`) wrap edge
- Seeds: `seed_credit_syn_rst`, `seed_credit_multi_rst`, `seed_credit_wu_max`,
  `seed_rst_ack` (+ prior `seed_credit_tiny_wu`, `seed_close_*`)

## Remaining gaps

| Gap | Notes |
|-----|-------|
| `HeaderDecodeError` Display | 0-hit (cosmetic) |
| Split bins | Deferred (user chose single-bin deepen) |
| llvm-cov FOCUS re-measure | Confirm stream.rs / flow_control ↑ after soak |
