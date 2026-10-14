# Coverage: `mplex_multiplexed_io` (+ `mplex_frame_codec` twin)

Last deepened: Phase 23 — `MaxBufferBehaviour::ResetStream` bias + tiny
`max_buffer_len` + dual-Open Data floods.

Regenerate: `./scripts/coverage_hints.sh mplex_multiplexed_io -- -dict=dicts/mplex.dict`

## Totals (`llvm-cov report`, focused)

Prior: `io.rs` **~74%**, codec **~69%**. Re-measure after soak.

Smoke INIT after Phase 23: **cov 1087** ft 4740 (clean).

## Hot paths

| Site | Notes |
|------|-------|
| `buffer` → `ResetStream` overflow | Biased: ctrl bit0 ~¾, `max_buffer_len` 1..=2, dual Open + Data flood |
| `buffer` → `Block` | Still reachable (~¼ of cases) |
| Unknown-stream Data drop | Orphan `sid+64` every structured case |
| `on_open` / `poll_read_frame` | Still primary hot paths |

## Weight / input strategy

- `Arbitrary` biases **ResetStream** (~¾), tiny buffer (1..=2), outbound opens with Reset
- Structured (~⅘): dual Open → orphan Data → Data flood on both sids → Close/Reset mix
- Multi-outbound budget when Reset; loopback ~¼
- Twin `mplex_frame_codec`: structured `(flag, id, payload)` + chunked decode

## Assets

- Dict: `dicts/mplex.dict`
- Seeds: prior + `seed_reset_dual_flood`, `seed_reset_tiny_buf`

## Remaining gaps

| Gap | Notes |
|-----|-------|
| llvm-cov FOCUS re-measure | Confirm ResetStream overflow hits ≫ 6 |
| `lib.rs` public API | 0% under this bin (expected) |
