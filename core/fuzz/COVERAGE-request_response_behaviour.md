# Coverage: `request_response_behaviour`

Action-sequence fuzzer for `libp2p-request-response` (QueryId-style attribution:
ghost responses, stale timeouts, inbound/outbound races). Soft DoS clamps:

- Per-peer `active_outbound` / `pending_inbound` ≤ `MAX_ACTIONS + 2`
- Totals ≤ `MAX_ACTIONS × PEER_POOL + 8`
- After disconnect: no pending outbound for that peer

## Attribution (Kad `query_slot` / `mismatch`)

| Field | Meaning |
|-------|---------|
| `request_slot == 0` | Newest active outbound / pending inbound |
| `request_slot > 0` | Walk older ring entries (`% len` from end) |
| `mismatch` | Ghost id (`0xF000_0000 + slot`) never issued |

Applies to `InjectResponse`, `InjectOutboundTimeout`, `InjectInboundTimeout`,
`InjectOutboundStreamFailed`. Ghost (`mismatch`) paths are skipped under
`debug_assertions` (Behaviour `debug_assert!`); soak with
`--sanitizer=none` / release for ghost-id density.

## FOCUS setup

Connect×2 → `SendRequest`×2 → ghost mismatch response → older-slot response →
inbound request → inbound timeout (± mismatch).

## Next llvm-cov targets

1. Timeout vs late response attribution under concurrent ring.
2. Handler stream-failure / codec-error arms.
3. Inbound omission + blackhole channel drop races.
