# Coverage: `autonatv2_server`

Action-sequence fuzzer for AutoNAT **v2 server** `Behaviour` (dial-request →
dial-back commands, DialFailure / success races, status events). Soft DoS clamps:

- `fuzz_dialing_count() ≤ MAX_ACTIONS + 4`
- `fuzz_pending_event_count() ≤ MAX_ACTIONS + 4`

## FOCUS setup

Inbound Connect → `InjectDialRequest` → `InjectDialBackResult` (± success) →
`InjectStatusEvent` → `FloodDialRequests` / `AdvanceTimeout`.

Biased: dial-request flood, dial-back failure vs establish+Ok, all-pending timeout.

## Next llvm-cov targets

1. Real dial-request stream codec path (handler `handle_request` still cold —
   Behaviour injectors skip stream I/O by design).
2. Outbound dial-back substream negotiate fail (`DialBackErr`).
3. Concurrent dial-backs for distinct peers vs same peer.
