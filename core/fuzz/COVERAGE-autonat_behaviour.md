# Coverage: `autonat_behaviour`

Action-sequence fuzzer for AutoNAT **v1** `Behaviour` (dial-back probes,
address confidence, inbound DialRequest throttle). Soft DoS clamps:

- `fuzz_ongoing_outbound_count() ≤ MAX_ACTIONS + 2`
- `fuzz_servers_count() ≤ PEER_POOL + 2`
- Confidence / `NatStatus` stay coherent after disconnect

## Attribution (Kad `request_slot` / `mismatch`)

| Field | Meaning |
|-------|---------|
| `request_slot == 0` | Newest ongoing outbound DialRequest |
| `request_slot > 0` | Walk older ring entries |
| `mismatch` | Ghost `OutboundRequestId` (skipped under `debug_assertions`) |

## FOCUS setup

Connect → `AddServer` → external candidate → `AdvanceProbeClock` → dial-back
success/fail → inbound DialRequest on a second peer.

Biased: `InjectDialBack`, `FloodAdvanceProbe`, inbound dial flood,
`DialFailure` / disconnect races.

## Next llvm-cov targets

1. `as_client` confidence flip Private ↔ Public under alternating dial-backs.
2. Inbound throttle / `only_global_ips` reject paths (fuzz uses `only_global_ips: false`).
3. Probe timer + `ProbeAddress` vs stale ConnectionClosed.
