# Coverage: `dcutr_behaviour`

Action-sequence fuzzer for `libp2p-dcutr` Behaviour (relayed vs direct,
hole-punch inject, dial failure). Soft DoS clamps:

- `fuzz_outgoing_attempt_count() ≤ attempt_bound + 2`
- `fuzz_direct_connection_count() ≤ PEER_POOL×4 + 2`
- Direct-connection set consistent across disconnect

## FOCUS setup / weights (Phase 43c)

Setup: candidate → relayed → HolePunch(Connect, WriteFault) → EmptyAddrs →
InboundNegotiated → **FloodDialFailure(7)** → ConcurrentUpgradeTeardown →
OutboundConnectFailed → ConnectDirect.

Free-action bias: hole-punch Sync/Empty/ManyAddrs, flood failures, teardown.

## Harness fixes

1. Coverage replay panicked at `behaviour.rs:220` (`state mismatch`) when harness
   `ConnectionId`s collided with `DialOpts`' global `NEXT_CONNECTION_ID`. Fixed by
   minting harness IDs from `0xE000_0001`.
2. `FloodDialFailure` / `DialFailure` used the **relayed** `ConnectionId`;
   `on_dial_failure` looks up the **direct** id in `direct_to_relayed_connections`.
   Fixed by seeding `OutboundConnectNegotiated` × `MAX_NUMBER_OF_UPGRADE_ATTEMPTS`,
   capturing `ToSwarm::Dial` connection ids, then failing those.

## Soak

| Run | Time | Cov / ft | Corp | exec/s | Crashes |
|-----|------|----------|------|--------|---------|
| #1 (deny bias) | 90s | 2170 / 8701 | 377 | ~138 | 0 |
| #2 (ConnectionId fix) | 60s | 2165 / 9004 | 310 | ~60 | 0 |
| #3 (AttemptsExceeded path) | 60s | **2280** / 9596 | 330 | ~45 | 0 |

## llvm-cov FOCUS (line %) — after soak #3

| Surface | % |
|---------|---|
| `fuzz_targets/dcutr_behaviour.rs` | 82% |
| `fuzz.rs` | **90%** |
| `behaviour.rs` | **85%** (regions **100%**) |
| `handler/relayed.rs` | **48%** |
| `protocol/inbound.rs` | **65%** |
| `protocol/outbound.rs` | 0% |

### Deny / teardown / WriteFault hits

| Site | Hits |
|------|------|
| `AttemptsExceeded` | **~8.61k** (was 0) |
| HolePunch Connect / EmptyAddrs / Sync | warm |
| `InboundError` / `OutboundError` | warm |
| `InboundConnectFailed` | warm |
| `InboundConnectNegotiated` → dial map insert | warm |

## Assets

- Dict: `dicts/dcutr_behaviour.dict`
- Seeds: `seeds/dcutr_behaviour/`
- Logs: `logs/dcutr_behaviour-soak*.log`, `logs/dcutr_behaviour-coverage4.log`
- HTML: `coverage/dcutr_behaviour/html-focus/`

## Remaining gaps

1. `protocol/outbound.rs` hole-punch as dialer encode path.
2. Optional: longer soak to push `handler/relayed.rs` past 50%.
