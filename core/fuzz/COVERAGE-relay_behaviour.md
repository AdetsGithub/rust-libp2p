# Coverage: `relay_behaviour`

Action-sequence fuzzer for `libp2p-relay` Behaviour (hop/stop wire + reservation
→ circuit state machine). Soft DoS clamps (release-safe `assert!`):

- `fuzz_active_reservation_count() ≤ MAX_RESERVATIONS + 2`
- `fuzz_circuit_count() ≤ MAX_CIRCUITS + 2`
- No active reservation after disconnect for that peer

## FOCUS setup / weights (Phase 43c)

Setup: external → enable → **dual-Connect peer0** → Connect peers 1–2 →
reserve×2 (fill global) → **FloodReservations(peer2)** → FloodCircuits →
ConcurrentTeardown → HopWire(MalformedPeer, WriteFault) → StopWire.

Caps tightened to `max_reservations=2` / `per_peer=1` / circuits `2`/`1` so
deny arms are reachable (Active is keyed per `ConnectionId`).

Free-action bias: flood deny / teardown / Disable / even-slot WriteFault hop+stop.

## Soak

| Run | Time | Cov / ft | Corp | exec/s | Crashes |
|-----|------|----------|------|--------|---------|
| #1 (deny bias) | 90s | 2694 / 7292 | 168 | ~15 | 0 |
| #2 (drain fix) | 60s | 2711 / 8181 | 154 | ~13 | 0 |
| #3 (tight caps + multi-conn) | 60s | **2723** / 8980 | 166 | ~11 | 0 |

## llvm-cov FOCUS (line %) — after soak #3

| Surface | % |
|---------|---|
| `fuzz_targets/relay_behaviour.rs` | 79% |
| `fuzz.rs` | **93%** |
| `fuzz_handler.rs` (WriteFault) | **73%** |
| `behaviour.rs` | **56%** |
| `behaviour/handler.rs` | **35%** |
| `inbound_hop.rs` | **73%** |
| `inbound_stop` / `outbound_*` | 0% (bin injects hop path only) |

### Deny / teardown hits

| Site | Hits |
|------|------|
| `DenyReservationReq` NotifyHandler | **~2.39k** (was 0) |
| Handler `ReservationReqDenied` | **~2.39k** (was 0) |
| Behaviour `Event::ReservationReqDenied` | **~2.39k** (was 0) |
| Circuit `ResourceLimitExceeded` | warm |
| `Event::CircuitClosed` | warm |

## Assets

- Dict: `dicts/relay_behaviour.dict`
- Seeds: `seeds/relay_behaviour/`
- Logs: `logs/relay_behaviour-soak*.log`, `logs/relay_behaviour-coverage3.log`
- HTML: `coverage/relay_behaviour/html-focus/`

## Remaining gaps

1. Real stop-protocol inject (not hop-shared) for `inbound_stop` / `outbound_stop`.
2. Rate-limiter deny arms (`rate_limiter.rs` 0% — limiters empty in fuzz config).
3. `ReservationReqAcceptFailed` / deny-failed under WriteFault err_every.
