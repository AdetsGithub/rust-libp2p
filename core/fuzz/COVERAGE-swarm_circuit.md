# Coverage: `swarm_circuit`

MemoryTransport swarm compose for the **relay + DCUtR circuit stack**.

Last deepened: Phase 43 FOCUS soak — reservation → circuit → DCUtR upgrade.

## Setup

- 1× `relay::Behaviour` hop server (plaintext + yamux + MemoryTransport, `Version::V1`)
- 2–3× `relay::client::Behaviour` + `dcutr::Behaviour` + Identify
  (`OrTransport(relay_transport, MemoryTransport)`)
- Tokio `current_thread` + **paused time**
- On relay `NewListenAddr`: **`add_external_address`** (required for hop reservations)
- Recipe: relay listen → client listen → dial relay → `listen_on(p2p-circuit)` →
  fat Poll → guaranteed `DialViaCircuit(0→1)` + `DialDirect(0→1)` → free actions

## Soak (90s, ASan, post external-addr fix)

| Metric | Value |
|--------|-------|
| Runs | 455 |
| Cov / ft | **15396** / 53763 (was ~12305 before fix) |
| Corp | 197 / 41Kb |
| exec/s | ~5 |
| RSS | ~436 Mb |
| Crashes | 0 |

## FOCUS llvm-cov (line %)

| Surface | Before fix | After fix |
|---------|------------|-----------|
| `swarm_circuit.rs` | 86% | **92%** |
| `relay` behaviour | 21% | **61%** |
| `relay` priv_client | 52% | **77%** |
| `inbound_hop.rs` | **0%** | **64%** |
| `outbound_hop.rs` | **0%** | **69%** |
| `inbound_stop.rs` | 0% | **65%** |
| `dcutr` behaviour | 44% | **80%** |
| `dcutr` handler/relayed | **0%** | **76%** |

FOCUS counters (reservation_accepted_*, circuit_*, relayed_connections, dcutr_ok|err)
are live under the event handlers; soft DoS clamps apply end-of-run.

## Assets

- Dict: `dicts/swarm_circuit.dict`
- Seeds: `seeds/swarm_circuit/` (4 hand seeds + grown corpus)
- Logs: `logs/swarm_circuit-soak2.log`, `logs/swarm_circuit-coverage2.log`
- HTML: `coverage/swarm_circuit/html-focus/`

## Remaining gaps

- Longer RSS soak (Noise XX on circuit mesh — optional)
- DCUtR `AttemptsExceeded` / stream Err arms still cold (zero-hit Err scan)
- Compose with `connection-limits` denial under circuit dials
- `outbound_stop` still ~51% — bias stop-protocol teardown
