# Progress

## 2026-10-13 — Phase 44 Principal five-vector re-scrutiny (analysis-only)

- User requested Principal evaluation of harness depth vs five vectors.
- Re-read live drivers + COVERAGE + Phase 43–43d evidence; case_417445b228 updated.
- Verdict: past protobuf wall; residual = swarm Strict compose, FragmentingIo,
  real-verify dual-lane soak, relay rate_limiter/stop cold paths.
- User chose **analysis + snippets only** (no in-tree edits this turn).

## 2026-10-13 — Phase 43 Principal re-scrutiny + patches

- Re-read live harnesses vs five vectors; residual gaps → implemented:
  WriteFault+flush on relay/dcutr; flush_stall_every on gossip/kad/identify;
  new `swarm_circuit` MemoryTransport compose.
- Unit smokes green (relay/dcutr/kad/gossip/identify WriteFault paths).
- `cargo check --bin swarm_circuit` clean.

## 2026-10-13 — Phase 43b swarm_circuit FOCUS soak

- First soak: hop protocol 0% — root cause: missing `add_external_address` on
  relay `NewListenAddr` (reservations never accepted).
- Fix: external addr + `Version::V1` + fat Poll + guaranteed circuit/direct dial.
- Re-soak 90s clean: cov **15396** ft 53763; FOCUS hits:
  reservation≈971, circuit_est≈1.19k, dcutr_ok≈1.31k / err≈839.
- llvm-cov: inbound_hop **0→64%**, outbound_hop **0→69%**, dcutr relayed
  handler **0→76%**, relay behaviour **21→61%**.

## 2026-10-13 — Phase 43c relay/dcutr deny+teardown llvm-cov

- Cold arms root causes:
  - Relay: Active keyed per `ConnectionId`; flood on one conn never exceeded
    `max_reservations_per_peer`. Tight caps (2/1) + dual-Connect + rotate conn
    in FloodReservations → `DenyReservationReq` / `Event::ReservationReqDenied`
    **0 → ~2.39k**.
  - DCUtR: FloodDialFailure used relayed cid; need direct DialOpts id after
    `OutboundConnectNegotiated` × MAX → `AttemptsExceeded` **0 → ~8.61k**.
- Soak #3 clean: relay cov **2723**; dcutr cov **2280**.
- llvm-cov: relay behaviour **56%**, inbound_hop **73%**; dcutr behaviour
  **74→85%** (regions 100%). Remaining: stop protocols / rate_limiter /
  `protocol/outbound.rs`.

## 2026-10-13 — Phase 43d Loom Handler Shared-queue races

- Expanded beyond tiny QueryBook / basic Shared push-pop:
  - Gossipsub (+4): Publish cap vs Handler poll, priority+non_priority dual-pop,
    dual Handler poll_pending + single push, remove_data XOR pop → **8** tests.
  - Kad (+3): `HandlerLane` enqueue/start/finish, dual-handler shared pool,
    stale QueryId finish → **6** tests.
- All green under `--features loom` (no `RUSTFLAGS=--cfg loom`).
