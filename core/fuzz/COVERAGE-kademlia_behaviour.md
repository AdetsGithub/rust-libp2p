# Coverage: `kademlia_behaviour`

Phase 33 — harness fix: `InjectInbound` / `InjectStructured` previously injected
inbound requests (`HandlerEvent::*Req`) via `on_connection_handler_event` with a
**synthetic** `RequestId::fuzz(next_req)` that had no matching inbound substream
in the live `Handler`. When the Behaviour answered, `Handler::answer_pending_request`
tripped its `debug_assert!("Cannot find inbound substream")` (handler.rs:870).
Both actions now feed the request as a length-prefixed wire frame through the
handler's real inbound codec (`ChunkFeed` + `pump_handler`), so a real substream
+ RequestId exist; the no-handler fallback injects directly but the queued
response is dropped (`drain_polls` has no handler). Verified: crash artifact
`artifacts/kademlia_behaviour/crash-4a2347e2…` now runs clean; 1000+ corpus seeds
replay without the panic (previously died at ~128 seeds).

Last deepened: Phase 28 — `AdvanceQueryClock` for deterministic query Timeouts
(rewinds query starts + `fuzz_take_timed_out`, even while `Waiting(Some)`).
Phase 27: live ConnectionHandler mock streams (InjectWire → ChunkFeed; drain
forwards NotifyHandler → HandlerIn for response encode).

Regenerate: `./scripts/coverage_hints.sh kademlia_behaviour -- -dict=dicts/kademlia.dict`

## Totals (`llvm-cov report`, focused)

Prior (Phase 18): behaviour **~62%**, jobs **~94%**, handler **~9%**.
Smoke INIT after Phase 23: **cov 4835** ft 20511 (was ~4679).
Standalone `kademlia_handler` soak: `handler.rs` **51% lines** (was ~9%).

FOCUS now includes `query/peers/closest.rs` + `closest/disjoint.rs`.

## Cold → hot

| Site | Before | After |
|------|--------|-------|
| `jobs.rs` / `fuzz_jobs_asap` | off | ~2.86k; jobs **94%** (Phase 18) |
| `PutRecordError::QuorumFailed` | sparse | ~28 (Phase 18) |
| `GetRecordError::NotFound` | ~4 | denser: empty-RT preamble + GetRecordEmpty bias |
| `ClosestDisjointPeersIter` | **0%** | `disjoint_query_paths(true)`, parallelism 3, setup GetClosestPeers |
| Query `Timeout` (wall Instant) | flaky / rare | `AdvanceQueryClock` + 60s fuzz timeout; unit green |

## Weight strategy

- Preamble: `GetRecord` before any `ProtocolConfirmed` → empty-RT NotFound
- Setup steps 0–5: Connect+ProtocolConfirmed ×3 peers
- Steps 6–7: GetClosestPeers + FindNodeRes (disjoint progress)
- Steps 8–9: GetRecord + GetRecordEmpty
- Post-setup (sum 50): InjectResponse 8 / InjectWire 6 / GetRecord 5 /
  GetClosestPeers 5 / PutRecordTo 3 / GetProviders 3 / AdvanceJobs 2 /
  AdvanceQueryClock 3 / PutRecord 2 / StartProviding 2 / …

## Config

- `disjoint_query_paths(true)`, `parallelism=3`, kbucket size 4
- `query_timeout=60s`; Timeout via `AdvanceQueryClock` (not short wall Instant)
- Jobs enabled; `AdvanceJobs` → `fuzz_jobs_asap`
- Skip drain after query-start so InjectResponse sees live `QueryId`
- Deterministic `fuzz_local_peer_id` + `peer_pool` (ed25519 seeds; corpus-stable)
- End-of-run connected/query/kbucket budgets are `assert!` (release-safe)

## Assets

- Dict: `dicts/kademlia.dict`
- Seeds: prior + `seed_notfound_empty_rt`, `seed_disjoint_closest`,
  `seed_notfound_empty_res`

## Invariants (Phase 32)

- Contract: `AddAddress` peers remain in the RT after `ConnectionClosed`
  (`fuzz_routing_table_contains`; tracked `routed_peers` set)
- Assert on Disconnect when peer was successfully AddAddress'd; end-of-run check
- Unit: `add_address_retained_after_connection_closed`

## Remaining gaps

| Gap | Notes |
|-----|-------|
| `handler.rs` (standalone bin) | **~58% lines** after Phase 31 soak — see COVERAGE-kademlia_handler.md |
| Handler upgrade errs | Apply / NegotiationFailed / Io covered on handler bin (Phase 31) |
| Longer kbucket/store DoS soak | README still open |
