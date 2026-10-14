# Coverage: Loom concurrency (not cargo-fuzz)

Separate from libFuzzer action-sequence bins. Exhaustive scheduler
exploration of Behaviour↔Handler Shared-queue / QueryPool+pending-lane
races under `feature = "loom"`.

## Run

```bash
# Gossipsub Shared / Queue — Behaviour↔Handler clones
cargo test -p libp2p-gossipsub --features loom --lib queue::loom_tests

# Kad QueryBook + HandlerLane / DualHandlerPool
cargo test -p libp2p-kad --features loom --lib query::loom_tests
```

Do **not** pass `RUSTFLAGS="--cfg loom"` — that breaks transitive crates
(`event-listener`, etc.). Prefer the `loom` Cargo feature, which swaps only
this crate’s `Arc`/`Mutex`/`AtomicUsize` to `loom::sync`.

Keep each model small (2 threads, ≤2 messages / queries). Loom is exponential
in branching; these are not soak targets.

## Models (Phase 43d)

| Crate | Module | Surfaces |
|-------|--------|----------|
| `libp2p-gossipsub` | `queue::loom_tests` | Clone push/pop, capacity race, poll-pending+push, dual consumer |
| | | **Handler-shaped:** Publish cap vs Handler `poll_pop`, priority+non_priority dual-handler pop, dual Handler `poll_pending` + one push, `remove_data_messages` XOR Handler pop |
| `libp2p-kad` | `query::loom_tests` | `QueryBook` dual add / add vs take / ghost single-take |
| | | **Handler-shaped:** `HandlerLane` enqueue vs start+finish, dual-handler shared pool, stale QueryId finish |

## Last run (2026-10-13)

```text
libp2p-gossipsub queue::loom_tests — 8 passed
libp2p-kad       query::loom_tests — 6 passed
```

## Notes

- Production Gossipsub `Queue` is intentionally shared across Behaviour + Handlers via `Arc<Mutex<_>>` — Loom exercises that path (including priority-before-non_priority and AllQueuesFull-class capacity).
- Production Kad `QueryPool` / Handler are single-threaded (`Instant`, substreams). Models mirror id allocation + `pending_messages` dequeue ↔ pool finish and dual-connection fan-out — same race class as QueryId attribution bugs.
- Do not mix `--features loom` with the full lib test suite (non-loom tests may assume std sync).
