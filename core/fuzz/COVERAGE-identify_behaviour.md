# Coverage: `identify_behaviour`

Last deepened: Phase 29 — Identify Behaviour + live Handler mock-I/O.
Last measured: 90s soak + `coverage_hints.sh` (2026-10-13).

Regenerate: `./scripts/coverage_hints.sh identify_behaviour -- -dict=dicts/identify.dict -max_len=4096`

## Soak (90s)

- `#2935 DONE cov: 3953 ft: 13495 corp: 283/38Kb lim: 4096 exec/s: 32 rss: 409Mb`

## Totals (`llvm-cov report`, focused)

| File | Regions | Functions | Lines |
|------|---------|-----------|-------|
| `behaviour.rs` | **66.26%** | 70.21% | **72.85%** |
| `handler.rs` | **65.00%** | 64.71% | **72.17%** |
| `protocol.rs` | 63.95% | 87.50% | 72.11% |
| `fuzz.rs` | 93.83% | 95.65% | 93.77% |

Zero-hit `Err` lines in `behaviour.rs`: none.

## Surface

- `protocols/identify/src/fuzz.rs` → `fuzz_behaviour` / `FuzzAction`
- Live `Handler` per peer with inbound-push `ChunkFeed`
- Structured kinds: MatchingPeer, MismatchedPeer, LargeLists, PushPartial, WithSignedRecord
- Swarm hooks: NewListenAddr (push_listen_addr_updates), ExternalAddrConfirmed, AddressesChanged
- Soft budgets on listen_addrs / protocols in `Event::Received`

## Weight strategy

- Setup steps 0–5: Connect×2 → MatchingPeer identify → LargeLists → NewListenAddr → Push
- Free actions bias LargeLists + InjectOutboundIdentify / InjectStructured
- FailOutboundUpgrade for IdentificationError

## Next

- Optional: add Identify to `swarm_orchestrator` FuzzBehaviour compose
- Residual list: gossipsub Strict+Signed; handler upgrade-failure / MessageDropped
