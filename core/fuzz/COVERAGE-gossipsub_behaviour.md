# Coverage: `gossipsub_behaviour`

Last deepened: Phase 27 — live ConnectionHandler mock streams wired into
`fuzz_behaviour` (InjectWire → ChunkFeed; pump drains outbound queues).

Regenerate: `./scripts/coverage_hints.sh gossipsub_behaviour -- -dict=dicts/gossipsub.dict`

## Totals (`llvm-cov report`, focused)

Prior (Phase 17): behaviour **~47%**, peer_score **~50%**, protocol **~51%**,
handler **~7%**. Re-measure with `coverage_hints.sh` after longer soak.

Smoke INIT after Phase 22: **cov 5434** ft 21034 (was ~5344).

## Cold → hot

| Site | Before | After |
|------|--------|-------|
| `PublishError::MessageTooLarge` | 0 | ~1.64k (Phase 17) |
| `GossipsubCodec::decode` | ~0 | ~53k (Phase 17) |
| `invalid_messages` → `reject_invalid_message` | 0 | ~631 (Phase 17) |
| `reject_message(msg_id)` | **0** | driven by `RejectMsgId` (blacklist / SelfOrigin / promise) |
| `PublishError::AllQueuesFull` | **0** | unit `all_queues_full_smoke` + setup Publish×2 |

## RejectMsgId strategy

- Config: `MessageAuthenticity::Author(local_id)`, `allow_self_origin(false)`,
  `message_id_fn` = seqno BE bytes (correlates with IHAVE `[mid_slot; 8]`).
- Deterministic `peer_pool` + `fuzz_local_peer_id` for `from` fields.
- `RejectMsgId { reason, with_ihave_promise }`:
  - `BlackListedPeer` — blacklist propagation peer, then Publish
  - `BlackListedSource` — blacklist other peer, PublishFromPeer with that `from`
  - `SelfOrigin` — PublishSelfOrigin with local Author id as `from`
  - optional IHAVE first → gossip promise → `gossip_promises.reject_message`

## Weight strategy (sum = 40)

- Steps 0–2: Connect; 3: Subscribe; 4: Graft; 5–6: Publish×2 (AllQueuesFull);
  7: RejectMsgId SelfOrigin+IHAVE. Min actions = 8.
- Post-setup: InjectWire 8 | RejectMsgId 6 | InjectRpc 4 | Heartbeat 4 |
  Publish 4 | BlacklistPeer 3 | Connect 3 | Subscribe 2 | raw 2+2 |
  RemoveBlacklisted 1 | Disconnect 1
- `connection_handler_queue_len(1)`; end-of-run mcache budget is `assert!`

## Assets

- Dict: `dicts/gossipsub.dict`
- Seeds: prior + `seed_reject_msgid`, `seed_reject_ihave_self`, `seed_reject_blacklist`

## Invariants (Phase 32)

- After `Disconnect`: peer not in `all_mesh_peers` (`assert!`)
- End-of-run: disconnected peers stay out of mesh; `peer_score` finite when scoring on
- Unit: `disconnect_clears_mesh_and_keeps_finite_scores`

## Remaining gaps

| Gap | Notes |
|-----|-------|
| `handler.rs` (standalone bin) | **~79% lines** after Phase 31 soak — see COVERAGE-gossipsub_handler.md |
| Topic-specific size | Hot on `gossipsub_strict_signed` (Phase 30/31b) |
| MessageDropped / MaxSubstreamAttempts | Covered on handler bin — see COVERAGE-gossipsub_handler.md |
