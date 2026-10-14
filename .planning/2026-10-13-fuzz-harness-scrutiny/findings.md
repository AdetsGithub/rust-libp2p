# Findings — fuzz harness re-scrutiny (post Phases 16–19)

## Inventory
16 bins under `core/fuzz/fuzz_targets/`; 10 dicts; COVERAGE for noise/gossip/kad/yamux/mplex/swarm/multiaddr/peer_id.

## Closed since last scrutiny
| Item | Evidence |
|------|----------|
| Noise XX structured + outbound + post-io | handshake/framed ~90%; io.rs ~66% |
| Gossipsub MessageTooLarge + InjectWire | MessageTooLarge ~1.6k; codec ~53k |
| Kad jobs + QuorumFailed/NotFound + InjectWire | jobs ~94%; behaviour ~62% |
| Yamux closing.rs | closing ~91%; cleanup ~93% |

## Closed this session
| Item | Evidence |
|------|----------|
| Swarm compose limits+gossipsub+kad | Phase 21; smoke cov 12605; 3 proto seeds |
| Gossipsub `reject_message(msg_id)` | Phase 22; RejectMsgId + seeds; INIT cov 5434 |
| Mplex ResetStream bias | Phase 23; dual-Open floods + tiny buf; smoke cov 1087 |
| Kad NotFound + disjoint paths | Phase 23; disjoint_query_paths; smoke cov 4835 |
| Yamux credit-exhaust / RST | Phase 24; driver soak + Credit/RST arm; cov 1555 |
| Swarm Noise XX selectable | Phase 25; INIT cov 14570; noise+plaintext seeds |
| Release assert! + Kad peer_pool + AllQueuesFull | Phase 26; unit smokes green; Graft needs Subscribe first |
| Gossipsub Handler mock-I/O | Phase 27; fuzz_handler + behaviour wire; partial-read unit green |
| Kad Handler mock-I/O | Phase 27b; inbound+outbound; NotifyHandler→HandlerIn bridge; units green |

## Critique deltas (case_417445b228)
| Claim | Verdict |
|-------|---------|
| Stop protobuf seeds; deepen architecture | Agree |
| AllQueuesFull needs handler driver | Partially wrong — error is Behaviour-level; queue *recovery* needs Handler |
| FaultyIo / InjectWireFrag on Behaviour | Low ROI — codec already hot; Handler mock is the lever |
| Virtual-time query timeout via fuzz_set_now | Prefer AdvanceQueryClock (Instant::now scattered) |
| Identify next after handlers | OK as #2; don't dilute before handler driver |

## Closed Phase 29
| Item | Evidence |
|------|----------|
| Identify harness (was unfuzzed) | `identify_behaviour` + `identify_handler`; INIT cov 3216 / 1184 |
| Large addr/protocol lists | `StructuredIdentifyKind::LargeLists` (64 addrs + 64 protos) |
| Peer-id mismatch / signed record | MismatchedPeer + WithSignedRecord kinds; unit smokes |

## Closed Phase 39
| Item | Evidence |
|------|----------|
| QUIC upgrade fuzz (was multiaddr-only) | `quic_handshake` + `fuzz_quic`; unit 3/3; in-memory Pair |
| Mid-handshake corrupt vs Noise/TLS | Arms 5–6 cert DER / wire flip |
| Dual-lane PeerId binding | Clean HS asserts `certificate::parse` PeerId |

## Closed Phase 41
| Item | Evidence |
|------|----------|
| AutoNAT v2 server dial-back throttle | `autonatv2_server` + injectors; smokes 2/2 |
| QUIC hole-punch without live UDP | Arms 8–9 mock Provider + `HolePunchBook`; smokes 4/4 |
| Book shared with GenTransport | `hole_punching::HolePunchBook` used by dial/poll |

## Closed Phase 42
| Item | Evidence |
|------|----------|
| swarm QUIC compose | `Security::Quic` ~⅛; Tokio UDP listen/dial; bin checks clean |
| TransportFault scope | Noise/TLS only; QUIC corrupt remains `quic_handshake` |

## Remaining depth gaps (soak only)
| Target | Gap |
|--------|-----|
| `swarm_orchestrator` | FOCUS soak QUIC meshes (exec/s / RSS under ASAN) |
| `quic_handshake` | FOCUS soak arms 8–9; draft-29 |
| AutoNAT v1/v2 client+server | FOCUS soak; stream codec still cold by design |
| `relay_behaviour` / `dcutr_behaviour` | Phase 43c: deny/AttemptsExceeded warm; stop/outbound still cold |
| `gossipsub_strict_signed` / `noise_handshake` | Optional `fuzzing-real-verify` dual-lane |
| Cross-cutting | OSS-Fuzz CI wiring |

## Phase 44 — Principal five-vector re-scrutiny (analysis-only)

### Verdict
Harnesses cleared the classic protobuf / handshake wall. Gaps that remain are
**composition + scheduling realism**, not missing `Arbitrary` enums.

### Per-vector status
| Vector | Status | Residual |
|--------|--------|----------|
| 1 State machine | Mature | Swarm still Anonymous+Permissive; score-decay virtual time soft |
| 2 Network/I/O | Mature on behaviour bins | Swarm `FaultyIo` = Noise frames only; no FragmentingIo / yamux reorder |
| 3 Async/timing | Mature | Kad `AdvanceQueryClock` + swarm `time::pause`; gossip Heartbeat is action not clock |
| 4 Crypto bypass | Mature dual-lane | Default stub hides BadSignature; real-verify not default soak |
| 5 Invariants | Strong on gossip/kad/identify/swarm | Mesh lower-bound soft; relay rate_limiter unasserted |

### Highest-leverage remaining patches (snippets, not applied)
1. Selectable Strict+Signed lane in `swarm_orchestrator`
2. `FragmentingIo` wrapper on MemoryTransport (partial read/write + reorder buffer)
3. Dual-lane CI soak with `--features fuzzing-real-verify`

### Next targets (under-tested relative to maturity)
1. Relay `rate_limiter` + stop protocols (cold after 43c)
2. request-response composed into swarm (ghost/stale IDs under real mux)
3. Gossipsub peer-score decay / graylist under virtual time across multi-swarm

## Phase 43 — Principal re-scrutiny residuals (architecture, not soak)

| Gap | Evidence | Leverage | Status after 43–43d |
|-----|----------|----------|---------------------|
| Relay/DCUtR write-side infinite-bandwidth | `BlackholeIo`/`FeedIo` | High | **Closed** — WriteFault+flush_stall |
| No circuit-stack swarm compose | limits+gossip+kad+identify only | High | **Closed** — `swarm_circuit` |
| `poll_flush` never stalls | WriteFault flush Ready | Medium | **Closed** — `flush_stall_every` |
| Swarm gossip Anonymous+Permissive | Strict lane behaviour-only | Medium | **Still open** |
| Loom tiny vs Handler races | QueryBook-only | Parked | **Expanded** Phase 43d |
| QUIC `TransportFault` not on swarm | By design | Low | Unchanged |

## Mature / park
unsigned_varint, multistream (dict+LD+interactive), peer_id stage, multiaddr
scaffolding (~66%). Scaffolding for five vectors + expansions + polish done.

## Phase 33 re-scrutiny (Principal review)

### Verdict
Harnesses are **past** the classic protobuf wall. Remaining value is in deeper state-machine / I/O scheduling / crypto-realism / cross-behaviour composition — not more raw byte injectors.

### Still-open architectural gaps
1. **Write-side I/O**: `ChunkIo`/`BlackholeIo` always `Poll::Ready(Ok(len))` — no backpressure, partial write, or flush stall → outbound codec / queue-drain under pressure cold.
2. **Kad query confusion**: `InjectResponse` always binds `active_queries.last()` — cannot stress stale/mismatched `QueryId` or out-of-order responses across concurrent queries.
3. **Gossipsub PX / Prune peers**: `structured_rpc(Prune)` always `peers: vec![]` — peer-exchange graft candidates unexercised.
4. **InjectRpc contract skip**: Behaviour path synthesizes `invalid_messages: Vec::new()` — codec rejection vs behaviour rejection divergence untested on that arm.
5. **Identify time/cache**: 3600s interval never advanced; no assert that MismatchedPeer never yields Identified / cache size ≤ `with_cache_size(16)`.
6. **Swarm compose**: Identify not in `FuzzBehaviour`; Noise BadSignature cold under stubbed verify.
7. **Concurrency**: single-threaded poll loops; no Loom / multi-waker / true parallel handler polls.

### Recommended next targets (new surface)
1. `libp2p-relay` / DCUtR circuit state machine
2. `libp2p-request-response` (generic codec + inbound/outbound race)
3. `libp2p-tls` or QUIC upgrade (parallel to Noise depth)
