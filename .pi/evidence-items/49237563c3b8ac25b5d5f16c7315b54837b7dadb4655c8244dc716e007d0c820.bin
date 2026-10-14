# Task Plan: Fuzz harness deepening (post re-scrutiny)

## Goal
Implement highest-leverage deepening moves from the re-scrutiny pass.

## Next Step
User parked implementation. When un-parked: (1) swarm Strict+Signed lane,
(2) MemoryTransport `FragmentingIo`, (3) dual-lane `fuzzing-real-verify` soak;
or FOCUS soak residual cold relay stop/rate_limiter.

## Current Phase
Phase 44 analysis-only complete — five-vector principal re-scrutiny

## Phases

### Phase 1–8: Scrutiny → mplex_multiplexed_io
- **Status:** complete

### Phase 9: unsigned_varint streaming Uvi + all widths
- **Status:** complete

### Phase 10: Multistream dict + Message/LengthDelimited split
- **Status:** complete

### Phase 11: mplex/yamux coverage docs + structured sequences
- **Status:** complete

### Phase 12: Kad response inject + Gossipsub scoring
- [x] `InjectResponse` / `StructuredResponseKind` + GetProviders bias
- [x] Skip drain after query-start; 1 ms timeout
- [x] Gossipsub `with_peer_score` + topic params; PublishError-biased publish
- [x] Coverage: kad **52.98%**, gossipsub behaviour **47.07%**, peer_score **45.4%**
- **Status:** complete

### Phase 13: Swarm soak/FOCUS/seeds
- [x] Tight-limit + Always dial bias; paused-time idle timeout
- [x] `dicts/swarm.dict` + 6 seeds; FOCUS in `coverage_hints.sh`
- [x] Soak clean (cov 5572); connection-limits **68%**, Exceeded ~3.4k
- **Status:** complete

### Phase 14: Noise stub harness
- [x] `libp2p-noise` `fuzzing` → `fuzz_noise` (payload / LP / inbound XX mock)
- [x] `core/fuzz` target + `dicts/noise.dict` + 9 seeds
- [x] Build fixes: `proto` `pub(crate)`; owned `MockIo` for `'static`
- [x] Smoke 20k clean (cov 1858); FOCUS: framed **69%**, protocol **78%**, handshake **40%**
- [x] `COVERAGE-noise_handshake.md` + README
- **Status:** complete (superseded by Phase 16 for XX crypto)

### Phase 15: Re-scrutiny after Phases 9–14
- [x] Diff inventory vs prior recommendations
- [x] Read COVERAGE-* + newest harnesses
- [x] Deliver updated per-harness deepening directions
- **Status:** complete

### Phase 16: Noise XX structured crypto + outbound + post-handshake I/O
- [x] Snow initiator/responder peer over `futures_ringbuf` duplex
- [x] Arms 3–6 structured inbound/outbound; arm 7 post-handshake `Output`
- [x] Fuzz-biased certhash / muxer extension fields in identity payload
- [x] Identity verify remains stubbed under `--cfg fuzzing`
- [x] Seeds `seed_xx_*`, dict arm selectors, README + COVERAGE update
- [x] Unit smoke (`structured_xx_inbound_and_outbound_smoke`)
- **Status:** complete

### Phase 17: Gossipsub MessageTooLarge + handler codec
- [x] Root-cause: `MAX_DATA_BYTES=1024` truncated oversize below `max_transmit_size=4KiB`
- [x] Align `MAX_TRANSMIT_SIZE=256` < `MAX_DATA_BYTES`; MessageTooLarge ~1.64k hits
- [x] `FuzzAction::InjectWire` + `encode_structured_wire` via `GossipsubCodec`
- [x] `PublishBadSig` → `invalid_messages` → `reject_invalid_message` (~631)
- [x] IHAVE-biased weights + low `max_ihave_messages_heartbeat`; setup Graft
- [x] Unit tests + 5k smoke clean; protocol.rs ~51%, peer_score ~50%
- **Status:** complete

### Phase 18: Kad jobs / quorum NotFound / codec
- [x] Expose job `asap` under `feature = "fuzzing"`; `Behaviour::fuzz_jobs_asap`
- [x] Enable replication/publication/provider intervals; `AdvanceJobs` action
- [x] `PutRecordTo` + Quorum::All → `QuorumFailed` (~28); GetRecord empty RT → `NotFound` (~4)
- [x] `InjectWire` / `encode_structured_wire` via Kad `Codec` (~40k decodes)
- [x] jobs.rs **94%**, behaviour **62%** (was ~53%); unit tests + smoke clean
- **Status:** complete

### Phase 19: Yamux closing path
- [x] Root-cause: Closing only from Active via `poll_close`; EOF/GoAway → Cleanup
- [x] `fuzz_connection_ex(..., graceful_close)` + mock `hold_eof` (Pending vs EOF)
- [x] Stream half-close then `Connection::poll_close` → closing.rs
- [x] Closing-biased arm without remote GoAway; FIN/RST / tiny WindowUpdate
- [x] Raw-wire Arbitrary fallback so seeds hit graceful close
- [x] Seeds `seed_close_*` / credit / multi-fin; dict FIN/RST prefixes
- [x] closing.rs **0% → 90.62%**; connection **64.75%**; unit + 20s soak clean
- **Status:** complete

### Phase 20: Re-scrutiny after Phases 16–19
- [x] Deliver updated per-harness next moves
- **Status:** complete

### Phase 21: Swarm compose gossipsub + kad
- [x] `#[derive(NetworkBehaviour)]` tree: limits + gossipsub + kad MemoryStore
- [x] Enable `libp2p-swarm` `macros` feature in fuzz Cargo.toml
- [x] Keep Always dial (~⅔) + tight MutateLimits (1..=2); weights sum 48
- [x] Protocol actions: GossipSubscribe/Publish/Heartbeat; KadAddAddress/Get/Put/Bootstrap
- [x] On ConnectionEstablished: kad.add_address + gossipsub.add_explicit_peer
- [x] Seeds `seed_gossip_mesh` / `seed_kad_mesh` / `seed_proto_limits`; dict proto bands
- [x] FOCUS paths include gossipsub/kad behaviour+handler
- [x] Smoke INIT clean: cov **12605** (was ~5572); seeds ~110–140 ms each
- **Status:** complete

### Phase 22: Gossipsub reject_message(msg_id)
- [x] Author authenticity + `allow_self_origin(false)` + seqno `message_id_fn`
- [x] Deterministic peer_pool / `fuzz_local_peer_id`
- [x] `FuzzAction::RejectMsgId` + BlacklistPeer/RemoveBlacklistedPeer
- [x] Paths: BlackListedPeer, BlackListedSource, SelfOrigin; optional IHAVE promise
- [x] Structured kinds `PublishSelfOrigin` / `PublishFromPeer` + `encode_structured_wire_from`
- [x] Harness weights sum 40 (RejectMsgId 6); setup step-4 SelfOrigin+IHAVE
- [x] Seeds `seed_reject_*`; unit `action_seq_smoke` covers all three reasons
- [x] Smoke INIT clean: cov **5434** ft 21034
- **Status:** complete

### Phase 23: Mplex ResetStream + kad NotFound/disjoint
- [x] Mplex Arbitrary: ResetStream ~¾, tiny `max_buffer_len` 1..=2, dual-Open Data flood
- [x] Seeds `seed_reset_dual_flood` / `seed_reset_tiny_buf`; smoke cov 1087 clean
- [x] Kad `disjoint_query_paths(true)` + parallelism 3
- [x] Empty-RT GetRecord preamble; setup GetClosestPeers + FindNodeRes; GetRecordEmpty bias
- [x] Seeds `seed_notfound_*` / `seed_disjoint_closest`; unit `disjoint_closest_and_not_found_smoke`
- [x] FOCUS includes `query/peers/closest/disjoint.rs`; smoke cov **4835** clean
- **Status:** complete

### Phase 24: Yamux credit-exhaust / RST
- [x] `fuzz_connection_ex` credit-soak (64 bursts → `poll_write` Pending) before graceful close
- [x] Harness arm Credit/RST (3/10): multi-stream SYN, RST/FIN+RST/RST|ACK, orphan RST, huge WU
- [x] Structured RST bias; zero/tiny WindowUpdate variants
- [x] Seeds `seed_credit_*` / `seed_rst_ack`; unit `credit_soak_and_rst_smoke`
- [x] Single bin kept (no header/connection split); smoke cov **1555** clean
- **Status:** complete

### Phase 25: Swarm Noise XX transport
- [x] Fuzz-selectable whole-mesh Noise XX (~¾) vs plaintext (~¼)
- [x] Noise dial timeout 500 ms; higher Poll budgets for handshake RTTs
- [x] Keep Always dial + tight MutateLimits (auth upgrade races under denial)
- [x] Seeds `seed_noise_mesh` / `seed_noise_limits` / `seed_plaintext_mesh`
- [x] Smoke INIT clean: cov **14570** (was 12605 plaintext-only compose)
- **Status:** complete

### Phase 26: Release asserts + Kad peers + AllQueuesFull
- [x] Promote gossipsub/kad end-of-run budgets `debug_assert!` → `assert!`
- [x] Deterministic Kad `peer_pool` + `fuzz_local_peer_id` (mirror gossipsub)
- [x] Gossipsub `connection_handler_queue_len(1)`; setup Subscribe→Graft→Publish×2
- [x] Unit `all_queues_full_smoke`; note Behaviour drain cannot pop Shared Queue
- [x] Fix Graft-without-Subscribe setup gap (Graft dropped unsubscribed topics)
- **Status:** complete

### Phase 27: ConnectionHandler mock-stream drivers (Gossipsub + Kad)
- [x] `multistream-select::Negotiated::for_fuzzing` + `Stream::from_async_rw` (swarm `fuzzing`)
- [x] Gossipsub `fuzz_handler.rs` + behaviour wire; bin `gossipsub_handler`
- [x] Kad `fuzz_handler.rs`: inbound decode, outbound FindNode mock response, auto-respond standalone
- [x] Kad behaviour wire: live Handlers; InjectWire → feed; drain forwards `NotifyHandler` → HandlerIn
- [x] Units: FindNodeReq / GetProviders partial / outbound FindNodeRes; bin `kademlia_handler`
- [x] 90s soak + llvm-cov: gossipsub `handler.rs` **65%** lines; kad `handler.rs` **51%** lines
- **Status:** complete

### Phase 28: AdvanceQueryClock (Kad Behaviour query timeouts)
- [x] `QueryPool::fuzz_rewind_starts` + `fuzz_take_timed_out` (fires even `Waiting(Some)`)
- [x] `Behaviour::fuzz_advance_query_clock` → `query_timeout` → queued events
- [x] `FuzzAction::AdvanceQueryClock`; fuzz `query_timeout=60s`; Arbitrary weight 3/50 (≥60s biased)
- [x] Unit `advance_query_clock_times_out_get_closest`; kad fuzz 9/9
- **Status:** complete

### Phase 28b: Kad handler substream TimedOut
- [x] `OutboundDrive::DialUpgradeTimeout` → `DialUpgradeError(Timeout)` → Io(TimedOut) map arm
- [x] `OutboundDrive::SubstreamIdleTimeout` → 1ms Delay + unsettled oneshot → FuturesTupleSet Err arm
- [x] `kademlia_handler` Arbitrary bias (~⅜ TimedOut); units for both arms; llvm-cov confirms hits
- **Status:** complete

### Phase 29: Identify behaviour/handler harness
- [x] `libp2p-identify` `fuzzing` feature + `fuzz.rs` / `fuzz_handler.rs`
- [x] Structured kinds: MatchingPeer / MismatchedPeer / LargeLists / PushPartial / WithSignedRecord
- [x] Bins `identify_behaviour` + `identify_handler`; dict + seeds; unit smokes green
- [x] INIT: handler cov **1184**; behaviour cov **3216** (clean)
- **Status:** complete

### Phase 29b: Identify soak + llvm-cov FOCUS
- [x] 90s soaks: handler cov **2827** / 17k runs; behaviour cov **3953** / 2.9k runs
- [x] FOCUS lines: `handler.rs` 62–72%; `behaviour.rs` **73%**; `protocol.rs` **81%**
- **Status:** complete

### Phase 30: Gossipsub Strict+Signed (+ real-verify gate)
- [x] `fuzz_behaviour_strict_signed` + bin `gossipsub_strict_signed`
- [x] Structured MissingSig/From/Seqno, OversizedTopic, GarbageSig
- [x] `FuzzAction::SetTopicMaxSize`; topic0 max=100 (ConfigBuilder floor)
- [x] identity feature `fuzzing-real-verify` gates verify stub
- [x] Units 11/11; INIT cov **3991** clean
- **Status:** complete

### Phase 31: Handler upgrade-failure / MessageDropped arms
- [x] Gossipsub `HandlerFault`: DialUpgrade Timeout/NegFailed/Io, MaxSubstream×2, MessageDropped
- [x] Kad `OutboundDrive`: NegotiationFailed / Apply / Io (+ existing TimedOut arms)
- [x] Units: gossipsub fuzz 15/15; kad fuzz 14/14; INIT clean (gs 1882 / kad 1956)
- [x] Note: MaxSubstreamOutbound uses DialUpgradeError×5 (FullyNegotiated asserts)
- **Status:** complete

### Phase 31b: FOCUS soak + Strict InjectWire codec fix
- [x] 90s soaks: gs_handler **78.7%** lines; kad_handler **57.8%**; Strict ValidationError hot
- [x] `attach_live_inbound_mode` + defer topic max; EmptySequenceNumber **302**; TopicSize **290**
- **Status:** complete

### Phase 32: Protocol invariants
- [x] Gossipsub: after Disconnect + end-of-run — not in `all_mesh_peers`; `peer_score` finite
- [x] Kad: `fuzz_routing_table_contains`; AddAddress peers retained after ConnectionClosed
- [x] Units: gossipsub **17/17**; kad **15/15** (`disconnect_clears_mesh_*`, `add_address_retained_*`)
- **Status:** complete

### Phase 38: AutoNAT v1 + v2 client
- [x] `autonat_behaviour` / `autonatv2_client` bins + drivers + COVERAGE
- **Status:** complete

### Phase 39: QUIC handshake (closes Noise/TLS upgrade gap)
- [x] `libp2p-quic` `fuzzing` → `fuzz_quic` (8 arms)
- [x] In-memory `quinn_proto::Endpoint` Pair (no live UDP / Tokio)
- [x] Multiaddr parse, Config→QuinnConfig, PartialDecode, structured HS,
      cert DER corrupt, mid-wire flip, post-handshake bi-stream
- [x] PeerId cert binding assert on clean handshake
- [x] Bin `quic_handshake` + `COVERAGE-quic_handshake.md` + README soak
- [x] Unit smokes 3/3
- **Status:** complete

### Phase 40: Park + soak
- [x] User chose park over polish; later un-parked for Phase 41 polish
- **Status:** superseded by Phase 41

### Phase 41: Optional polish — v2 server + QUIC hole-punch
- [x] `autonatv2_server` bin + `fuzz_v2_server` (dial-back throttle / DialFailure)
- [x] QUIC arms 8–9: mock Provider hole-punch + `HolePunchBook` races
- [x] Extract `HolePunchBook` used by `GenTransport::dial` / poll
- [x] COVERAGE + README; unit smokes green
- **Status:** complete

### Phase 42: swarm Security::Quic compose
- [x] `Security::Quic` (~⅛) whole-mesh via `libp2p_quic::tokio::Transport`
- [x] Listen `/ip4/127.0.0.1/udp/0/quic-v1`; NewListenAddr captures QuicV1
- [x] `TransportFault` remains Noise/TLS-only (QUIC corrupt → `quic_handshake`)
- [x] `libp2p-quic` `tokio` + tokio `net` in core/fuzz; bin checks clean
- [x] COVERAGE / README / dict updated
- **Status:** complete

### Phase 43: WriteFault port + flush stall + circuit swarm
- [x] `WriteFault.flush_stall_every` on gossipsub/kad/identify mock I/O
- [x] Relay `BlackholeIo` + `inject_inbound_hop_ex` WriteFault; unit smoke
- [x] DCUtR hole-punch `FeedIo` WriteFault; extra pump rounds
- [x] New `swarm_circuit` bin (relay hop + client + DCUtR MemoryTransport)
- [x] COVERAGE-swarm_circuit.md + README row
- **Status:** complete

### Phase 43b: swarm_circuit FOCUS soak
- [x] 90s soak #1 exposed cold hop (0% inbound_hop) — missing external addr
- [x] Fix `add_external_address` + V1 + fat Poll + setup DialViaCircuit/Direct
- [x] 90s soak #2 clean: cov 15396; reservation/circuit/dcutr FOCUS warm
- [x] llvm-cov FOCUS: hop 64–69%, dcutr handler 76%, relay behaviour 61%
- **Status:** complete

### Phase 43c: relay_behaviour / dcutr_behaviour deny+teardown under WriteFault
- [x] Deny-biased Arbitrary + WriteFault hop/hole-punch; ConnectionId base `0xE000_0001`
- [x] Relay: tight caps + multi-conn FloodReservations → `DenyReservationReq` / Event warm
- [x] DCUtR: FloodDialFailure via OutboundConnectNegotiated + direct DialFailure → `AttemptsExceeded`
- [x] Soak #3 clean: relay cov 2723; dcutr cov 2280
- [x] llvm-cov: relay DenyReservationReq ~2.39k; dcutr AttemptsExceeded ~8.61k; behaviour 85%
- **Status:** complete

### Phase 43d: Loom Handler Shared-queue races (beyond QueryBook)
- [x] Gossipsub Handler-shaped: Publish cap vs poll, priority lanes dual-pop, dual poll_pending, remove_data XOR pop
- [x] Kad HandlerLane + DualHandlerPool + stale QueryId finish (keep QueryBook baselines)
- [x] `COVERAGE-loom_concurrency.md` updated; 8 + 6 loom tests green
- **Status:** complete

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Skip drain after query start | Keeps QueryId alive for InjectResponse |
| Enable peer scoring by default in fuzz | Was ~0% of peer_score.rs |
| Noise stub only (not full XX) | Phase 14; valid snow messages deferred to Phase 16 |
| Own MockIo bytes | `InboundConnectionUpgrade` requires `T: 'static` |
| Snow peer + ringbuf (not dual-Config only) | Allows fuzzing encrypted identity/extension protobuf |
| `PumpResult.done` | Avoid `async fn resumed after completion` on outbound finish |
| Lower max_transmit_size vs raise MAX_DATA | Keeps publish bodies bounded while still oversize |
| Codec InjectWire (not Handler poll) | Superseded Phase 27: live Handler + ChunkFeed for wire |
| queue_len(1) + sticky Shared Queue | AllQueuesFull without Handler; recovery via pump_handler after non-Publish |
| Kad deterministic ed25519 pool | Corpus / closer_peers correlation; was Keypair::generate each run |
| Empty inbound = Pending not EOF | Keeps long-lived Gossipsub inbound open for later feed.push |
| Arc<Mutex> ChunkFeed (not Rc) | `Stream::from_async_rw` requires `Send + 'static` |
| Job `asap` under fuzzing (not real sleep) | Deterministic; long intervals + cut delay |
| AdvanceQueryClock (not fuzz_set_now / Instant mock) | Instant::now scattered; rewind starts + force take |
| DialUpgradeTimeout + short Delay (not sleep-only) | Deterministic TimedOut without waiting full substreams timeout |
| `put_record_to` for QuorumFailed | Skips get-closest; fixed peers finish below quorum |
| `hold_eof` under graceful_close | Real EOF forces Cleanup; Closing needs Active |
| No GoAway on closing-biased arm | Remote GoAway → Cleanup, not Closing |
| Compose gossipsub+kad with limits (not limits-only) | Highest-leverage swarm depth; Noise deferred |
| Anonymous + Permissive gossip on swarm | Matches behaviour harness; avoids key/sign friction |
| Kad Mode::Server + clamped MemoryStore | Real handler negotiation without DoS unbounded store |
| Keep Always + MutateLimits dominant weights | Denial paths must stay warm after protocol arms added |
| Author + allow_self_origin(false) | Anonymous has no own_id; SelfOrigin needs Author/Signed |
| seqno BE message_id_fn | Correlates IHAVE `[mid_slot;8]` with publish seqno for promises |
| RejectMsgId dedicated action (not random PublishSelfOrigin) | Needs correlated PeerIds; random wire would mis-attribute `from` |
| Bias ResetStream + dual-Open floods | Single-stream read returns Data without buffering; overflow needs cross-stream |
| Always enable disjoint_query_paths in kad fuzz | Was 0% ClosestDisjointPeersIter; parallelism 3 seeds multiple paths |
| Empty-RT GetRecord preamble | Immediate NotFound before ProtocolConfirmed; denser than Timeout |
| Credit-soak before graceful close | Short wires exited Active before DEFAULT_CREDIT (256 KiB) exhausted |
| Keep single yamux bin | User declined header/connection split; deepen arms in-place |
| Whole-mesh Noise vs plaintext (not per-node) | Mixed security cannot complete upgrade on MemoryTransport |
| Bias Noise ~¾; keep plaintext lane | New auth surface warm; plaintext regresses compose paths |
| Identify dedicated bins before swarm compose | Critique #1 target; compose add-on after FOCUS soak |
| Direct inject outbound identify (not timer-only) | Delay(0)+noop_waker flaky; DialUpgradeError injected directly |
| Separate Strict+Signed bin (keep Permissive warm) | Dual corpus; real-verify is opt-in feature |
| Topic max ≥100 in ConfigBuilder; tighter via SetTopicMaxSize | Builder rejects <100; inbound oversize still reachable |
| Assert mesh/score on Disconnect + end-of-run (not only soft budgets) | Critique policy invariants; panic = finding |
| Kad RT retention via AddAddress set + fuzz_routing_table_contains | Documents real API: ConnectionClosed does not purge addresses |
| MaxSubstreamOutbound via DialUpgradeError not FullyNegotiated | Handler asserts if outbound already open |
| Skip gossipsub DialUpgrade Apply | Maps to `unreachable!()` — would abort fuzzer |
| Strict InjectWire uses Behaviour validation codec | Permissive attach hid EmptySeqno / TopicSize |
| Defer Strict topic max until after signed rejects | Signed MissingSeqno >100b misread as oversize |
| QUIC via quinn-proto Pair (not live UdpSocket) | Deterministic exec/s; mirrors quinn test harness |
| Export TLS `make_*_with_material` under fuzzing | Cert DER corrupt without duplicating verifier wiring |
| Phase 40: park + soak (no new scaffolding) | Five vectors + expansions architecturally complete; polish deferred |
| Phase 41: un-park v2 server + hole-punch | User requested optional polish #2 and #3 |
| HolePunchBook extract from GenTransport | Real dial_as_listener map logic fuzzable without live UDP |
| Phase 42: swarm Security::Quic (~⅛) | Integration-level QUIC under connection_limits; Tokio UDP trade-off accepted |
| TransportFault stays off QUIC meshes | Mid-handshake wire corrupt density remains in `quic_handshake` |
