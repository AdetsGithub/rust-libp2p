# Coverage: `swarm_orchestrator`

Action-sequence fuzzer for the **Swarm orchestrator** (not Behaviour-in-isolation).

Last deepened: Phase 42 — whole-mesh **QUIC (~⅛)** via Tokio UDP loopback
alongside Noise/TLS/plaintext; `TransportFault` remains Noise/TLS-only.

Regenerate:
`./scripts/coverage_hints.sh swarm_orchestrator -- -dict=dicts/swarm.dict -max_len=512`

## Setup

- 2–4 `Swarm`s over:
  - `MemoryTransport` + **Noise (~½) / TLS (~⅛) / plaintext (~¼)** + yamux, **or**
  - whole-mesh **QUIC (~⅛)** on `/ip4/127.0.0.1/udp/0/quic-v1` (no yamux; Tokio UDP)
- Whole-mesh transport choice (mixed security cannot interconnect)
- ~¼ of Noise/TLS meshes wrap channels with `TransportFault`
  (`DropAfterNoiseMsg1` / `FlipByteInMsg2`) before the security upgrade
- QUIC mid-handshake corrupt stays in `quic_handshake` — no `TransportFault` on UDP
- Behaviour tree (`#[derive(NetworkBehaviour)]`):
  - `libp2p-connection-limits::Behaviour` (limits mutated live)
  - `libp2p-gossipsub::Behaviour` (Anonymous + Permissive; `fuzz_heartbeat`)
  - `libp2p-kad::Behaviour<MemoryStore>` (`Mode::Server`, clamped store)
  - `libp2p-identify::Behaviour` (signed peer record; cache 16; push listen updates)
- On `ConnectionEstablished`: `kad.add_address` + `gossipsub.add_explicit_peer`
  (Identify opens `/ipfs/id/1.0.0` via handler `Delay::ZERO`)
- Drive: tokio `current_thread` + **paused time** + bounded polls
- Dial timeout: 500 ms (Noise/TLS/QUIC) / 200 ms (plaintext); idle 50 ms

## Totals

Smoke INIT after Phase 25 (Noise selectable): **cov 14570** ft 62462
(was **12605** plaintext-only compose). Re-measure after Identify compose.

## Hot denial / auth paths

| Site | Intent |
|------|--------|
| `check_limit` → `Exceeded` | Tight MutateLimits (1..=2) |
| `PeerCondition::Always` dials | Multi-conn + per-peer deny |
| Noise XX handshake | Auth upgrade under concurrent dial / denial |
| TLS mutual handshake | Cert/ALPN under dial+limits (~⅛) |
| QUIC whole-mesh | UDP loopback upgrade under dial+limits (~⅛) |
| Plaintext path | Regression / faster mesh |
| Identify push / Received | Active push + organic identify on connect |

## Actions / weights (sum = 50)

Noise inputs get higher Poll budgets (handshake RTTs).

Setup: Listen → Poll → dial mesh → GossipSubscribe → KadAddAddress → IdentifyPush.

## Invariants

- Connected-map ↔ `Swarm::is_connected` (bookkeeping)
- Identify `fuzz_discovered_peer_count` ≤ 16; addr count ≤ 160

## Assets

- Dict: `dicts/swarm.dict` (noise_on / plaintext_on / identify_band)
- Seeds: prior + `seed_noise_mesh`, `seed_noise_limits`, `seed_plaintext_mesh`

## Remaining gaps

- Longer RSS soak under Noise / QUIC + Always + MutateLimits + Identify
- llvm-cov FOCUS re-measure (identify + QUIC dial path via Swarm)
- Optional certhash / prologue variants on swarm Noise config
- QUIC meshes cost more exec/s than MemoryTransport — watch RSS under ASAN
