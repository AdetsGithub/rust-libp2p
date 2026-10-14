# Fuzzing `rust-libp2p` wire parsers

`cargo-fuzz` (libFuzzer) harnesses for the home-grown parsers that sit on
untrusted bytes. Targets live in `fuzz_targets/`; findings in `FINDINGS.md`.

## Prerequisites

```bash
rustup toolchain install nightly
rustup component add llvm-tools-preview --toolchain nightly
cargo install cargo-fuzz
```

The fuzz crate carries its own empty `[workspace]` table so it builds
independently of the parent `rust-libp2p` workspace. Build/run with the nightly
toolchain explicitly (`cargo-fuzz` otherwise defaults to stable here):

```bash
cargo +nightly fuzz build
```

## Targets

| Target | Covers | Invariants |
|---|---|---|
| `multiaddr_roundtrip` | `multiaddr` binary + text (combined) | binary round-trip HARD; text SOFT (Finding #1) |
| `multiaddr_binary` | binary `TryFrom` only | binary round-trip HARD |
| `multiaddr_text` | text `FromStr` + structured labels | text→binary HARD; Display→parse SOFT / feature-gated HARD |
| `multiaddr_protocol_from_bytes` | single `Protocol::from_bytes` | proto encode/decode HARD |
| `multiaddr_structured` | Arbitrary `(code, payload)` wire assembly | binary round-trip HARD |
| `peer_id_from_bytes` | `PeerId::from_bytes` + `PublicKey::try_decode_protobuf` (all key types) | decode never panics HARD; `to_peer_id` after Ok |
| `unsigned_varint_roundtrip` | `unsigned-varint` decode/encode + streaming `codec::Uvi` | encode→decode HARD; decode never panics HARD; chunked Uvi≡bulk |
| `mplex_frame_codec` | `libp2p-mplex` frame decoder (`Codec`) | decode never panics HARD; decode→encode→decode HARD |
| `mplex_multiplexed_io` | `libp2p-mplex` `Multiplexed` I/O (open/data/close/reset, MaxBufferBehaviour) | never panics / terminates HARD; watch RSS/OOM |
| `multistream_select_negotiation` | negotiation + `Message::decode` + `LengthDelimited` | never panics / terminates HARD; poll-budget HARD |
| `yamux_frame_header` | `yamux` 12-byte header + stateful `Connection` (EOF mock, clamped streams/window) | header lossless HARD; connection terminates HARD; watch RSS/OOM |
| `gossipsub_behaviour` | `libp2p-gossipsub` `NetworkBehaviour` action sequences (no transport) | never panics / terminates HARD; mcache soft budget; watch RSS/OOM |
| `kademlia_behaviour` | `libp2p-kad` `NetworkBehaviour` action sequences (no transport) | never panics / terminates HARD; kbucket/store soft budgets; watch RSS/OOM |
| `swarm_orchestrator` | N-swarm MemoryTransport Noise/TLS/plaintext **or** QUIC UDP (~⅛) + limits + gossipsub/kad/identify | never panics / terminates HARD; connected-map leak HARD; identify cache HARD |
| `swarm_circuit` | 1 hop relay + 2–3 clients (`relay::client` + DCUtR + Identify) over MemoryTransport/plaintext | never panics / terminates HARD; connected-map leak HARD |
| `noise_handshake` | `libp2p-noise` payload/LP + structured XX (snow) inbound/outbound + post-handshake `Output` | never panics / terminates HARD (poll budget) |
| `quic_handshake` | `libp2p-quic` multiaddr/Config + Pair handshake (+ cert/wire corrupt) + hole-punch book/Provider | never panics / terminates HARD (step budget) |
| `autonatv2_server` | AutoNAT v2 server Behaviour (dial-back throttle / DialFailure / status) | never panics / terminates HARD; dialing soft clamp |

Prefer the **split** `multiaddr_*` targets over `multiaddr_roundtrip` so binary and
text corpora do not dilute each other. After Finding #1 is fixed upstream, rebuild
with `--features hard_text_roundtrip` to make Display→`FromStr` a hard assert.

The `mplex_frame_codec` target drives the `pub(crate)` `Codec` through a byte-in
entry point (`libp2p_mplex::fuzz_frame_codec`) exposed only under the crate's
`fuzzing` feature.

The `mplex_multiplexed_io` target drives `io::Multiplexed` via
`libp2p_mplex::fuzz_multiplexed_io`: mock socket (EOF + optional fragmented
reads), clamped `max_substreams` / `max_buffer_len`, both
`MaxBufferBehaviour`s, held streams with read/write/close/drop. The harness
`Arbitrary` biases `ResetStream` + tiny buffers + dual-Open Data floods so the
overflow reset arm stays warm. Dict `dicts/mplex.dict`; seeds
`seeds/mplex_multiplexed_io/`.

The `yamux_frame_header` target depends on a local `yamux` 0.14.0 checkout at
`/home/adethya/Documents/yamux` with a `fuzzing` feature. `fuzz_connection` /
`fuzz_connection_ex` keep up to 32 streams alive and drive
`poll_read`/`poll_write` (credit / WindowUpdate). With `graceful_close` (default
for `fuzz_connection`), the mock holds EOF so the connection stays Active, then
**soaks send credit** until `poll_write` Pending, half-closes streams, and calls
`Connection::poll_close` → `connection/closing.rs` (remote GoAway / real EOF
instead go to Cleanup). Harness arms bias RST edges + tiny/huge WindowUpdate.
Clamps `max_num_streams=100` and receive window to `100 * 256 KiB` (yamux 0.14
has no `max_buffer_size`). Hunt OOM / window deadlocks / stream-ID panics under
ASan; treat libFuzzer **OOM** as a finding separately from Crash. See
`COVERAGE-yamux_frame_header.md`.

`gossipsub_behaviour` depends on `libp2p-gossipsub` with a `fuzzing` feature that
exposes `fuzz_behaviour` / `FuzzAction` (connect, InjectRpc, InjectWire,
publish, heartbeat, blacklist, `RejectMsgId`). Keeps live `Handler`s with
`Stream::from_async_rw` mock I/O: InjectWire feeds a `ChunkFeed`, and
`pump_handler` drains outbound queues (encode/flush). `MAX_TRANSMIT_SIZE=256`
so oversize publish hits `MessageTooLarge`. `RejectMsgId` drives
`reject_message(msg_id)` via blacklist / self-origin / IHAVE-promise. See
`COVERAGE-gossipsub_behaviour.md`. Sibling bin `gossipsub_handler` drives the
handler in isolation (`fuzz_handler_io`); see `COVERAGE-gossipsub_handler.md`.
Sibling bin `gossipsub_strict_signed` uses Strict + Signed (missing-field /
topic-size rejects); optional `--features fuzzing-real-verify` for real
`PublicKey::verify`. See `COVERAGE-gossipsub_strict_signed.md`.

`kademlia_behaviour` depends on `libp2p-kad` with a `fuzzing` feature
(`fuzz_behaviour` / `FuzzAction`: connect, protocol confirm, InjectWire,
InjectResponse, `put_record_to` Quorum::All, AdvanceJobs, bootstrap). Keeps
live `Handler`s with mock I/O; InjectWire feeds a `ChunkFeed`, and Behaviour
`NotifyHandler` events are forwarded as `HandlerIn` so response encode runs.
Config enables `disjoint_query_paths` (parallelism 3). See
`COVERAGE-kademlia_behaviour.md`. Sibling bin `kademlia_handler` drives the
handler in isolation (`fuzz_handler_io`); see `COVERAGE-kademlia_handler.md`.

`identify_behaviour` depends on `libp2p-identify` with a `fuzzing` feature
(`fuzz_behaviour` / `FuzzAction`: connect, InjectWire / InjectStructured,
InjectOutboundIdentify, Push, NewListenAddr, FailOutboundUpgrade). Keeps live
`Handler`s with mock I/O; structured kinds bias large listen_addrs/protocols
lists, peer-id mismatch discard, and signedPeerRecord. See
`COVERAGE-identify_behaviour.md`. Sibling bin `identify_handler` drives the
handler in isolation (`fuzz_handler_io`); see `COVERAGE-identify_handler.md`.

`peer_id_from_bytes` depends on `libp2p-identity` with `ed25519`/`rsa`/`secp256k1`/
`ecdsa`. Under cargo-fuzz (`--cfg fuzzing`), identity bypasses curve-point
rejection after a successful protobuf decode (RSA ASN.1 stays strict) and
`PublicKey::verify` always returns true for future Noise targets.

`swarm_orchestrator` drives **real** `Swarm`s (2–4 nodes) over either
`MemoryTransport` + **Noise (~½) / TLS (~⅛) / plaintext (~¼)** + yamux, or
whole-mesh **QUIC (~⅛)** on UDP loopback (`/ip4/127.0.0.1/udp/0/quic-v1`),
with a composed Behaviour (`connection-limits` + gossipsub + Kademlia +
Identify). Transport is chosen per input for the whole mesh. Action sequence
covers listen/dial(Always)/disconnect/close/mutate-limits/poll plus gossip
publish/heartbeat, kad get/put/bootstrap, and IdentifyPush. Encrypted meshes
get higher Poll budgets and a 500 ms dial timeout. Event-tracked peer maps
must stay aligned with `Swarm::is_connected` (leak invariant). See
`COVERAGE-swarm_orchestrator.md`. The fuzz crate `[patch.crates-io]` forces path
`libp2p-identity` so PeerId types unify with Swarm; `libp2p-swarm` needs the
`macros` feature for `#[derive(NetworkBehaviour)]`.

`noise_handshake` drives `libp2p-noise` (`fuzzing` → `fuzz_noise`): arm 0
protobuf `NoiseHandshakePayload`, arm 1 u16-BE frames, arm 2 raw inbound XX
mock, arms 3–6 structured XX via snow over `futures_ringbuf` (inbound +
outbound upgrades, fuzzed certhash/muxer extensions; flags **bit7** flips one
ciphertext byte), arm 7 post-handshake `Output` read/write. Identity `verify`
is stubbed under `--cfg fuzzing` unless `--features fuzzing-real-verify`
(dual-lane). Dict `dicts/noise.dict`; seeds `seeds/noise_handshake/`
(includes `seed_xx_inbound_corrupt_cipher`). See `COVERAGE-noise_handshake.md`.

New action-sequence bins (same pattern as gossip/kad/identify):
`relay_behaviour`, `dcutr_behaviour`, `request_response_behaviour`,
`tls_handshake`, `quic_handshake`, `autonat_behaviour`, `autonatv2_client`,
`autonatv2_server` — reservation/circuit/RequestId/TLS/QUIC/AutoNAT
dial-back surfaces with end-of-run soft DoS clamps. See
`COVERAGE-relay_behaviour.md`, `COVERAGE-dcutr_behaviour.md`,
`COVERAGE-request_response_behaviour.md`, `COVERAGE-tls_handshake.md`,
`COVERAGE-quic_handshake.md`, `COVERAGE-autonat_behaviour.md`,
`COVERAGE-autonatv2_client.md`, `COVERAGE-autonatv2_server.md`.
`swarm_orchestrator` can select TLS (~⅛) or QUIC (~⅛, Tokio UDP loopback)
as whole-mesh security alongside Noise/plaintext. QUIC mid-handshake corrupt
stays in `quic_handshake`; swarm `TransportFault` remains Noise/TLS-only.

**Loom (not cargo-fuzz):** Behaviour↔Handler Shared-queue / HandlerLane
QueryId concurrency models under `--features loom` — see
`COVERAGE-loom_concurrency.md` (Phase 43d expands beyond tiny QueryBook).

## Dictionaries & seeds

| Asset | Path | Notes |
|---|---|---|
| Multiaddr dict | `dicts/multiaddr.dict` | text tokens + raw protocol-code varints |
| PeerId / key dict | `dicts/peer_id.dict` | protobuf tags, KeyType, ASN.1 OID fragments |
| Yamux dict | `dicts/yamux.dict` | version/type/flags + GoAway + SYN/FIN/RST/Ping prefixes |
| Mplex dict | `dicts/mplex.dict` | varint header/flag patterns + Open/Data/Close/Reset |
| Gossipsub dict | `dicts/gossipsub.dict` | protobuf Rpc/control field tags + topic fragments |
| Kademlia dict | `dicts/kademlia.dict` | DHT MessageType tags + key/closerPeers fragments |
| unsigned-varint dict | `dicts/unsigned_varint.dict` | `0x80` continuations, terminators, Finding #2 edges |
| Multistream dict | `dicts/multistream.dict` | header/na/ls + length-prefixed golden frames |
| Swarm dict | `dicts/swarm.dict` | limit / Always-dial / memory-port edges |
| Noise dict | `dicts/noise.dict` | protobuf tags + u16-BE length edges + muxer/certhash fragments |
| Identify dict | `dicts/identify.dict` | Identify protobuf field tags + protocol/multiaddr fragments |
| Hand-written seeds | `seeds/<target>/seed_*` | git-tracked; see gen scripts below |
| Fuzzer-grown corpus | `corpus/<target>/` | gitignored; keep separate from seeds |

```bash
./scripts/merge_seeds.sh              # copy new seeds into corpus/
./scripts/gen_multiaddr_seeds.sh      # regenerate multiaddr seed_*
./scripts/gen_peer_id_seeds.sh        # regenerate ed25519/rsa/secp256k1/ecdsa seeds
```

## Running

Important environment note for this host: libFuzzer stalls to ~1 exec/s because it
hangs symbolizing newly-covered functions and crash stacks. Disable symbolization
to restore full throughput:

```bash
cd rust-libp2p/core/fuzz
./scripts/merge_seeds.sh

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multiaddr_binary -- \
  -dict=dicts/multiaddr.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multiaddr_text -- \
  -dict=dicts/multiaddr.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multiaddr_protocol_from_bytes -- \
  -dict=dicts/multiaddr.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multiaddr_structured -- \
  -dict=dicts/multiaddr.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run peer_id_from_bytes -- \
  -dict=dicts/peer_id.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run unsigned_varint_roundtrip -- \
  -dict=dicts/unsigned_varint.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multistream_select_negotiation -- \
  -dict=dicts/multistream.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run swarm_orchestrator -- \
  -dict=dicts/swarm.dict -print_funcs=0 -max_len=512 -len_control=0 -rss_limit_mb=4096

# Relay + DCUtR circuit stack (MemoryTransport / plaintext):
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run swarm_circuit -- \
  -dict=dicts/swarm_circuit.dict -print_funcs=0 -max_len=512 -len_control=0 \
  -rss_limit_mb=4096 -max_total_time=90
# FOCUS: ./scripts/coverage_hints.sh swarm_circuit -- -dict=dicts/swarm_circuit.dict -max_len=512

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run yamux_frame_header -- \
  -dict=dicts/yamux.dict -print_funcs=0 -max_len=65536 -rss_limit_mb=4096

# Gossipsub Behaviour (use -len_control=0 so -max_len is reached; log outside artifacts/):
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run gossipsub_behaviour -- \
  -dict=dicts/gossipsub.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096

# Gossipsub Strict + Signed (optional real verify):
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run gossipsub_strict_signed -- \
  -dict=dicts/gossipsub.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
# ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run gossipsub_strict_signed --features fuzzing-real-verify -- \
#   -dict=dicts/gossipsub.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096

# Kademlia Behaviour:
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run kademlia_behaviour -- \
  -dict=dicts/kademlia.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096

# Identify Behaviour / Handler:
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run identify_behaviour -- \
  -dict=dicts/identify.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run identify_handler -- \
  -dict=dicts/identify.dict -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096

# Noise — Lane A (stub verify) / Lane B (real verify + bit7 corrupt):
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run noise_handshake -- \
  -dict=dicts/noise.dict -print_funcs=0 -max_len=4096
# ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run noise_handshake --features fuzzing-real-verify -- \
#   -dict=dicts/noise.dict -print_funcs=0 -max_len=4096

# Relay / DCUtR / request-response / TLS:
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run relay_behaviour -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run dcutr_behaviour -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run request_response_behaviour -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run tls_handshake -- \
  -print_funcs=0 -max_len=4096

# AutoNAT v1 / v2 client / v2 server:
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run autonat_behaviour -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run autonatv2_client -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run autonatv2_server -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096

# QUIC (in-memory Pair + mock Provider hole-punch; no live net I/O):
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run quic_handshake -- \
  -print_funcs=0 -max_len=4096 -len_control=0 -rss_limit_mb=4096
```

### Sanitizers & debug assertions

- Default cargo-fuzz builds use **ASan**. Keep `ASAN_OPTIONS=symbolize=0` here.
- `core/fuzz/.cargo/config.toml` enables **`-C debug-assertions=on`** for fuzz builds.
- For pure-Rust panic/logic throughput comparison (no ASan), build/run with
  `cargo +nightly fuzz run <target> --sanitizer=none` (cargo-fuzz ≥0.12) or
  equivalent; compare exec/s against the ASan build.

### Coverage / stuckness

Requires `rustup component add llvm-tools-preview --toolchain nightly`.
Prioritize edges with 0 hits in protocol match arms / `Err` paths before adding
new targets. Tracked summaries:

- `COVERAGE-multiaddr_structured.md`
- `COVERAGE-peer_id_from_bytes.md`
- `COVERAGE-gossipsub_behaviour.md`
- `COVERAGE-gossipsub_strict_signed.md`
- `COVERAGE-kademlia_behaviour.md`
- `COVERAGE-identify_behaviour.md`
- `COVERAGE-identify_handler.md`
- `COVERAGE-swarm_orchestrator.md`
- `COVERAGE-mplex_multiplexed_io.md`
- `COVERAGE-yamux_frame_header.md`
- `COVERAGE-noise_handshake.md`
- `COVERAGE-quic_handshake.md`
- `COVERAGE-autonatv2_server.md`

(HTML under gitignored `coverage/`.)

```bash
# rebuild coverage binary, merge corpus profiles, HTML + Err-gap scan:
./scripts/coverage_hints.sh multiaddr_structured
./scripts/coverage_hints.sh peer_id_from_bytes
./scripts/coverage_hints.sh gossipsub_behaviour
./scripts/coverage_hints.sh kademlia_behaviour
./scripts/coverage_hints.sh mplex_multiplexed_io -- -dict=dicts/mplex.dict
./scripts/coverage_hints.sh yamux_frame_header -- -dict=dicts/yamux.dict -max_len=65536
./scripts/coverage_hints.sh swarm_orchestrator -- -dict=dicts/swarm.dict -max_len=512
./scripts/coverage_hints.sh noise_handshake -- -dict=dicts/noise.dict -max_len=4096

# live sancov / cmin:
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run peer_id_from_bytes -- \
  -dict=dicts/peer_id.dict -print_coverage=1 -print_funcs=0
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz cmin peer_id_from_bytes
```

To reproduce a saved crash:

```bash
ASAN_OPTIONS=symbolize=0 \
  ./target/x86_64-unknown-linux-gnu/release/<target> <path-to-artifact>
```

## Roadmap

- [x] `multiaddr` binary/text round-trip   → Finding #1
- [x] Split multiaddr targets + dict/seeds/structured Arbitrary
- [x] `peer_id_from_bytes` (protobuf / ASN.1) + identity `--cfg fuzzing` bypasses
- [x] `unsigned-varint` decode/encode      → Finding #2
- [x] `mplex` frame-header decoder (stateful) → clean after 15-min soak
- [x] `mplex_multiplexed_io` (`Multiplexed` open/data/close/reset + MaxBufferBehaviour) → smoke-clean
- [x] `multistream-select` negotiation (stateful) → clean after 15-min soak
- [x] `yamux` frame headers → clean after 15-min soak
- [x] `yamux` stateful connection deepen (EOF mock, DoS clamps, dict/SYN+Ping seeds)
- [x] `yamux` closing path (`poll_close` / closing.rs **90%**; FIN/RST / credit seeds)
- [x] Yamux soak launched (`-max_len=65536`, RSS watch via soak.log)
- [x] `gossipsub_behaviour` action-sequence harness + smoke 5k
- [x] Longer gossipsub soak (`-max_len=4096 -len_control=0` → `logs/`)
- [x] `kademlia_behaviour` action-sequence harness + smoke 5k
- [x] Coverage-bias Arbitrary + structured inject (gossipsub control / kad DHT arms)
- [x] `swarm_orchestrator` N-swarm MemoryTransport harness + smoke 500
- [x] Longer swarm_orchestrator soak / llvm-cov FOCUS
- [x] Compose connection-limits + gossipsub + kad on swarm_orchestrator mesh
- [x] Compose Identify into swarm_orchestrator (+ IdentifyPush / cache assert)
- [x] Gossipsub `reject_message(msg_id)` (blacklist / self-origin / IHAVE promise)
- [x] Mplex ResetStream bias + kad NotFound/disjoint density
- [x] Yamux credit-exhaust / RST edges (single bin; soak send credit)
- [x] Swarm Noise XX transport (fuzz-selectable vs plaintext; Always + limits)
- [ ] Longer kademlia soak / kbucket+store DoS watch
- [ ] Longer swarm Noise RSS soak + llvm-cov FOCUS re-measure
- [x] Noise stub harness (payload / LP frames / inbound XX mock)
- [x] Noise handshake structured XX crypto sequences
- [ ] CI integration (OSS-Fuzz)
- [x] Draft security advisories for Findings #1 and #2 (`advisories/`)
- [ ] File / follow up upstream (SA-001 new report; SA-002 → existing #73/#68)
- [ ] Enable `hard_text_roundtrip` after Finding #1 fix
