# multiaddr_structured — coverage status

Updated: 2026-10-13 after Unix input-bias fix + `DataLessThanLen` exclusion.

## Totals (`llvm-cov report`, multiaddr 0.19.1)

| File | Line cov | Notes |
|------|----------|-------|
| `protocol.rs` | **66.10%** | Up from 63.81% after `force_unix_arm` |
| `lib.rs` | (see HTML) | Constructors / serde mostly unused |
| `errors.rs` | (see HTML) | `Display`/`source` still cold |
| `from_url.rs` | 0.00% | Out of scope |

HTML (multiaddr-focused, gitignored):
`core/fuzz/coverage/multiaddr_structured/html-multiaddr/index.html`

Regenerate: `./scripts/coverage_hints.sh multiaddr_structured`

### Coverage Exclusions: `multiaddr_structured`

| Path | Justification | Delegated Target |
|---|---|---|
| `protocol.rs` (`DataLessThanLen`) | **Unreachable by design.** The assembler natively guarantees the varint length prefix matches the payload. | Covered by `multiaddr_binary` and `multiaddr_protocol_from_bytes` (raw byte mutation). |

## Gates

| Gate | Status | Evidence |
|------|--------|----------|
| Unix binary arm (code 400, `protocol.rs` 415–417) | **GREEN** | `Protocol::Unix` Ok path **818 hits** after `force_unix_arm` |
| `DataLessThanLen` (`split_at` line 294) | **Excluded** | Still **0 hits** — unreachable by design (see table) |

### Why dict failed for Unix

`arbitrary` consumes libFuzzer bytes as an entropy stream. Injecting `\x90\x03` via `multiaddr.dict` does not set `code == 400`. Structure-aware targets need input bias (bool toggle), not dictionary tokens.

Harness change: `force_unix_arm: bool` in `StructuredMultiaddr` overrides the first component to protocol code `400`, and `Protocol::from_bytes(&wire)` is called on every input so the arm is counted even when a later component fails full `Multiaddr::try_from`.

## Remaining cold paths (non-blocking)

| Path | Notes |
|------|-------|
| onion text `InvalidMultiaddr` edges | `multiaddr_text` |
| `errors.rs` `Display`/`source` | Optional |
| `from_url.rs` | Out of scope |

## Multiaddr scaffolding complete — next stack

1. **`peer_id_from_bytes` / multihash** — crypto + identity decode; may need `#[cfg(fuzzing)]` to bypass sig checks
2. **Noise handshake sequences** — structured frame sequences for stateful security transitions
