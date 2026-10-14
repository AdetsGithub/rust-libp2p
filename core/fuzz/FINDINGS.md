# Fuzzing findings — rust-libp2p wire parsers

Harnesses live in `core/fuzz/fuzz_targets/`. Run with the environment workaround
documented in `README-fuzzing.md` (symbolization off):

```bash
cd rust-libp2p/core
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run <target> -- -print_funcs=0
```

---

## Finding #1 — `multiaddr`: binary→text round-trip is not total for `Dns*` / `Unix`

- **Component:** `multiaddr` crate (`multiformats/rust-multiaddr`), v`0.19.1` (latest
  published; `master` identical). Re-exported by `libp2p-core` as `multiaddr::Multiaddr`.
- **Class:** Encode/decode asymmetry (serialization round-trip violation). Not memory-unsafety.
- **Reachability:** Untrusted wire bytes. Any peer that sends a binary multiaddr
  (e.g. inside an identify/peer-record payload, DHT record, or any protocol that
  ships `Multiaddr` bytes) controls the `Dns*` label contents.
- **Found by:** `multiaddr_roundtrip` fuzz target, within seconds (~a few thousand execs).

### Summary

The binary decoder accepts **any UTF-8** as the value of a string-valued protocol
(`Dns`, `Dns4`, `Dns6`, `Dnsaddr`, and `Unix`), including the `/` separator and
empty strings. `Display` writes that value verbatim, but `FromStr` tokenizes the
textual form on `/`. Consequently a `Multiaddr` that decodes cleanly from bytes can
produce a `Display` string that **fails to re-parse**. The common downstream idiom
`addr.to_string().parse::<Multiaddr>()` therefore errors (or panics via `.unwrap()`)
on attacker-controlled input.

The reverse round-trip — **binary → binary** — is stable and canonical; only the
text projection is lossy.

### Minimal reproducer

3 bytes: `36 01 2f` → protocol code `0x36` = 54 (`dns4`), varint length `1`, value `/`.

```text
input bytes: [0x36, 0x01, 0x2f]
Multiaddr::try_from(bytes)  -> Ok([Dns4("/")])
addr.to_vec()               -> [0x36, 0x01, 0x2f]        # binary round-trip: stable
addr.to_string()            -> "/dns4//"
"/dns4//".parse::<Multiaddr>() -> Err(UnknownProtocolString(""))
```

Standalone repro project: `/tmp/marepro` (depends on `multiaddr = "=0.19.1"`).
libFuzzer artifacts: `core/fuzz/artifacts/multiaddr_roundtrip/` (`min.bin` = 3-byte case).

### Root cause (upstream `src/protocol.rs`, `src/lib.rs` on master)

- Binary decode accepts arbitrary UTF-8, no structural validation:
  ```rust
  // Protocol::from_bytes
  Ok((Protocol::Dns4(Cow::Borrowed(str::from_utf8(data)?)), rest))
  ```
- `Display` emits the label verbatim:
  ```rust
  Protocol::Dns4(s) => write!(f, "/{s}"),
  ```
- `FromStr` splits on `/`, so an embedded (or leading/trailing) `/` desynchronizes
  the tokenizer:
  ```rust
  let mut parts = input.split('/').peekable();
  // ... Protocol::from_str_parts(&mut parts) ...
  ```
  `"/dns4//".split('/')` = `["", "dns4", "", ""]`; after the leading `""` and
  `dns4` + name `""`, the trailing `""` is parsed as a protocol name →
  `UnknownProtocolString("")`.

### Impact

- Any code doing `addr.to_string().parse()` (round-tripping through text — common in
  logging, config, allowlists, and cross-language interop) breaks on hostile input.
  With `.unwrap()`/`.expect()` this is a remotely triggerable panic / DoS.
- Text and binary representations disagree about which addresses are valid, which can
  create parser-differential / filter-bypass conditions between components that use
  the text form vs. the binary form.

### Suggested fix (for the issue)

Make the two representations agree. Options, in order of preference:
1. Reject structural/invalid characters (`/`, control chars, empty labels) in `Dns*`
   values at **binary decode** time, so the binary parser doesn't accept addresses
   the text parser can't represent.
2. Or make the text form unambiguous (percent-encode `/` in string labels on
   `Display`, decode on parse) so `Display`→`FromStr` is total.

Option 1 is the smaller, safer change and matches the spec intent (DNS labels do not
contain `/`).

### Status / next action

- [x] Duplicate check (2026-10-13): no matching issue on `multiformats/rust-multiaddr`.
- [x] Draft security advisory: `advisories/SA-2026-001-multiaddr-binary-text-asymmetry.md`
- [x] Private report text ready: `advisories/PRIVATE_REPORT-SA-2026-001-multiaddr.md`
- [ ] Submit private GHSA on `multiformats/rust-multiaddr` (+ optional rust-libp2p).
- [ ] Offer the `multiaddr_roundtrip` harness as a regression test / `fuzz/` PR.

---

## Finding #2 — `unsigned-varint`: over-range final byte is truncated, not rejected (overflow + malleability)

- **Component:** `unsigned-varint` crate (`paritytech/unsigned-varint`), v`0.8.0`
  (resolved in `rust-libp2p` `Cargo.lock`). Underpins every libp2p length prefix
  and protocol code.
- **Class:** Integer overflow / wraparound + encoding malleability (non-canonical
  acceptance). Not memory-unsafety (no panic — the shift amount stays in range).
- **Reachability:** Untrusted wire bytes. Varints prefix virtually everything:
  multiaddr protocol codes & value lengths, multistream-select frame lengths,
  yamux/mplex header fields, protobuf-style delimiters.
- **Found by:** `unsigned_varint_roundtrip` fuzz target, within ~268 execs.

### Summary

`decode::u64` (and, by the same mechanism, `u8`/`u16`/`u32`/`u128`) accepts a
maximal-length encoding whose **final** byte carries bits beyond the target type's
width. Those bits are silently dropped (`n |= k << (i*7)` truncates), so:

1. A value that **overflows** the type is accepted and **wraps** instead of
   returning `Error::Overflow`.
2. **Multiple distinct byte strings decode to the same integer** (malleability),
   even though the library explicitly rejects other non-canonical forms with
   `Error::NotMinimal`.

### Reproducers (standalone project `/tmp/uvrepro`, `unsigned-varint = "=0.8.0"`)

```text
decode::u64([80 80 80 80 80 80 80 80 80 02]) -> Ok(value = 0)
    # 2 << 63 overflows u64; expected Err(Overflow), got wraparound to 0.

decode::u64([80 80 80 80 80 80 80 80 80 01]) -> value = 9223372036854775808
decode::u64([80 80 80 80 80 80 80 80 80 03]) -> value = 9223372036854775808
    # Two different encodings, identical value => malleable / non-canonical.
```

Fuzzer-minimized crash (10 bytes): `f7 ff f7 bf ff a7 bf ff a7 0f`, which decodes
to `12105391299603857399` but re-encodes canonically to `…a7 01` (last byte differs).
Artifacts: `core/fuzz/artifacts/unsigned_varint_roundtrip/` (`min.bin`).

### Root cause (upstream `src/decode.rs`)

The `decode!` macro returns as soon as it sees a terminal byte, and only checks the
`Overflow` bound for *continuation* bytes:

```rust
for (i, b) in $buf.iter().cloned().enumerate() {
    let k = $typ::from(b & 0x7F);
    n |= k << (i * 7);               // <-- bits above the type width are dropped here
    if is_last(b) {
        if b == 0 && i > 0 { return Err(Error::NotMinimal); }
        return Ok((n, &$buf[i + 1..]));   // <-- returns before the Overflow check
    }
    if i == $max_bytes { return Err(Error::Overflow); }
}
```

For a `B`-bit type, `max_bytes = ceil(B/7) - 1`, so the terminal byte at
`i == max_bytes` can represent only `B - 7*max_bytes` bits
(`u8`:1, `u16`:2, `u32`:4, `u64`:1, `u128`:2). Any higher bits in that byte are
truncated with no error.

### Impact

- **Length-prefix / size confusion:** an attacker-chosen varint can decode to a
  different (e.g. much smaller, or zero) length than its byte-length implies,
  desynchronizing framed readers.
- **Malleability:** canonical-form assumptions (hashing/dedup/equality over the raw
  bytes, signatures over serialized forms) break because distinct encodings alias to
  one value — directly contradicting the crate's own `NotMinimal` guarantee.

### Suggested fix (for the issue)

On the terminal byte, verify no out-of-range bits are set before accepting, e.g.
reject when `i == max_bytes && (b >> (B - 7*max_bytes)) != 0` → `Error::Overflow`.

### Status / next action

- [x] Duplicate check (2026-10-13): **already upstream** —
      [issue #73](https://github.com/paritytech/unsigned-varint/issues/73) (open),
      fix [PR #68](https://github.com/paritytech/unsigned-varint/pull/68) (open, unmerged).
      Still present in published `0.8.0`.
- [x] Draft security advisory (duplicate-aware):
      `advisories/SA-2026-002-unsigned-varint-silent-overflow.md`
- [ ] Comment on #73 with malleability pair + libp2p blast radius; help land PR #68.
- [ ] Add `unsigned_varint_roundtrip` as a regression harness once fixed.
