# peer_id_from_bytes — coverage baseline (complete)

Updated: 2026-10-13 after reject-seed pass + **100k** soak
(`-dict=dicts/peer_id.dict`, corpus includes new ASN.1 / Secp length seeds).

**Status: identity parsing stage complete.**

## Totals (`llvm-cov report`)

| File | Line cov | Δ vs prior | Notes |
|------|----------|------------|-------|
| `identity/src/rsa.rs` | **57.32%** | +4.45 | Wrong-tag / wrong-OID Errs now hit |
| `identity/src/ecdsa.rs` | **54.22%** | +3.02 | |
| `asn1_der` `der.rs` | **69.06%** | +4.31 | Nested DER |
| `identity/src/peer_id.rs` | **38.24%** | — | |
| `identity/src/error.rs` | **36.36%** | — | |
| `identity/src/ed25519.rs` | **28.45%** | — | |
| `identity/src/secp256k1.rs` | **26.56%** | — | |
| `identity/src/keypair.rs` | **17.97%** | +0.39 | Decode path hot; private Keypair API cold |

HTML (gitignored): `coverage/peer_id_from_bytes/html-identity/index.html`  
Regenerate: `./scripts/coverage_hints.sh peer_id_from_bytes`

## Gates (both green)

| Gap | Path | Hits | Seed / dict |
|-----|------|------|-------------|
| **1a** | `Asn1RawOid` wrong tag (`rsa.rs` ~186) | **1** | dict near-miss tags + mutations |
| **1b** | `Asn1OidRsaEncryption` wrong OID (~219) | **2** | `rsa_oid` dict + mutations |
| **1c** | `Asn1SubjectPublicKey` not BIT STRING (~277) | **1** | `seed_rsa_invalid_asn1` (0x03→0x04) |
| **2** | Secp256k1 `Err(e)` wrong length (`keypair.rs` ~708) | **3** | `seed_secp256k1_bad_len` (type=2, 16-byte data) |

## Decode-path baseline (hot)

| Site | Role |
|------|------|
| `PeerId::from_bytes` / `try_decode_protobuf` | Every input |
| `DecodingError::bad_protobuf` | Malformed protobuf wrapper |
| `unknown_key_type` | Invalid KeyType enum |
| Ed25519 / Secp / ECDSA `fuzz_dummy` | `--cfg fuzzing` bypass after sized payloads |
| RSA `try_decode_x509` Ok + ASN.1 Errs | Strict surface (no bypass) |
| `verify` early-return under fuzzing | Live for future Noise |

## Seeds / dict (checked in)

| Asset | Purpose |
|-------|---------|
| `seeds/peer_id_from_bytes/seed_*_{protobuf,peerid}` | Valid ed25519/rsa/secp256k1/ecdsa |
| `seed_rsa_invalid_asn1` | BIT STRING → OCTET STRING |
| `seed_secp256k1_bad_len` | KeyType=Secp + 16-byte payload |
| `dicts/peer_id.dict` | protobuf KeyType headers, ASN.1 tags, `rsa_oid` |

```bash
./scripts/merge_seeds.sh peer_id_from_bytes
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run peer_id_from_bytes -- \
  -dict=dicts/peer_id.dict -print_funcs=0
```

## Exclusions (expected cold)

| Path | Justification |
|------|----------------|
| Private `Keypair::{sign,from_protobuf_encoding,…}` | Out of scope for this target |
| `PublicKey::try_into_*` / serde / `from_str` | Not exercised |
| Real crypto `verify` backends | Bypassed under `--cfg fuzzing` |

## Next stack

Identity protobuf / ASN.1 decode fuzzing is done. Next when requested:

1. **Noise handshake** structured frame sequences  
2. Optional longer soak / OSS-Fuzz wiring for `peer_id_from_bytes`
