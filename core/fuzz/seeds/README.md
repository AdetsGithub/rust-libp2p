# Hand-written seed corpora

Checked-in golden inputs (`seed_*`). **Separate from** fuzzer-grown
`corpus/<target>/` (gitignored).

Merge into the live corpus before a soak (does not overwrite existing hashes):

```bash
cd core/fuzz
./scripts/merge_seeds.sh multiaddr_binary
./scripts/merge_seeds.sh peer_id_from_bytes
# or all targets:
./scripts/merge_seeds.sh
```

Regenerate:

```bash
./scripts/gen_multiaddr_seeds.sh
./scripts/gen_peer_id_seeds.sh   # ed25519 / rsa / secp256k1 / ecdsa + peerid bytes
```

Or pass seeds as an extra corpus directory to libFuzzer:

```bash
ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run multiaddr_binary \
  seeds/multiaddr_binary -- -dict=dicts/multiaddr.dict -print_funcs=0

ASAN_OPTIONS=symbolize=0 cargo +nightly fuzz run peer_id_from_bytes \
  seeds/peer_id_from_bytes -- -dict=dicts/peer_id.dict -print_funcs=0
```
