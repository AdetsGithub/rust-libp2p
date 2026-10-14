# Coverage: `autonatv2_client`

Action-sequence fuzzer for AutoNAT **v2 client** `Behaviour` (candidates,
dial-back nonces, `TestOutcome`). Soft DoS clamps:

- `fuzz_candidate_count() ≤ max_candidates + 2`
- `fuzz_pending_nonces().len() ≤ MAX_ACTIONS + 2`
- Failed outcomes do not leave confirmed peers without matching support

## FOCUS setup

Connect×2 → `InjectPeerHasServerSupport` → candidate → `AdvanceProbeClock` →
`InjectDialBackNonce` → `InjectTestOutcome` (± success / ghost nonce).

Biased: dial-back nonce attribution, test-outcome races, `FloodCandidates`.

## Next llvm-cov targets

1. Nonce mismatch / stale dial-back after probe expiry.
2. Candidate eviction under `max_candidates`.
3. Server-support identify path vs injected support helper.
