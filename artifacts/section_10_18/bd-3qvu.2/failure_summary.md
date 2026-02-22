# bd-3qvu.2 support findings

## Repro command

```bash
rch exec -- cargo test -p frankenengine-node --test vef_proof_service_support -- --nocapture
```

## Result

- Exit code: `101`
- Failing test: `vef_proof_service_support_perf::tests::mixed_backend_sequence_preserves_verification_integrity`
- Assertion failure (from remote output):
  - `assert_eq!(hash_selected, hash_jobs)`
  - left: `64`
  - right: `32`

## Root cause

`tests/perf/vef_proof_service_support_perf.rs` counts backend-selection events using substring checks:

- `entry.detail.contains(ProofBackendId::HashAttestationV1.as_str())`
- `entry.detail.contains(ProofBackendId::DoubleHashAttestationV1.as_str())`

In `crates/franken-node/src/vef/proof_service.rs`, event detail is emitted as:

- `detail: format!("backend={}", backend_id.as_str())`

And backend ids are:

- `hash_attestation_v1`
- `double_hash_attestation_v1`

So the hash selector overmatches double-hash events because `"double_hash_attestation_v1"` contains `"hash_attestation_v1"`.

## Minimal fix

Switch the perf test filter from substring matching to exact detail matching:

- hash side: `entry.detail == format!("backend={}", ProofBackendId::HashAttestationV1.as_str())`
- double side: `entry.detail == format!("backend={}", ProofBackendId::DoubleHashAttestationV1.as_str())`

This preserves semantics and removes the collision.
