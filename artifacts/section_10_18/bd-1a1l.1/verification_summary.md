# bd-1a1l.1 verification summary

## Context

Support lane targeted the remaining failure in:
- `vef_proof_service_support_perf::tests::mixed_backend_sequence_preserves_verification_integrity`

Observed root cause was backend-id substring overmatch in perf test event counting.

## Current code state

`tests/perf/vef_proof_service_support_perf.rs` now uses exact detail equality for backend-selected events (lines 133-146), preventing hash/double-hash substring collision.

## Validation (offloaded via rch)

Exact failing test path rerun:

```bash
rch exec -- cargo test -p frankenengine-node --test vef_proof_service_support \
  vef_proof_service_support_perf::tests::mixed_backend_sequence_preserves_verification_integrity \
  -- --exact --nocapture
```

Result:
- exit `0`
- `running 1 test`
- `test vef_proof_service_support_perf::tests::mixed_backend_sequence_preserves_verification_integrity ... ok`
- `test result: ok. 1 passed; 0 failed; ...`

Note: command still emits substantial pre-existing warning backlog unrelated to this support fix.

## Additional acceptance check

Full target rerun:

```bash
rch exec -- cargo test -p frankenengine-node --test vef_proof_service_support
```

Result:
- exit `0`
- `test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out`
