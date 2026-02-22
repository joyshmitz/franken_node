# bd-3ptu Verification Summary

- bead: `bd-3ptu`
- support bead: `bd-3287`
- section: `10.18`
- verdict: **FAIL**
- checks: 49/51 passed (2 failed)
- generated_at: 2026-02-22T06:37:35.212618+00:00

## Scope
- `tests/security/vef_adversarial_suite.rs` (or fallback `tests/vef_adversarial_suite.rs`)
- `docs/security/vef_adversarial_testing.md`
- `artifacts/10.18/vef_adversarial_results.json`

## Detection Coverage
- `tamper` = 1
- `replay` = 1
- `stale_policy` = 1
- `commitment_mismatch` = 1

## Failed Checks
- `suite_symbol_error_assertion` — expect_err or matches!(..., Err(...))
- `suite_minimum_test_count` — 7 tests
