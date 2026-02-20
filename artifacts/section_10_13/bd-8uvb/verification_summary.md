# bd-8uvb: Overlapping-Lease Conflict Policy — Verification Summary

## Verdict: PASS

## Checks (6/6)

| Check | Description | Status |
|-------|-------------|--------|
| OLC-IMPL | Implementation with all required types | PASS |
| OLC-ERRORS | All 4 error codes present | PASS |
| OLC-FIXTURES | Fork log sample fixtures | PASS |
| OLC-INTEG | Integration tests cover all 4 invariants | PASS |
| OLC-TESTS | Rust unit tests pass (23) | PASS |
| OLC-SPEC | Specification with invariants and types | PASS |

## Artifacts

- Spec: `docs/specs/section_10_13/bd-8uvb_contract.md`
- Impl: `crates/franken-node/src/connector/lease_conflict.rs`
- Integration: `tests/integration/overlapping_lease_conflicts.rs`
- Fixtures: `artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json`
- Evidence: `artifacts/section_10_13/bd-8uvb/verification_evidence.json`

## Test Counts

- Rust unit tests: 23
- Python verification tests: 19
- Integration tests: 6 (deterministic, dangerous_halt, fork_log, classified, purpose_priority, no_conflict)

## Invariants Covered

- **INV-OLC-DETERMINISTIC**: Same conflict inputs → same resolution outcome
- **INV-OLC-DANGEROUS-HALT**: Dangerous-tier conflicts always halt; never silently resolved
- **INV-OLC-FORK-LOG**: Every conflict produces a ForkLogEntry with trace correlation
- **INV-OLC-CLASSIFIED**: Every conflict failure tagged with a stable error code
