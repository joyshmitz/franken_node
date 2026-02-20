# bd-2k74: Per-Peer Admission Budgets — Verification Summary

## Verdict: PASS (6/6 checks)

## Implementation

`crates/franken-node/src/connector/admission_budget.rs`

- `AdmissionBudget`: per-peer limits across 5 dimensions (bytes, symbols, failed_auth, inflight_decode, decode_cpu)
- `AdmissionBudgetTracker`: stateful tracker with per-peer HashMap; runtime-reconfigurable budget
- `check_admission()`: evaluates all 5 dimensions, returns verdict + audit records
- `admit()`: check + update usage on success; no update on rejection (INV-PAB-BOUNDED)
- `record_failed_auth()` / `record_decode_start()` / `record_decode_complete()`: dimension-specific mutations
- `check_admission_stateless()`: convenience for one-shot checks without persistent state

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-PAB-ENFORCED | PASS | All 5 dimensions checked on every admission (28 unit tests, integration test) |
| INV-PAB-BOUNDED | PASS | Over-budget requests rejected; usage not updated on rejection |
| INV-PAB-AUDITABLE | PASS | BudgetCheckRecord per dimension with peer_id, timestamp, usage, limit, verdict |
| INV-PAB-DETERMINISTIC | PASS | Same state + config → same decision (unit + integration test) |

## Error Codes

All 6 error codes present: PAB_BYTES_EXCEEDED, PAB_SYMBOLS_EXCEEDED, PAB_AUTH_EXCEEDED, PAB_INFLIGHT_EXCEEDED, PAB_CPU_EXCEEDED, PAB_INVALID_BUDGET.

## Test Results

- 28 Rust unit tests passed
- 4 integration tests (1 per invariant)
- 18 Python verification tests passed
- Violation report fixture with 5 scenarios
