# bd-1nab Contract: Federated Privacy Leakage Risk Control

## Goal

Prevent federated telemetry leakage by enforcing strict differential privacy budgets, secure aggregation guarantees, and independent verifier validation without raw-data exposure.

## Quantified Invariants

- `INV-FPL-BUDGETS`: Every telemetry channel has a configured epsilon budget with default `epsilon <= 1.0`.
- `INV-FPL-EXHAUSTION`: When a channel budget is exhausted, the `(N+1)`th emission is blocked with a stable error.
- `INV-FPL-SECURE-AGGREGATION`: Secure aggregation runs with at least 10 participants and individual contributions are not recoverable from aggregate output.
- `INV-FPL-EXTERNAL-VERIFIER`: External verifier API can confirm budget compliance/exhaustion using only aggregate artifacts and budget parameters.
- `INV-FPL-RESET-AUTHZ`: Unauthorized privacy-budget reset attempts are denied and logged.

## Determinism Requirements

- Re-running verification on identical federation report input yields identical aggregate metrics and verdict.
- Channel order does not affect aggregate privacy-budget outcomes.
- Adversarial perturbation that bypasses `(N+1)` blocking deterministically flips validation from pass to fail.

## Required Scenarios

1. Scenario A: Emit telemetry until budget exhaustion; subsequent emission is blocked with clear error.
2. Scenario B: Execute secure aggregation with 10 participants; recovery of individual contribution from aggregate fails.
3. Scenario C: External verifier audits a fully consumed budget and reports exhausted.
4. Scenario D: Unauthorized privacy-budget reset attempt is denied and logged.

## Structured Event Codes

- `FPL-001`: Privacy budget accounting evaluation started.
- `FPL-002`: Channel emission accepted under remaining budget.
- `FPL-003`: Budget exhaustion block emitted.
- `FPL-004`: Secure aggregation privacy validation completed.
- `FPL-005`: Unauthorized budget reset denied and logged.

All events must include stable `trace_id` and channel/federation context.

## Machine-Readable Artifacts

- `artifacts/12/federated_privacy_leakage_report.json`
- `artifacts/section_12/bd-1nab/verification_evidence.json`
- `artifacts/section_12/bd-1nab/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): strict privacy budgets are verified by per-channel epsilon config with default max <= 1.0.
- Countermeasure (b): secure aggregation checks prove non-recoverability with participant count >= 10.
- Countermeasure (c): external verifier confirms exhausted budgets without raw-data visibility.
- Unauthorized reset attempts are denied, surfaced with stable error code, and logged via event code.
