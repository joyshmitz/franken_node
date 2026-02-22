# bd-1rff Contract: Longitudinal Privacy/Re-identification Risk Control

## Goal

Prevent trajectory re-identification over time by enforcing sketch-only persistence, cohort-size query thresholds, epoch-level temporal aggregation, and adversarial linkage limits.

## Quantified Invariants

- `INV-LPR-SKETCH-ONLY`: Raw behavioral trajectories are not stored; only privacy-preserving sketches are persisted.
- `INV-LPR-K-ANON`: Query results require cohort size `k >= 50`; smaller cohorts are blocked.
- `INV-LPR-EPOCH`: Stored temporal data is bucketed to minimum 1-hour granularity.
- `INV-LPR-LINKAGE`: Linkage/re-identification success rate remains `< 1%` under adversarial auxiliary data tests.
- `INV-LPR-BLOCKING`: Violations trigger explicit blocking behavior and stable error codes.

## Determinism Requirements

- Re-running verification on identical artifact input yields identical aggregate verdict.
- Sketch record ordering does not affect aggregate privacy checks.
- Adversarial perturbation that lowers cohort threshold below 50 deterministically flips gate result to fail.

## Required Scenarios

1. Scenario A: Store 100 trajectories as sketches and fail exact trajectory reconstruction.
2. Scenario B: Query cohort of 30 is blocked with insufficient-cohort error.
3. Scenario C: Sub-hour data is automatically bucketed to 1-hour epochs.
4. Scenario D: Linkage attack over 1000 sketches stays below 1% success.

## Structured Event Codes

- `LPR-001`: Sketch persistence validated.
- `LPR-002`: Cohort threshold gate evaluated.
- `LPR-003`: Temporal bucketing enforcement evaluated.
- `LPR-004`: Linkage attack evaluation completed.
- `LPR-005`: Privacy policy block event emitted.

All events must include stable `trace_id` and query/model context.

## Machine-Readable Artifacts

- `artifacts/12/longitudinal_privacy_report.json`
- `artifacts/section_12/bd-1rff/verification_evidence.json`
- `artifacts/section_12/bd-1rff/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): sketch-only storage and reconstruction failure checks enforce lossy representation guarantees.
- Countermeasure (b): k-anonymity query filters enforce `k >= 50`.
- Countermeasure (c): temporal storage resolution is bounded to 1-hour epochs.
- Adversarial linkage tests enforce `<1%` re-identification success ceiling.
