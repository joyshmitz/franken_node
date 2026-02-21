# bd-3jc1 Contract: Migration Friction Persistence Risk Control

## Goal

Prevent persistent migration friction by enforcing machine-verifiable guardrails for migration autopilot coverage, confidence reporting quality, and mixed-mode fallback behavior.

## Quantified Invariants

- `INV-MFP-AUTOPILOT`: For a representative 10-project cohort, autopilot automation coverage is `>= 80%` with zero manual interventions.
- `INV-MFP-CONFIDENCE-REPORT`: Every migration attempt emits a confidence report containing `confidence_score` and a ranked blocker list.
- `INV-MFP-CALIBRATION`: Predictions with `confidence_score >= 80` achieve observed migration success rate `>= 90%`.
- `INV-MFP-MIXED-MODE`: Mixed-mode (partially migrated project) executes with both runtimes active and functional.

## Determinism Requirements

- Re-running verification on identical report input yields identical aggregate metrics and verdict.
- Project list order must not affect aggregate guardrail outcomes.
- Adversarial perturbation (forcing one high-confidence migration to fail) must deterministically fail calibration checks.

## Required Scenarios

1. Scenario A: Express starter migration completes with confidence `>= 90` and no manual intervention.
2. Scenario B: Native-addon project produces confidence `< 50` and blocker list includes `native addon`.
3. Scenario C: Mixed-mode project with 50% migrated modules reports both runtimes healthy.

## Structured Event Codes

- `MFP-001`: Autopilot cohort evaluation started.
- `MFP-002`: Confidence report emitted for project.
- `MFP-003`: Mixed-mode validation completed.
- `MFP-004`: Migration blocker detected.
- `MFP-005`: Calibration gate evaluation completed.

All events must include stable `trace_id` and `project` (or `cohort`) context.

## Machine-Readable Artifacts

- `artifacts/12/migration_friction_report.json`
- `artifacts/section_12/bd-3jc1/verification_evidence.json`
- `artifacts/section_12/bd-3jc1/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): `autopilot_coverage_pct >= 80` in cohort report.
- Countermeasure (b): confidence score + ranked blockers present for each project.
- Countermeasure (c): mixed-mode project includes `migrated_module_pct = 50` and both runtimes passing.
