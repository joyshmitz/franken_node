# bd-paui Contract: Topological Choke-Point False-Positive Risk Control

## Goal

Prevent over-hardening from producing choke-point false positives by requiring pre-enforcement counterfactual replay, expected-loss calibration, and staged promotion controls.

## Quantified Invariants

- `INV-CFP-SIMULATION`: Every candidate hardening rule is evaluated by counterfactual simulation over at least `1000` historical operations before enforcement.
- `INV-CFP-FP-GATE`: Any rule promoted to enforce mode has measured false-positive rate `<= 1%`.
- `INV-CFP-EV-GATE`: Every enforced rule has net-positive expected value (blocked-threat value exceeds false-positive cost).
- `INV-CFP-STAGED`: Rule lifecycle is strictly `audit -> warn -> enforce`, with minimum `24h` residency in each stage.
- `INV-CFP-ROLLBACK`: Rules failing thresholds are prevented from enforcement and emit rollback/hold receipts.

## Determinism Requirements

- Re-running verification on identical rule report input yields identical aggregate verdict.
- Rule order does not affect aggregate promotion and expected-loss outcomes.
- Adversarial perturbation that raises an enforced rule FP rate above `1%` deterministically flips gate result to fail.

## Required Scenarios

1. Scenario A: A proposed rule that would block `5%` of legitimate operations is rejected before enforcement.
2. Scenario B: A rule in audit mode logs violations without blocking operations.
3. Scenario C: Warn-to-enforce promotion only succeeds when measured FP rate is `<= 1%`.
4. Scenario D: Expected-loss model flags net-negative rules (e.g., `$100/day` legit loss vs `$10/day` blocked threat value).

## Structured Event Codes

- `CFP-001`: Counterfactual simulation executed.
- `CFP-002`: Staged rollout transition recorded.
- `CFP-003`: False-positive threshold gate evaluated.
- `CFP-004`: Expected-loss calibration evaluated.
- `CFP-005`: Promotion denied or rollback receipt issued.

All events must include stable `trace_id` and `rule_id` context.

## Machine-Readable Artifacts

- `artifacts/12/chokepoint_false_positive_report.json`
- `artifacts/section_12/bd-paui/verification_evidence.json`
- `artifacts/section_12/bd-paui/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): counterfactual replay and FP estimation are required before enforce mode.
- Countermeasure (b): expected-loss threshold determines promotion eligibility.
- Countermeasure (c): staged rollout with minimum stage duration gates promotion.
- Rules exceeding FP/EV thresholds are blocked from enforcement and tracked with receipts.
