# bd-2ymp: Rollout Wedge Contract Field — Verification Summary

## Result: PASS

| Metric | Value |
|--------|-------|
| Verification checks | 57/57 |
| Python unit tests | 65/65 |
| Verdict | **PASS** |
| Agent | CrimsonCrane |

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_11/bd-2ymp_contract.md` |
| Policy document | `docs/policy/rollout_wedge.md` |
| Verification script | `scripts/check_rollout_wedge.py` |
| Python tests | `tests/test_check_rollout_wedge.py` |
| Evidence JSON | `artifacts/section_11/bd-2ymp/verification_evidence.json` |
| This summary | `artifacts/section_11/bd-2ymp/verification_summary.md` |

## Coverage

- Spec contract defines rollout wedge contract field with 6 required sub-fields
- Policy document covers contract requirements, staged deployment rules, blast radius controls, governance, appeal process
- 4 event codes: RWG-001 (stage advanced), RWG-002 (paused), RWG-003 (rolled back), RWG-004 (completed)
- 4 invariants: INV-RWG-STAGED, INV-RWG-OBSERVE, INV-RWG-BLAST, INV-RWG-ROLLBACK
- 5 wedge states: PENDING, ACTIVE, PAUSED, ROLLED_BACK, COMPLETE
- 3 increment policies: linear, exponential, manual
- 5 stage sub-fields: stage_id, target_percentage, duration_hours, success_criteria, rollback_trigger
- Thresholds: initial_percentage <= 10%, min stages >= 2, observation_window >= 1 hour, first-stage blast radius <= 25%, rollback execution <= 60s
- Monotonically increasing target_percentage required across stages
- Validation helper: validate_rollout_wedge() with 8 validation rules
- Duration helper: compute_total_rollout_duration()

## Verification Checks (57)

| # | Check | Result |
|---|-------|--------|
| 1 | file: spec contract | PASS |
| 2 | file: policy document | PASS |
| 3-8 | spec required fields (6) | PASS |
| 9-13 | stage required fields (5) | PASS |
| 14-17 | spec event codes (4) | PASS |
| 18-21 | spec invariants (4) | PASS |
| 22-26 | spec wedge states (5) | PASS |
| 27-29 | spec increment policies (3) | PASS |
| 30-34 | spec thresholds (5) | PASS |
| 35 | spec validation rules section | PASS |
| 36-37 | spec helper functions (2) | PASS |
| 38-41 | policy event codes (4) | PASS |
| 42-45 | policy invariants (4) | PASS |
| 46-50 | policy wedge states (5) | PASS |
| 51-53 | policy increment policies (3) | PASS |
| 54 | policy blast radius controls | PASS |
| 55 | policy observation window | PASS |
| 56 | policy governance section | PASS |
| 57 | policy appeal process | PASS |

## Unit Test Coverage (65 tests)

| Test Class | Count | Description |
|------------|-------|-------------|
| TestRunAllStructure | 10 | Report structure, keys, types, counts |
| TestSelfTest | 2 | Self-test returns bool and passes |
| TestIndividualChecks | 2 | All checks pass, verdict is PASS |
| TestMissingFileDetection | 3 | Mock-based file absence detection |
| TestValidateRolloutWedge | 16 | Contract validation: valid/invalid cases |
| TestComputeTotalRolloutDuration | 5 | Duration computation helper |
| TestConstants | 8 | Event codes, invariants, states, policies |
| TestJsonOutput | 3 | JSON, self-test, human-readable CLI modes |
| TestSafeRel | 3 | Path safety for root-relative paths |
| TestCheckHelper | 4 | _check() helper behavior |
| TestSpecificFileChecks | 2 | Spec and policy file existence |
| TestSpecEventCodes | 4 | Individual event code checks |
| TestSpecInvariants | 4 | Individual invariant checks |
