# bd-2fpj: Contract Field — Expected-Loss Model — Verification Summary

**Section:** 11 | **Verdict:** PASS | **Agent:** CrimsonCrane | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 13 | 13 |
| Python unit tests | 44 | 44 |

## Coverage

- **Contract field**: `change_summary.expected_loss_model`
- **Scenarios**: Minimum 3 with name, probability, impact_value, impact_unit, mitigation
- **Loss categories**: 5 (negligible, minor, moderate, major, catastrophic) with numeric thresholds
- **Aggregate formula**: sum(probability * impact_value) with 1e-6 tolerance
- **Confidence interval**: lower/upper bounds + confidence_level validation
- **Event codes**: 4 (CONTRACT_ELM_VALIDATED, MISSING, INVALID, THRESHOLD_EXCEEDED)
- **Invariants**: 4 (INV-ELM-SCENARIOS, AGGREGATE, CATEGORY, CONFIDENCE)
- **Acceptance criteria**: 10 numbered items

## Artifacts

- Spec: `docs/specs/section_11/bd-2fpj_contract.md`
- Policy: `docs/policy/expected_loss_model.md`
- Verification: `scripts/check_expected_loss.py`
- Unit tests: `tests/test_check_expected_loss.py`
