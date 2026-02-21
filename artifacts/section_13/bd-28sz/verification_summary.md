# Verification Summary: bd-28sz

**Bead:** bd-28sz
**Title:** Concrete target gate: >= 95% compatibility corpus pass
**Section:** 13 (Program Success Criteria Instrumentation)
**Verdict:** PASS
**Date:** 2026-02-20

## Results

- **Total checks:** 20
- **Passed:** 20
- **Failed:** 0

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec contract | `docs/specs/section_13/bd-28sz_contract.md` | Present |
| Policy document | `docs/policy/compat_corpus_gate.md` | Present |
| Verification script | `scripts/check_compat_corpus_gate.py` | Present |
| Unit tests | `tests/test_check_compat_corpus_gate.py` | 71 tests, all passing |
| Evidence JSON | `artifacts/section_13/bd-28sz/verification_evidence.json` | Generated |

## Check Summary

### Spec Checks (C01-C13)
- C01: Spec contract file exists
- C02: Policy document exists
- C03: Aggregate >= 95% threshold documented
- C04: Per-module >= 80% floor documented
- C05: All 5 gate tiers (G0-G4) defined
- C06: All 4 event codes (CCG-001 through CCG-004) defined
- C07: All 4 invariants (INV-CCG-OVERALL, INV-CCG-FAMILY-FLOOR, INV-CCG-RATCHET, INV-CCG-REPRODUCIBILITY) defined
- C08: 0% regression tolerance / ratchet documented
- C09: <= 30 min max corpus run time documented
- C10: Corpus result schema fields documented (run_id, timestamp, total_tests, etc.)
- C11: Module result sub-schema fields documented (module_name, pass_rate)
- C12: Gate Decision Flow section present
- C13: pass_rate formula documented

### Policy Checks (C14-C20)
- C14: All 5 gate tiers referenced in policy
- C15: All 4 event codes referenced in policy
- C16: All 4 invariants referenced in policy
- C17: Governance section present
- C18: Appeal Process section present
- C19: Both thresholds (>= 95%, >= 80%) documented
- C20: Gate Decision Flow documented

## Helper Functions Tested

| Helper | Unit Tests | Boundary Values |
|--------|-----------|-----------------|
| `validate_corpus_result()` | 23 tests | Valid/invalid, missing fields, tolerance, empty modules |
| `pass_rate_to_tier()` | 13 tests | 0, 79.99, 80, 89.99, 90, 94.99, 95, 99.99, 100 |
| `check_regression()` | 7 tests | Equal, increase, decrease, zero-to-95, 95-to-zero |

## Acceptance Criteria Mapping

1. Spec defines aggregate >= 95%, per-module >= 80%, ratchet 0%, max run <= 30 min -- SATISFIED
2. Policy codifies gate tiers G0-G4 and decision flow -- SATISFIED
3. `validate_corpus_result()` validates positive and negative cases -- SATISFIED (23 tests)
4. `pass_rate_to_tier()` maps all boundary values correctly -- SATISFIED (13 tests)
5. `check_regression()` detects decreases and accepts equal/increasing -- SATISFIED (7 tests)
6. All 4 event codes documented -- SATISFIED
7. All 4 invariants documented -- SATISFIED
8. Verification script passes all checks with --json output -- SATISFIED (20/20 pass)
9. Unit tests cover helpers, boundaries, mock-based absence detection -- SATISFIED (71 tests)

## Reproducible Commands

```bash
python3 scripts/check_compat_corpus_gate.py --json
python3 scripts/check_compat_corpus_gate.py --self-test
python3 -m pytest tests/test_check_compat_corpus_gate.py -v
```
