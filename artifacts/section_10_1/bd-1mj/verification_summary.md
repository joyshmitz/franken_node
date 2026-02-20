# bd-1mj: Claim-Language Policy — Verification Summary

## Verdict: PASS

## What was delivered

1. **Policy spec** `docs/specs/section_10_1/bd-1mj_contract.md`:
   - Defines external claims, categories, and evidence requirements
   - 5 policy rules: no unverified claims, evidence freshness, reproducibility, claim registry, CI enforcement
   - 5 invariants with failure semantics

2. **Claims registry** `docs/CLAIMS_REGISTRY.md`:
   - Central registry where all external claims must be registered
   - Structured format: category, claim text, evidence artifact paths, verification command, status
   - Starts empty — claims added as capabilities are implemented

3. **Enforcement script** `scripts/check_claim_language.py` with 5 checks:
   - CLAIM-REGISTRY: Registry file exists
   - CLAIM-FORMAT: Registry has required structure
   - CLAIM-ARTIFACTS: All registered claims reference existing artifacts
   - CLAIM-VERDICTS: Referenced evidence JSON contains verdict fields
   - CLAIM-POLICY: Policy spec document exists

4. **Unit tests** `tests/test_check_claim_language.py`: 11 tests covering parser, field extraction, code-fence/comment stripping, integration checks.

## Check results

| Check | Status |
|-------|--------|
| CLAIM-REGISTRY | PASS |
| CLAIM-FORMAT | PASS |
| CLAIM-ARTIFACTS | PASS |
| CLAIM-VERDICTS | PASS |
| CLAIM-POLICY | PASS |

## Unit tests

- 11/11 passed, 0 failed
