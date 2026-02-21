# bd-2a4l: Externally Verifiable Trust/Security Claims — Verification Summary

**Section:** 13 | **Verdict:** PASS | **Agent:** CrimsonCrane | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 44 | 44 |
| Python unit tests | 26 | 26 |

## Coverage

- **5 verifiability dimensions** (VD-01 through VD-05)
- **4 quantitative targets** (100% coverage, 95% reproduction, 30-day freshness, SHA-256)
- **4 event codes** (EVC-001 through EVC-004)
- **4 invariants** (INV-EVC-COVERAGE, REPRODUCE, DETERMINISM, INTEGRITY)
- **4 evidence bundle format elements** (claim.json, procedure.md, manifest.json, SHA-256)
- **5 reproduction protocol aspects** (reproduction, external, determinism, timestamp, non-determinism)
- **4 adversarial perturbation types** (corrupted, truncated, tampered, replayed)
- **3 CI integration aspects** (release gate, freshness, nightly)
- **5 claim categories** (compatibility, security, trust, performance, migration)
- **4 acceptance criteria** (claim registry, content-addressed, external-reproduction, adversarial)

## Artifacts

- Spec: `docs/specs/section_13/bd-2a4l_contract.md`
- Policy: `docs/policy/externally_verifiable_claims.md`
- Verification: `scripts/check_verifiable_claims.py`
- Unit tests: `tests/test_check_verifiable_claims.py`
