# bd-1rff Verification Summary

- Bead: `bd-1rff`
- Section: `12`
- Capability: `Risk control: longitudinal privacy/re-identification`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-1rff_contract.md`
- Machine-readable report: `artifacts/12/longitudinal_privacy_report.json`
- Verifier: `scripts/check_longitudinal_privacy.py`
- Unit tests: `tests/test_check_longitudinal_privacy.py`

## Acceptance Results

- Raw trajectories are not persisted; only sketch representations are stored.
- Query responses enforce `k >= 50`; below-threshold cohorts are blocked with a stable error code.
- Sub-hour temporal inputs are bucketed and stored at `>= 1h` granularity.
- Adversarial linkage success stays below the `<1%` threshold.
- Structured event codes `LPR-001` through `LPR-005` are present with traceability.

## Scenario Coverage

- Scenario A: reconstruction from sketches fails.
- Scenario B: cohort-30 query is blocked with `ERR_INSUFFICIENT_COHORT_SIZE`.
- Scenario C: sub-hour input is bucketed to one-hour resolution.
- Scenario D: linkage attack over 1000 sketches remains below threshold.

## Determinism and Adversarial Validation

- Query-order-insensitive evaluation remains stable.
- Adversarial lowering of minimum cohort size is detected and causes policy failure.

## Reproducible Commands

```bash
python3 scripts/check_longitudinal_privacy.py --self-test --json
python3 scripts/check_longitudinal_privacy.py --json
python3 -m unittest tests/test_check_longitudinal_privacy.py
```
