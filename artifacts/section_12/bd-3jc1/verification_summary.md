# bd-3jc1 Verification Summary

- Bead: `bd-3jc1`
- Section: `12`
- Capability: `Risk control: migration friction persistence`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-3jc1_contract.md`
- Machine-readable report: `artifacts/12/migration_friction_report.json`
- Verifier: `scripts/check_migration_friction_persistence.py`
- Unit tests: `tests/test_check_migration_friction_persistence.py`

## Acceptance Results

- Autopilot handled `85.9%` of migration steps in a 10-project cohort (threshold: `>= 80%`).
- Confidence report generated for every migration attempt with score and ranked blockers.
- Calibration check passed: confidence `>= 80` predicted success at `100.0%` (threshold: `>= 90%`).
- Mixed-mode operation demonstrated with `50%` migrated modules running alongside legacy runtime.
- Scenario coverage passed:
  - Scenario A: Express starter autopilot success with high confidence.
  - Scenario B: Native addon blocker detected with low confidence and explicit blocker.
  - Scenario C: Mixed-mode project executed correctly with partial migration.

## Determinism and Adversarial Validation

- Determinism checks passed for order-insensitive aggregate recomputation.
- Adversarial perturbation test correctly flipped calibration gate when degraded inputs were introduced.

## Reproducible Commands

```bash
python3 scripts/check_migration_friction_persistence.py --json
python3 -m unittest tests/test_check_migration_friction_persistence.py
```
