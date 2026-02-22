# bd-whxp Verification Summary

## Scope Delivered

Implemented the section-13 concrete KPI gate requiring at least two independent replications of headline claims:
- `docs/specs/section_13/bd-whxp_contract.md`
- `artifacts/13/independent_replication_report.json`
- `scripts/check_independent_replications_gate.py`
- `tests/test_check_independent_replications_gate.py`
- `.github/workflows/independent-replication-gate.yml`

## Gate Validation Results

- PASS `python3 scripts/check_independent_replications_gate.py --self-test --json`
- PASS `python3 scripts/check_independent_replications_gate.py --json`
  - verdict: `PASS`
  - checks: `24/24`
  - independent replications passing: `2` (required `>=2`)
  - required claims validated: migration velocity, compromise reduction, replay coverage
  - determinism and adversarial perturbation checks: PASS
  - required structured events emitted: `IRG-001..IRG-006`
- PASS `python3 -m unittest tests/test_check_independent_replications_gate.py`
  - `5` tests run, all passing

## Required Cargo Gates (via rch)

- FAIL (pre-existing baseline): `rch exec -- cargo check --all-targets` (exit `101`)
- FAIL (pre-existing baseline): `rch exec -- cargo clippy --all-targets -- -D warnings` (exit `101`)
- FAIL (pre-existing baseline): `rch exec -- cargo fmt --check` (exit `1`)

Logs are captured under `artifacts/section_13/bd-whxp/rch_cargo_*.log`; failures are unrelated to this bead's docs/script/test/workflow changes.
