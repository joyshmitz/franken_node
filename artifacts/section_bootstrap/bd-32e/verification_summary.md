# bd-32e Verification Summary

## Scope Delivered

- Implemented `franken-node init` bootstrap behavior with explicit overwrite policy:
  - non-destructive default abort when generated targets already exist
  - `--overwrite` replace mode
  - `--backup-existing` backup-then-replace mode
  - `--overwrite` and `--backup-existing` mutual exclusion enforcement
- Added init reporting surface:
  - `--json` for machine-readable init report
  - `--trace-id` for correlation
  - report includes file actions and merge provenance
- Added profile-template bootstrapping in `--out-dir` mode:
  - writes `franken_node.toml`
  - writes `franken_node.profile_examples.toml`

## Contract / Test Results

- `tests/e2e/init_profile_bootstrap.sh` => **PASS**
- `python3 -m py_compile tests/test_init_profile_bootstrap_gate.py` => **PASS**
- `pytest -q tests/test_init_profile_bootstrap_gate.py` => **PASS** (`4 passed`)

## Generated Artifacts

- `artifacts/section_bootstrap/bd-32e/init_contract_checks.json`
- `artifacts/section_bootstrap/bd-32e/init_contract_checks.md`
- `artifacts/section_bootstrap/bd-32e/init_snapshots.json`
- `artifacts/section_bootstrap/bd-32e/verification_evidence.json`

## Required Quality Gates (`rch` offload)

- `rch exec -- cargo fmt --check` => exit `1`
- `rch exec -- cargo check --all-targets` => exit `101` (retry log used after transient sync race)
- `rch exec -- cargo clippy --all-targets -- -D warnings` => exit `101`

These failures are existing workspace-wide baseline debt and were captured as evidence under:

- `artifacts/section_bootstrap/bd-32e/rch_cargo_fmt_check.log`
- `artifacts/section_bootstrap/bd-32e/rch_cargo_check_retry.log`
- `artifacts/section_bootstrap/bd-32e/rch_cargo_clippy.log`
