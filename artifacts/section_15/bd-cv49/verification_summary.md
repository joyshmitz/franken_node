# bd-cv49 Verification Summary

**Bead:** `bd-cv49`  
**Section:** `15`  
**Timestamp (UTC):** `2026-02-22T01:03:57Z`

## Outcome

`bd-cv49` contract checks pass for case-study publication capability:

- `3/3` case studies published
- `2/2` measurable security-improvement case studies
- `3/3` reviewed by featured organizations
- `3/3` published on project website
- `1/1` external submission threshold
- Template + docs + machine-readable registry present

## Validation Runs

| Command | Result |
|---|---|
| `python3 scripts/check_case_study_registry.py --json` | PASS (`24/24` checks) |
| `python3 scripts/check_case_study_registry.py --self-test` | PASS (`24 checks OK`) |
| `pytest -q tests/test_check_case_study_registry.py` | PASS (`32 passed`) |
| `rch exec -- cargo check --all-targets` | FAIL (pre-existing workspace compile errors) |
| `rch exec -- cargo clippy --all-targets -- -D warnings` | FAIL (pre-existing workspace lint/compile errors) |
| `rch exec -- cargo fmt --check` | FAIL (pre-existing workspace formatting drift) |

## Determinism Evidence

`python3 scripts/check_case_study_registry.py --json | sha256sum` produced the same hash on repeated runs:

- `359c6e1ea9c69d687a333a37e8ba38583836e5c9483539501cbd6c5d5668c4b1`
- `359c6e1ea9c69d687a333a37e8ba38583836e5c9483539501cbd6c5d5668c4b1`

## Primary Artifacts

- `artifacts/15/case_study_registry.json`
- `docs/specs/section_15/bd-cv49_contract.md`
- `docs/templates/case_study_template.md`
- `docs/ecosystem/migration_case_studies.md`
- `scripts/check_case_study_registry.py`
- `tests/test_check_case_study_registry.py`

