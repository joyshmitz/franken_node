# Bootstrap Foundation E2E Harness (bd-3k9t)

## Purpose

`tests/e2e/foundation_bootstrap_suite.sh` provides a deterministic foundation-level E2E harness for bootstrap workflows and structured evidence generation.

The harness aggregates:

1. `tests/e2e/config_profile_resolution.sh`
2. `tests/e2e/init_profile_bootstrap.sh`
3. `tests/e2e/doctor_command_diagnostics.sh`
4. Transplant integrity probes:
   - `transplant/verify_lockfile.sh --json`
   - `transplant/drift_detect.sh --json`

It emits machine-readable stage results, replay inputs, and structured JSONL logs under:

- `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_log.jsonl`
- `artifacts/section_bootstrap/bd-3k9t/stage_results.jsonl`
- `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.json`
- `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_bundle.json`
- `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.md`

## Structured Event Codes

- `FB-E2E-001` suite start
- `FB-E2E-010` stage start
- `FB-E2E-020` stage completion
- `FB-E2E-099` suite verdict

Each event includes `trace_id`, `stage`, `category`, `status`, and command details for replay triage.

## Deterministic Stage Contract

- Stage list is fixed-order and stable.
- Stage pass/fail is deterministic by `(expected_exit, expected_pattern)`.
- Coverage must include at least one stage in each class:
  - `clean`
  - `degraded`
  - `drifted`

## Replay Inputs

The bundle references canonical replay inputs needed for post-failure triage:

- `artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json`
- `artifacts/section_bootstrap/bd-32e/init_snapshots.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json`
- `transplant/TRANSPLANT_LOCKFILE.sha256`
- `transplant/transplant_manifest.txt`

## CI Integration Note

Add this gate to bootstrap pipelines:

```bash
tests/e2e/foundation_bootstrap_suite.sh
python3 scripts/check_foundation_e2e_bundle.py --json
```

Pipeline behavior:

- Fail build if either command exits non-zero.
- Persist `artifacts/section_bootstrap/bd-3k9t/` as CI artifact payload.
- Use `foundation_e2e_bundle.json` as the machine-readable gate contract for downstream bootstrap verification (`bd-3ohj`).
