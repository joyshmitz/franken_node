# bd-2a3 Verification Summary

**Bead:** `bd-2a3`  
**Section:** `bootstrap`  
**Timestamp (UTC):** `2026-02-22T01:11:19Z`

## Outcome

The `bd-2a3` objective is complete for scope: baseline workspace checks were executed strictly through `rch` offload and evidence was captured deterministically.

Baseline verdict:
- `FAIL (0/3 checks passed)`

This failure is expected at workspace level and is now documented with machine-readable provenance for triage.

## Required Commands (All via rch)

| Check | Status Code | Exit | Duration (ms) | Command |
|---|---|---:|---:|---|
| `cargo_fmt_check` | `BD2A3-FMT-FAIL` | `1` | `1864` | `rch exec -- cargo fmt --check` |
| `cargo_check_all_targets` | `BD2A3-CHECK-FAIL` | `101` | `141720` | `rch exec -- cargo check --all-targets` |
| `cargo_clippy_all_targets` | `BD2A3-CLIPPY-FAIL` | `101` | `91709` | `rch exec -- cargo clippy --all-targets -- -D warnings` |

## Key Failure Signals Captured

- `cargo fmt --check`: broad formatting drift across many files (`Diff in ...` entries in `cargo_fmt_check.log`).
- `cargo check --all-targets`: compiler errors including `E0599`, `E0423`, `E0499`, `E0502` and target compilation failures.
- `cargo clippy --all-targets -- -D warnings`: compile/lint hard failures under warning-deny mode.

## Artifacts

- `artifacts/section_bootstrap/bd-2a3/baseline_checks.json`
- `artifacts/section_bootstrap/bd-2a3/baseline_checks.md`
- `artifacts/section_bootstrap/bd-2a3/rch_command_log.jsonl`
- `artifacts/section_bootstrap/bd-2a3/rch_doctor.log`
- `artifacts/section_bootstrap/bd-2a3/cargo_fmt_check.log`
- `artifacts/section_bootstrap/bd-2a3/cargo_check_all_targets.log`
- `artifacts/section_bootstrap/bd-2a3/cargo_clippy_all_targets.log`

## Determinism

`baseline_checks.json` hash was stable across repeated reads:
- `e60cc16617a74fb05df450481db76bebfbbc8dea8319be1ddd7fee81245b9363`
- `e60cc16617a74fb05df450481db76bebfbbc8dea8319be1ddd7fee81245b9363`

## Reproduction

```bash
timeout 900 tests/e2e/baseline_rch_sequence.sh
```
