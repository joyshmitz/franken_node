# Bootstrap Foundation Gate Summary

## Gate Identity
- Bead: `bd-3ohj`
- Gate script: `scripts/check_bootstrap_foundation_gate.py`
- Canonical verdict artifact: `artifacts/bootstrap/bootstrap/gate_verdict/bd-3ohj_bootstrap_gate.json`
- Section verdict artifact: `artifacts/section_bootstrap/bd-3ohj/check_report.json`
- Structured log: `artifacts/section_bootstrap/bd-3ohj/foundation_gate_log.jsonl`

## Verdict
- Verdict: `PASS`
- Checks: `9/9` passing
- Failing dimensions: `none`
- Content hash: `59225884b60df80eac4bd2af4071f8828f353d9927daf18c60ee0d303018cdf8`

## Upstream Traceability
| Bead | Evidence | Contract/Gate Input | Status |
|---|---|---|---|
| `bd-n9r` | `artifacts/section_bootstrap/bd-n9r/verification_evidence.json` | `artifacts/section_bootstrap/bd-n9r/contract_checks.json` | pass |
| `bd-1pk` | `artifacts/section_bootstrap/bd-1pk/verification_evidence.json` | `artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json` | pass |
| `bd-32e` | `artifacts/section_bootstrap/bd-32e/verification_evidence.json` | `artifacts/section_bootstrap/bd-32e/init_contract_checks.json` | pass |
| `bd-2a3` | `artifacts/section_bootstrap/bd-2a3/verification_evidence.json` | `artifacts/section_bootstrap/bd-2a3/baseline_checks.json` | pass-for-scope with documented baseline FAIL |
| `bd-3k9t` | `artifacts/section_bootstrap/bd-3k9t/verification_evidence.json` | `artifacts/section_bootstrap/bd-3k9t/check_report.json` | pass |

## Coverage Dimensions Enforced
- Matrix coverage contract (`docs/verification/bootstrap_test_matrix.json`)
- E2E outcomes (`artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.json`)
- Baseline workspace check semantics (`bd-2a3`)
- Docs navigation links (`BOOTSTRAP_TEST_MATRIX.md`, `bootstrap_e2e_harness.md`)
- Structured log stability and deterministic stage ordering

## Quality Gate Snapshot (`rch`)
- `cargo fmt --check` via `rch`: exit `1`
- `cargo check --all-targets` via `rch`: exit `0`
- `cargo clippy --all-targets -- -D warnings` via `rch`: exit `101`

Captured logs/exits:
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_fmt_check.log`
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_check.log`
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_clippy.log`
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_fmt_check.exit`
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_check.exit`
- `artifacts/section_bootstrap/bd-3ohj/rch_cargo_clippy.exit`
