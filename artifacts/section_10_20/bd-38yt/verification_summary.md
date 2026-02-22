# bd-38yt Verification Summary

## Result
PASS (bead scope) with pre-existing workspace baseline cargo failures

## Delivered
- `.github/workflows/dgis-claim-gate.yml`
- `docs/conformance/dgis_release_claim_gate.md`
- `tests/perf/dgis_budget_gate.rs`
- `artifacts/10.20/dgis_release_gate_report.json`
- `scripts/check_dgis_claim_gate.py`
- `tests/test_check_dgis_claim_gate.py`
- `artifacts/section_10_20/bd-38yt/check_self_test.json`
- `artifacts/section_10_20/bd-38yt/check_report.json`
- `artifacts/section_10_20/bd-38yt/unit_tests.txt`
- `artifacts/section_10_20/bd-38yt/verification_evidence.json`

## Commands
- `python3 -m py_compile scripts/check_dgis_claim_gate.py tests/test_check_dgis_claim_gate.py`
- `python3 scripts/check_dgis_claim_gate.py --self-test --json`
- `python3 scripts/check_dgis_claim_gate.py --json`
- `python3 -m unittest tests/test_check_dgis_claim_gate.py`
- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo fmt --check`

## Key Outcomes
- DGIS release claims are blocked when any designated computation exceeds p95/p99 budgets, lacks required signed evidence, or references missing artifacts.
- Claim contract covers all required DGIS computation classes: ingestion, metric computation, contagion simulation, and economic ranking.
- Deterministic canonical signing metadata is validated (`canonical_payload_sha256` and derived `signature`).
- External verification is reproducible from report fields alone.
- Structured event code contract is documented and checked (`DGIS-PERF-001..005`, `DGIS-PERF-ERR-*`).
- Performance contract file `tests/perf/dgis_budget_gate.rs` defines explicit target scales and budget verdict semantics for CI gating.

## Cargo Gate Notes
- `cargo check` failed via `rch` with pre-existing workspace compile debt outside `bd-38yt` scope.
- `cargo clippy` failed via `rch` with pre-existing workspace lint/compile debt outside `bd-38yt` scope.
- `cargo fmt --check` failed via `rch` with pre-existing workspace formatting drift outside `bd-38yt` scope.
