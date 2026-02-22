# bd-12n3 Verification Summary

## Result
PASS (bead scope) with pre-existing workspace baseline cargo failures.

## Delivered
- `crates/franken-node/src/remote/idempotency.rs`
- `crates/franken-node/src/remote/mod.rs` (`pub mod idempotency;`)
- `tests/conformance/idempotency_key_derivation.rs`
- `scripts/check_idempotency_key_derivation.py`
- `tests/test_check_idempotency_key_derivation.py`
- `artifacts/10.14/idempotency_vectors.json`
- `docs/specs/section_10_14/bd-12n3_contract.md`
- `artifacts/section_10_14/bd-12n3/check_report_idempotency_key_derivation.json`
- `artifacts/section_10_14/bd-12n3/check_idempotency_key_derivation_self_test.log`
- `artifacts/section_10_14/bd-12n3/pytest_check_idempotency_key_derivation.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_check_all_targets.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_clippy_all_targets.log`
- `artifacts/section_10_14/bd-12n3/rch_cargo_fmt_check.log`
- `artifacts/section_10_14/bd-12n3/verification_evidence.json`

## Gate Results
- `python3 scripts/check_idempotency_key_derivation.py --json` -> PASS (`28/28` checks).
- `python3 scripts/check_idempotency_key_derivation.py --self-test` -> PASS.
- `pytest -q tests/test_check_idempotency_key_derivation.py` -> PASS (`6 passed`).
- `rch exec -- cargo check --all-targets` -> `101` (baseline workspace failures).
- `rch exec -- cargo clippy --all-targets -- -D warnings` -> `101` (baseline workspace failures).
- `rch exec -- cargo fmt --check` -> `1` (baseline workspace formatting drift).
