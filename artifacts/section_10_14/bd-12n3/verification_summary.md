# bd-12n3 Verification Summary

## Result
PASS on the contract/gate surface after the canonical framing fix.
Remote cargo verification remains partially blocked by worker infrastructure.

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
- `python3 scripts/check_idempotency_key_derivation.py --json` -> PASS (`30/30` checks).
- `python3 scripts/check_idempotency_key_derivation.py --self-test` -> PASS.
- `python3 -m pytest -q tests/test_check_idempotency_key_derivation.py` -> PASS (`7 passed`).
- `rustfmt --edition 2024 --check crates/franken-node/src/remote/idempotency.rs tests/conformance/idempotency_key_derivation.rs` -> PASS.
- `git diff --check` on the touched bd-12n3 surface -> PASS.
- `rch exec -- env CARGO_TARGET_DIR=target/bd-3vmoo-check2 cargo check -p frankenengine-node --all-targets` -> `101`, but from remote temp-dir creation failure while compiling sibling `frankenengine-engine`, not from a bd-12n3 Rust diagnostic.
- `rch exec -- env CARGO_TARGET_DIR=target/bd-3vmoo-filter2 cargo test -p frankenengine-node separator_collision_inputs_do_not_alias_after_derivation_fix -- --nocapture` -> still active/quiet on the worker when this summary was updated.
