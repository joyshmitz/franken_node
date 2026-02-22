# bd-274s Verification Summary

- Status: **PASS**
- Bead: `bd-274s`
- Section: `10.17`

## Delivered Surface

- `crates/franken-node/src/security/adversary_graph.rs`
- `crates/franken-node/src/security/quarantine_controller.rs`
- `crates/franken-node/src/security/mod.rs`
- `tests/integration/bayesian_risk_quarantine.rs`
- `crates/franken-node/tests/bayesian_risk_quarantine.rs`
- `artifacts/10.17/adversary_graph_state.json`
- `artifacts/section_10_17/bd-274s/verification_evidence.json`
- `artifacts/section_10_17/bd-274s/verification_summary.md`

## Acceptance Coverage

- Deterministic Bayesian posterior updates for identical evidence inputs.
- Deterministic threshold mapping from posterior risk to control actions:
  - `throttle`
  - `isolate`
  - `quarantine`
  - `revoke`
- Reproducible signed evidence entries (`sha256`) for action receipts.
- Stable action ordering for replay determinism.
- Checker gate passes with all required files and token contracts present.

## Validation Commands

- `python3 scripts/check_bd_274s_bayesian_quarantine.py --json` -> PASS (`17/17`)
- `python3 -m unittest tests/test_check_bd_274s_bayesian_quarantine.py` -> PASS (`13 tests`)
- `rustfmt --edition 2024 --check crates/franken-node/src/security/adversary_graph.rs crates/franken-node/src/security/quarantine_controller.rs tests/integration/bayesian_risk_quarantine.rs crates/franken-node/tests/bayesian_risk_quarantine.rs` -> PASS
- `rch exec -- cargo check -p frankenengine-node --tests` -> FAIL (remote worker missing sibling path dependency `../franken_engine`; manifest resolution fails pre-compile)

## Notes

- `bd-274s` checker gate is green with this implementation.
- Remote cargo verification remains blocked by worker sync topology, not by bead-level checker/test regressions.
