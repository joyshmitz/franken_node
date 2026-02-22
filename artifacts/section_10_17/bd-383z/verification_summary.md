# bd-383z Verification Summary

- Status: **PASS**
- Checker: `45/45` PASS (`artifacts/section_10_17/bd-383z/check_report.json`)
- Checker self-test: PASS (`artifacts/section_10_17/bd-383z/check_self_test.txt`)
- Unit tests: `17` tests PASS (`artifacts/section_10_17/bd-383z/unit_tests.txt`)

## Delivered Surface

- `docs/specs/section_10_17/bd-383z_contract.md`
- `crates/franken-node/src/runtime/incident_lab.rs`
- `scripts/check_incident_lab.py`
- `tests/test_check_incident_lab.py`
- `artifacts/10.17/counterfactual_eval_report.json`
- `artifacts/section_10_17/bd-383z/verification_evidence.json`
- `artifacts/section_10_17/bd-383z/verification_summary.md`

## Acceptance Coverage

- Real incident traces can be replayed with reproducible, deterministic outcomes.
- Synthesized mitigations are compared against original traces with expected-loss deltas.
- Promoted mitigations require signed rollout and rollback contracts.
- The lab emits 6 structured event codes (ILAB_001..ILAB_006).
- 6 error codes (ERR_ILAB_*) cover all failure modes.
- 5 invariants (INV-ILAB-*) are documented and enforced.
- 27+ inline Rust unit tests verify all invariants and error paths.
- Deterministic replay fixture: same trace always produces identical digest.
- BTreeMap used for deterministic ordering throughout.

## Key Invariants

| ID | Enforcement |
|----|-------------|
| INV-ILAB-DETERMINISTIC | Replay of same trace always produces identical digest |
| INV-ILAB-DELTA-REQUIRED | No promotion without computed expected-loss delta |
| INV-ILAB-SIGNED-ROLLOUT | Promoted mitigations require signed rollout contract |
| INV-ILAB-ROLLBACK-ATTACHED | Every rollout contract includes rollback clause |
| INV-ILAB-TRACE-INTEGRITY | Traces are SHA-256-verified before replay |
