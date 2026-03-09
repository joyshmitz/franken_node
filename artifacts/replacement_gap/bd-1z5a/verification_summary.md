# bd-1z5a Replacement-Gap Evidence Pack

**Section:** 10.17  
**Support bead:** `bd-1z5a.5`  
**Verdict:** PARTIAL

## Scope Of This Support Slice

This artifact pack does not claim that `bd-1z5a` is finished. It captures the
truthful current state of the verifier-economy / replay-capsule replacement-gap
work without touching the reserved core Rust files owned in other lanes.

What this support slice adds:

- a refreshed evidence pack that now points at the passing operator E2E bundle
  and structured event log
- a deterministic replay fixture index that includes the operator shell harness,
  checker, and machine-readable fraud-proof witness bundle
- fresh local checker evidence and prior `rch` build IDs that prove the current
  shared `frankenengine-node` tree remains materially healthier than the
  original surrogate-path bug report

## Fresh Evidence Gathered

- `python3 scripts/check_verifier_economy.py --json` passed `152/152` checks.
  The replacement-critical guard windows for attestation signature verification,
  cached-key verification, and replay-capsule integrity all passed.
- `python3 scripts/check_verifier_sdk.py --json` passed `65/65` checks. The
  replacement-critical guard windows for canonical migration-signature
  verification and content-hash validation both passed.
- `python3 -m unittest tests/test_check_verifier_economy.py tests/test_check_verifier_sdk.py`
  passed `74` tests.
- `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_verifier_replay_operator_e2e.py --json`
  passed `17/17` checks. The operator E2E bundle now reports a single trace id,
  five passing stages, all required `CAPSULE_VERIFY_*` / `VERIFIER_SCORE_*`
  events, and valid stage artifact paths.
- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests/test_check_verifier_replay_operator_e2e.py`
  passed `9` tests.
- `rch` build `29747325727408129` passed strict test-surface clippy for
  `frankenengine-node`.
- `rch` build `29747325727408132` passed the existing trust-state verification
  probe.
- `rch` build `29747325727408133` passed strict
  `cargo clippy -p frankenengine-node --all-targets -- -D warnings` on the
  current shared tree.

## Replay / Score / Witness Inventory

The indexed fixture set is currently anchored in the existing Section 10.17
reports, conformance tests, and replacement-gap operator artifacts:

- `artifacts/10.17/verifier_sdk_certification_report.json`
- `tests/conformance/verifier_sdk_capsule_replay.rs`
- `artifacts/10.17/public_trust_scoreboard_snapshot.json`
- `tests/conformance/claim_compiler_gate.rs`
- `tests/e2e/verifier_replay_operator_suite.sh`
- `scripts/check_verifier_replay_operator_e2e.py`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_bundle.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-1z5a/fraud_proof_bundle.json`
- the replacement-critical Python checker + unittest pairs for
  `verifier_economy` and `connector/verifier_sdk`

That now gives us deterministic capsule-report, scoreboard-report, operator E2E,
structured event-log, and witness-reference inputs in the replacement-gap lane.

## Remaining Gaps

- The parent bead remains in progress on the canonical shared verifier kernel
  itself, in the reserved Rust surfaces owned on RoseMountain's lane.
- This support pack proves the external replay / quarantine / scoreboard
  evidence path and records a machine-readable fraud-proof witness reference,
  but it does not independently declare the underlying core verifier
  implementation complete.

## Notes

- The older `bd-1z5a.2` evidence-pack gaps for operator shell coverage,
  acceptance-specific event-family artifacts, and a replacement-gap witness
  bundle are now closed by the passing operator E2E bundle and
  `fraud_proof_bundle.json`.
- The operator bundle is normalized to one coherent trace id:
  `trace-bd-1z5a-operator-e2e-final`.
- The witness bundle is intentionally truthful and minimal: it records the
  extracted fraud-proof id, trace binding, and source artifact references
  without inventing a counterexample payload that current stage outputs do not
  expose.
