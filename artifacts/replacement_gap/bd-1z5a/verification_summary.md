# bd-1z5a Replacement-Gap Evidence Pack

**Section:** 10.17  
**Support bead:** `bd-1z5a.14`  
**Verdict:** PARTIAL

## Scope Of This Support Slice

This artifact pack does not claim that `bd-1z5a` is finished. It captures the
truthful current state of the verifier-economy / replay-capsule replacement-gap
work without touching the reserved core Rust files owned in other lanes.

What this support slice adds:

- a refreshed evidence pack that now points at the passing operator E2E bundle
  and structured event log
- a deterministic replay fixture index that includes the operator shell harness,
  checker, machine-readable fraud-proof witness bundle, the evidence-pack
  coherence checker, and a first-class `rch_tractability_benchmarks.json`
  report
- explicit `rch` build IDs and durations for one representative external replay
  verification lane and one representative trust-score update lane
- a tighter evidence-pack checker that fails if the benchmark report, budget,
  fixture-index summary, or human-readable references drift

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
- `python3 scripts/check_bd_1z5a_evidence_pack.py --json` now passes `28/28`
  checks. It verifies replacement-gap artifact paths, required fixture ids,
  current support-shard metadata, operator bundle/log linkage, fraud-proof
  witness references, canonical summary markdown, tractability benchmark build
  IDs/durations, and stale-gap regression phrases.
- `python3 scripts/check_bd_1z5a_evidence_pack.py --self-test --json` passed.
  Its internal mutation harness still forces a failure when stale-gap text is
  reintroduced.
- `python3 -m unittest tests/test_check_bd_1z5a_evidence_pack.py` now passes
  `13` tests, including tractability-benchmark fixture and budget regressions.
- `python3 -m py_compile scripts/check_bd_1z5a_evidence_pack.py tests/test_check_bd_1z5a_evidence_pack.py`
  passed.
- `rch` build `29747325727408129` passed strict test-surface clippy for
  `frankenengine-node`.
- `rch` build `29747325727408132` passed the existing trust-state verification
  probe.
- `rch` build `29747325727408133` passed strict
  `cargo clippy -p frankenengine-node --all-targets -- -D warnings` on the
  current shared tree.
- `rch` build `29747594884285383` passed the representative external replay
  verification lane in `475466ms`.
- `rch` build `29747594884285343` passed the representative trust-score update
  lane in `465686ms`.

## Tractability Benchmark Snapshot

The dedicated machine-readable report lives at
`artifacts/replacement_gap/bd-1z5a/rch_tractability_benchmarks.json` and
declares a per-lane tractability budget of `900000ms`.

| Lane | Build ID | Duration (ms) | Result |
|---|---:|---:|---|
| `external_replay_verification` | `29747594884285383` | `475466` | `PASS` |
| `trust_score_update_publication` | `29747594884285343` | `465686` | `PASS` |

## Replay / Score / Witness Inventory

The indexed fixture set is currently anchored in the existing Section 10.17
reports, conformance tests, and replacement-gap operator artifacts:

- `artifacts/10.17/verifier_sdk_certification_report.json`
- `tests/conformance/verifier_sdk_capsule_replay.rs`
- `artifacts/10.17/public_trust_scoreboard_snapshot.json`
- `tests/conformance/claim_compiler_gate.rs`
- `tests/e2e/verifier_replay_operator_suite.sh`
- `scripts/check_verifier_replay_operator_e2e.py`
- `scripts/check_bd_1z5a_evidence_pack.py`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_bundle.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-1z5a/fraud_proof_bundle.json`
- `artifacts/replacement_gap/bd-1z5a/rch_tractability_benchmarks.json`
- the replacement-critical Python checker + unittest pairs for
  `verifier_economy`, `connector/verifier_sdk`, and the replacement-gap
  evidence pack itself

That now gives us deterministic capsule-report, scoreboard-report, operator E2E,
structured event-log, witness-reference, artifact-coherence, and
benchmark-budget inputs in the replacement-gap lane.

## Remaining Gaps

- The parent bead remains in progress on the canonical shared verifier kernel
  itself, in the reserved Rust surfaces owned on RoseMountain's lane.
- This support pack proves the external replay / quarantine / scoreboard
  evidence path, records a machine-readable fraud-proof witness reference, and
  now includes explicit tractability proof for representative replay/score
  lanes, but it does not independently declare the underlying core verifier
  implementation complete.

## Notes

- The older `bd-1z5a.2` evidence-pack gaps for operator shell coverage,
  acceptance-specific event-family artifacts, and a replacement-gap witness
  bundle are now closed by the passing operator E2E bundle and
  `fraud_proof_bundle.json`.
- This refresh makes both the older `bd-1z5a.9` coherence guard and the newer
  `bd-1z5a.14` tractability proof discoverable directly from the replacement-gap
  pack instead of only from agent-mail thread history.
- The operator bundle is normalized to one coherent trace id:
  `trace-bd-1z5a-operator-e2e-final`.
- The witness bundle is intentionally truthful and minimal: it records the
  extracted fraud-proof id, trace binding, and source artifact references
  without inventing a counterexample payload that current stage outputs do not
  expose.
