# bd-1xbc: Deterministic Time-Travel Runtime Capture/Replay

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-1xbc |
| Section | 10.17 |
| Title | Add deterministic time-travel runtime capture/replay for extension-host workflows |
| Type | task |

## Purpose

Extension-host workflows in the franken_node radical expansion track must be
fully reproducible for incident analysis, regression testing, and audit.
This bead implements a deterministic time-travel runtime that captures every
control decision made during an extension-host workflow execution and replays
them byte-for-byte under the same seed and input.

The time-travel runtime provides:
- Frame-by-frame capture of all extension-host control decisions.
- A deterministic clock that eliminates wallclock non-determinism from replays.
- Stepwise state navigation (forward and backward) during incident replay.
- Divergence detection and explanation when replayed execution deviates from
  the captured trace.
- Workflow snapshot serialization for offline analysis and long-term archival.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-1xbc_contract.md` |
| Rust module | `crates/franken-node/src/runtime/time_travel.rs` |
| Check script | `scripts/check_time_travel_replay.py` |
| Test suite | `tests/test_check_time_travel_replay.py` |
| Evidence | `artifacts/section_10_17/bd-1xbc/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-1xbc/verification_summary.md` |

## Invariants

### Implementation-Level Invariants

- **INV-TTR-DETERMINISM**: Replay of captured traces produces bit-identical
  outcomes under identical environment assumptions.
- **INV-TTR-DIVERGENCE-DETECT**: Any divergence between original and replayed
  outputs is detected and reported with structured diagnostics.
- **INV-TTR-TRACE-COMPLETE**: Every captured trace includes all inputs, outputs,
  side-effects, and environment state necessary for faithful replay.
- **INV-TTR-STEP-ORDER**: Trace steps are strictly ordered by sequence number;
  replays respect that order.
- **INV-TTR-ENV-SEALED**: The environment snapshot is immutable once captured;
  replays use the sealed snapshot.
- **INV-TTR-AUDIT-COMPLETE**: Every capture, replay, and divergence event is
  logged with a stable event code and trace correlation ID.

### Contract-Level Invariants

- **INV-REPLAY-DETERMINISTIC**: Replayed executions produce byte-for-byte identical
  control decisions when given the same seed and input sequence.
- **INV-REPLAY-SEED-EQUIVALENCE**: Two executions sharing the same seed and input
  sequence converge to the same final state digest.
- **INV-REPLAY-STEP-NAVIGATION**: The replay engine supports forward and backward
  stepwise navigation through recorded execution states.
- **INV-REPLAY-DIVERGENCE-EXPLAIN**: When a replay diverges from its capture, the
  engine produces a structured explanation identifying the first divergent step.

## Event Codes

### TTR-Series (Implementation)

| Code | Description |
|------|-------------|
| TTR-001 | Workflow trace capture started |
| TTR-002 | Trace step recorded |
| TTR-003 | Workflow trace capture completed |
| TTR-004 | Replay started |
| TTR-005 | Replay step compared (identical) |
| TTR-006 | Replay step diverged |
| TTR-007 | Replay completed -- verdict emitted |
| TTR-008 | Environment snapshot sealed |
| TTR-009 | Trace integrity check passed |
| TTR-010 | Trace integrity check failed |

### Contract-Level Event Codes

| Code | Description |
|------|-------------|
| REPLAY_CAPTURE_START | Capture session opened |
| REPLAY_CAPTURE_COMPLETE | Capture sealed with final digest |
| REPLAY_PLAYBACK_START | Replay session initiated |
| REPLAY_PLAYBACK_MATCH | Replay matches capture byte-for-byte |
| REPLAY_DIVERGENCE_DETECTED | Replay diverges from capture |

## Error Codes

### TTR-Series (Implementation)

| Code | Description |
|------|-------------|
| ERR_TTR_EMPTY_TRACE | Trace has no steps |
| ERR_TTR_SEQ_GAP | Sequence gap detected in trace steps |
| ERR_TTR_DIGEST_MISMATCH | Trace digest does not match recomputed value |
| ERR_TTR_ENV_MISSING | Environment snapshot is missing required fields |
| ERR_TTR_REPLAY_FAILED | Replay execution failed |
| ERR_TTR_DUPLICATE_TRACE | Trace with this ID already exists in engine |
| ERR_TTR_STEP_ORDER_VIOLATION | Steps violate ordering invariant |
| ERR_TTR_TRACE_NOT_FOUND | Trace not found in engine |

### Contract-Level Error Codes

| Code | Description |
|------|-------------|
| ERR_REPLAY_SEED_MISMATCH | Replay seed differs from capture seed |
| ERR_REPLAY_STATE_CORRUPTION | Internal state integrity check failed |
| ERR_REPLAY_STEP_OVERFLOW | Step index exceeds capture length |
| ERR_REPLAY_INPUT_MISSING | Required input for step not available |
| ERR_REPLAY_CLOCK_DRIFT | Deterministic clock deviates beyond tolerance |
| ERR_REPLAY_SNAPSHOT_INVALID | Snapshot restoration failed validation |

## Acceptance Criteria

1. Captured executions replay byte-for-byte equivalent control decisions under
   same seed/input.
2. Incident replay includes stepwise state navigation (forward + backward)
   and divergence explanation.
3. Module contains >= 20 inline `#[test]` functions covering all invariants,
   error codes, and edge cases.
4. All event codes (TTR_001..TTR_010) and error codes (ERR_TTR_*) are present
   as constants in the Rust source.
5. BTreeMap is used for all map types to guarantee deterministic ordering.
6. Schema version constant is present and prefixed `ttr-v`.

## Dependencies

- bd-274s: Bayesian adversary graph (blocker, in progress)
