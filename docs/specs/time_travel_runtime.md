# Time-Travel Runtime Capture/Replay Contract (bd-1xbc)

## Scope

This contract defines the deterministic time-travel capture/replay runtime for
extension-host workflows in `franken_node`. Captured executions replay
byte-for-byte equivalent control decisions under the same seed/input. Incident
replay includes stepwise state navigation and divergence explanation.

## Core Invariants

- `INV-REPLAY-DETERMINISTIC`: replayed executions produce byte-for-byte identical
  control decisions when given the same seed and input sequence.
- `INV-REPLAY-SEED-EQUIVALENCE`: two executions sharing the same seed and input
  sequence converge to the same final state digest.
- `INV-REPLAY-STEP-NAVIGATION`: the replay engine supports forward and backward
  stepwise navigation through recorded execution states.
- `INV-REPLAY-DIVERGENCE-EXPLAIN`: when a replay diverges from its capture, the
  engine produces a structured explanation identifying the first divergent step,
  the expected versus actual state, and the probable cause.

## Capture Protocol

1. A workflow execution session is opened with `capture_start(seed, workflow_id)`.
2. Every control decision (branch, dispatch, yield) is recorded as a `CapturedStep`.
3. Each step records: step index, input hash, state digest before/after, decision tag.
4. On completion `capture_complete()` seals the trace with a final digest covering
   all steps. Event `REPLAY_CAPTURE_COMPLETE` is emitted.

## Replay Protocol

1. `playback_start(capture)` loads a sealed capture and resets the engine.
2. The engine re-executes each step using the original seed and inputs.
3. After each step, the replayed state digest is compared to the recorded digest.
4. If all steps match, event `REPLAY_PLAYBACK_MATCH` is emitted.
5. On mismatch, `REPLAY_DIVERGENCE_DETECTED` is emitted with a `DivergenceReport`.

## Stepwise Navigation

The replay engine exposes `step_forward()` and `step_backward()` for incident
debugging. At each position the current step, state digest, and decision are
available. Backward navigation restores the snapshot recorded during capture.

## Divergence Explanation

A `DivergenceReport` contains:

- `step_index`: the first step where divergence occurred.
- `expected_digest`: state digest from the original capture.
- `actual_digest`: state digest produced during replay.
- `decision_tag`: the control decision at the divergent step.
- `probable_cause`: one of `SeedMismatch`, `InputMissing`, `ClockDrift`,
  `SnapshotInvalid`, `StateCorruption`, `StepOverflow`.

## Event Codes

- `REPLAY_CAPTURE_START` -- capture session opened.
- `REPLAY_CAPTURE_COMPLETE` -- capture sealed with final digest.
- `REPLAY_PLAYBACK_START` -- replay session initiated.
- `REPLAY_PLAYBACK_MATCH` -- replay matches capture byte-for-byte.
- `REPLAY_DIVERGENCE_DETECTED` -- replay diverges from capture.

## Error Codes

- `ERR_REPLAY_SEED_MISMATCH` -- replay seed differs from capture seed.
- `ERR_REPLAY_STATE_CORRUPTION` -- internal state integrity check failed.
- `ERR_REPLAY_STEP_OVERFLOW` -- step index exceeds capture length.
- `ERR_REPLAY_INPUT_MISSING` -- required input for step not available.
- `ERR_REPLAY_CLOCK_DRIFT` -- deterministic clock deviates beyond tolerance.
- `ERR_REPLAY_SNAPSHOT_INVALID` -- snapshot restoration failed validation.

## Required Artifacts

- `crates/franken-node/src/replay/time_travel_engine.rs`
- `crates/franken-node/src/replay/mod.rs`
- `tests/lab/time_travel_replay_equivalence.rs`
- `artifacts/10.17/time_travel_replay_report.json`
- `artifacts/section_10_17/bd-1xbc/verification_evidence.json`
- `artifacts/section_10_17/bd-1xbc/verification_summary.md`
