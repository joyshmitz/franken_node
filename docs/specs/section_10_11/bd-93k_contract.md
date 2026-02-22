# bd-93k Contract: Checkpoint Placement for Long Orchestration Loops

## Scope

This contract defines deterministic checkpoint persistence, hash-chain integrity, and runtime checkpoint-placement enforcement for long orchestration loops.

## Core APIs

- `CheckpointWriter<B: CheckpointBackend>`
- `CheckpointContract`
  - `save_checkpoint(...) -> Result<CheckpointId, CheckpointError>`
  - `restore_checkpoint(...) -> Result<Option<RestoredCheckpoint<T>>, CheckpointError>`
  - `list_checkpoints(...) -> Result<Vec<CheckpointMeta>, CheckpointError>`
- `CheckpointGuard`
  - `on_iteration(iteration_count)`
  - `checkpoint(iteration_count)`

## Placement Rules

1. Every long orchestration loop must checkpoint no less frequently than:
   - `max_iterations_between_checkpoints` (default `100`), or
   - `max_duration_between_checkpoints` (default `5000ms`),
   whichever comes first.
2. In `GuardMode::Warn`, violations emit warnings and continue.
3. In `GuardMode::Strict`, violations beyond `strict_abort_multiplier` (default `2x`) abort with `CHECKPOINT_CONTRACT_VIOLATION`.

## Integrity Rules

1. Checkpoints are content-addressed:
   - `checkpoint_id = sha256(orchestration_id, iteration, epoch, progress_state_hash, previous_checkpoint_hash)`.
2. Checkpoints form a hash chain through `previous_checkpoint_hash`.
3. Reader verification must reject corrupted chain links and continue with the latest valid checkpoint.

## Cancellation Semantics

`save_checkpoint` performs backend persistence through `bounded_mask` so cancellation is deferred during the atomic write section and delivered immediately after unmask.

## Invariants

| Invariant | Description |
|---|---|
| `INV-CK-PLACEMENT` | Long loops must checkpoint within configured iteration/time bounds. |
| `INV-CK-IDEMPOTENT` | Saving identical checkpoint state yields identical `CheckpointId`. |
| `INV-CK-HASH-CHAIN` | Tampered checkpoint records are detected by chain verification. |
| `INV-CK-RESUME` | Restart resumes from latest valid checkpoint, not from loop start. |
| `INV-CK-AUDIT` | Checkpoint operations emit structured event records. |

## Structured Events

- `FN-CK-001` / `CHECKPOINT_SAVE`
- `FN-CK-002` / `CHECKPOINT_RESTORE`
- `FN-CK-003` / `CHECKPOINT_HASH_CHAIN_FAILURE`
- `FN-CK-004` / `CHECKPOINT_RESUME`
- `FN-CK-005` / `CHECKPOINT_IDEMPOTENT_REUSE`
- `FN-CK-006` / `CHECKPOINT_WARNING`
- `FN-CK-007` / `CHECKPOINT_CONTRACT_VIOLATION`
- `FN-CK-008` / `CHECKPOINT_DECISION_STREAM_APPEND`

## Verification Artifacts

- `scripts/check_checkpoint_placement.py`
- `tests/test_check_checkpoint_placement.py`
- `artifacts/section_10_11/bd-93k/verification_evidence.json`
- `artifacts/section_10_11/bd-93k/verification_summary.md`
