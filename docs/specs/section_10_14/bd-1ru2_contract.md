# bd-1ru2: Cancel-Safe Eviction Saga

## Purpose

Implement a multi-step saga for L2->L3 artifact lifecycle (upload, verify, retire)
with deterministic compensations. Guarantees no partial retire on cancellation or
crash. Each phase transition is recorded for audit, and compensation actions are
derived deterministically from the current phase.

## Invariants

- **INV-ES-CANCEL-SAFE**: Cancellation at any phase triggers a deterministic compensation
  action that leaves the system in a consistent state. No partial retires.
- **INV-ES-DETERMINISTIC**: Given identical saga state, compensation actions and content
  hashes are fully deterministic and reproducible.
- **INV-ES-LEAK-FREE**: After a full saga (success or compensated), no orphaned artifacts
  remain. Leak detection scans confirm zero orphans.
- **INV-ES-GATED**: Saga creation requires the `has_remote_cap` capability flag.
  Attempts without it are rejected with "RemoteCap required" error.
- **INV-ES-PERSISTED**: Every phase transition is recorded in the saga's transition log
  with saga_id, artifact_id, from_phase, to_phase, timestamp_ms, and outcome.
- **INV-ES-AUDITABLE**: All significant events are emitted to an audit log with stable
  event codes. Both audit log and saga traces are exportable as JSONL.

## Types

### SagaPhase

Enum of saga lifecycle states:
- `Created` -- initial state after saga construction
- `Uploading` -- L2->L3 upload in progress
- `Verifying` -- L3 content verification in progress
- `Retiring` -- L2 retirement in progress
- `Complete` -- saga completed successfully (L2 retired, L3 verified)
- `Compensating` -- compensation action in progress
- `Compensated` -- compensation completed, saga is safe
- `Failed` -- terminal failure state

### CompensationAction

Deterministic compensation for each interruptible phase:
- `AbortUpload` -- during Uploading: abort upload, L2 remains intact
- `CleanupL3` -- during Verifying: remove partial L3 state
- `CompleteRetirement` -- during Retiring: L3 is confirmed, complete the retirement
- `None` -- no compensation needed (Created, Complete, Compensated, Failed)

### PhaseTransition

Record of a single phase transition:
- `saga_id`: String
- `artifact_id`: String
- `from_phase`: SagaPhase
- `to_phase`: SagaPhase
- `timestamp_ms`: u64
- `outcome`: String

### EsAuditRecord

Structured audit entry:
- `event_code`: String (stable ES_* code)
- `trace_id`: String (distributed tracing correlation)
- `detail`: serde_json::Value (event-specific payload)

### LeakCheckResult

Result of orphan detection scan:
- `orphans_found`: usize
- `details`: Vec<String>
- `passed`: bool

### SagaInstance

Individual saga tracking:
- `saga_id`, `artifact_id`: String identifiers
- `phase`: SagaPhase (current state)
- `l2_present`, `l3_present`, `l3_verified`: bool (artifact presence flags)
- `transitions`: Vec<PhaseTransition> (full transition history)
- `has_remote_cap`: bool (capability flag)

### EvictionSagaManager

Central saga coordinator:
- `sagas`: BTreeMap<String, SagaInstance>
- `audit_log`: Vec<EsAuditRecord>
- `next_saga_id`: u64

## Compensation Matrix

| Current Phase | CompensationAction   | Effect                                |
|---------------|---------------------|---------------------------------------|
| Created       | None                | No action needed                      |
| Uploading     | AbortUpload         | L2 intact, L3 cleared                |
| Verifying     | CleanupL3           | L2 intact, L3 + verification cleared |
| Retiring      | CompleteRetirement  | L3 confirmed, L2 removed             |
| Complete      | None                | Already finished                      |
| Compensating  | None                | Already compensating                  |
| Compensated   | None                | Already compensated                   |
| Failed        | None                | Terminal state                        |

## Operations

### `new() -> EvictionSagaManager`
Construct an empty manager.

### `init(trace_id) -> EvictionSagaManager`
Construct and emit an initialization audit event.

### `start_saga(artifact_id, has_remote_cap, trace_id) -> Result<String, String>`
Create a new saga. Requires `has_remote_cap == true` (INV-ES-GATED). Returns saga_id.

### `begin_upload(saga_id, trace_id) -> Result<(), String>`
Advance from Created to Uploading.

### `complete_upload(saga_id, trace_id) -> Result<(), String>`
Advance from Uploading to Verifying. Sets `l3_present = true`.

### `complete_verify(saga_id, trace_id) -> Result<(), String>`
Advance from Verifying to Retiring. Sets `l3_verified = true`.

### `complete_retire(saga_id, trace_id) -> Result<(), String>`
Advance from Retiring to Complete. Sets `l2_present = false`.

### `cancel_saga(saga_id, trace_id) -> Result<CompensationAction, String>`
Cancel saga at current phase. Applies deterministic compensation (INV-ES-CANCEL-SAFE).
Transitions through Compensating to Compensated.

### `recover_saga(saga_id, trace_id) -> Result<CompensationAction, String>`
Crash recovery: determine compensation action for persisted phase (INV-ES-PERSISTED).

### `leak_check(trace_id) -> LeakCheckResult`
Scan all sagas for orphaned artifacts (INV-ES-LEAK-FREE).

### `get_saga(saga_id) -> Option<&SagaInstance>`
Look up saga by ID.

### `export_audit_log_jsonl() -> String`
Export full audit log as newline-delimited JSON (INV-ES-AUDITABLE).

### `export_saga_trace_jsonl() -> String`
Export all phase transitions as newline-delimited JSON.

### `content_hash() -> String`
SHA-256 of canonical saga state (INV-ES-DETERMINISTIC).

### `saga_count() -> usize`
Number of tracked sagas.

## Event Codes

- `ES_SAGA_START` -- new saga created or manager initialized
- `ES_PHASE_UPLOAD` -- upload phase entered
- `ES_PHASE_VERIFY` -- verify phase entered
- `ES_PHASE_RETIRE` -- retire phase entered
- `ES_SAGA_COMPLETE` -- saga completed successfully
- `ES_COMPENSATION_START` -- compensation initiated (via cancel)
- `ES_COMPENSATION_COMPLETE` -- compensation finished
- `ES_LEAK_CHECK_PASSED` -- leak scan found zero orphans
- `ES_LEAK_CHECK_FAILED` -- leak scan found orphans
- `ES_CRASH_RECOVERY` -- crash recovery invoked
- `ES_CANCEL_REQUESTED` -- cancellation requested
- `ES_AUDIT_EMITTED` -- audit record emitted

## Artifacts

- Implementation: `crates/franken-node/src/remote/eviction_saga.rs`
- Verification script: `scripts/check_eviction_saga.py`
- Unit tests: `tests/test_check_eviction_saga.py`
- Evidence: `artifacts/section_10_14/bd-1ru2/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-1ru2/verification_summary.md`
