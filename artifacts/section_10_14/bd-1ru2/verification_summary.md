# bd-1ru2: Verification Summary

## Cancel-Safe Eviction Saga

**Section:** 10.14 (Remote Subsystem)
**Status:** PASS (12/12 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-21

## Implementation

- **Module:** `crates/franken-node/src/remote/eviction_saga.rs`
- **Spec:** `docs/specs/section_10_14/bd-1ru2_contract.md`
- **Verification:** `scripts/check_eviction_saga.py`
- **Tests:** `tests/test_check_eviction_saga.py`

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-ES-CANCEL-SAFE | PASS | `cancel_saga()` triggers deterministic compensation per phase |
| INV-ES-DETERMINISTIC | PASS | `content_hash()` uses SHA-256 of canonical serialization |
| INV-ES-LEAK-FREE | PASS | `leak_check()` scans for orphaned artifacts post-saga |
| INV-ES-GATED | PASS | `start_saga()` rejects when `has_remote_cap == false` |
| INV-ES-PERSISTED | PASS | All transitions recorded in `SagaInstance.transitions` |
| INV-ES-AUDITABLE | PASS | `export_audit_log_jsonl()` and `export_saga_trace_jsonl()` |

## Types Implemented

- `SagaPhase` -- 8 states (Created, Uploading, Verifying, Retiring, Complete, Compensating, Compensated, Failed)
- `CompensationAction` -- 4 variants (AbortUpload, CleanupL3, CompleteRetirement, None)
- `PhaseTransition` -- transition record with saga_id, artifact_id, from/to phase, timestamp, outcome
- `EsAuditRecord` -- structured audit entry with event_code, trace_id, detail
- `LeakCheckResult` -- orphan scan result with orphans_found, details, passed
- `SagaInstance` -- individual saga state with phase, artifact presence flags, transitions
- `EvictionSagaManager` -- central coordinator with BTreeMap of sagas and audit log

## Event Codes (12)

ES_SAGA_START, ES_PHASE_UPLOAD, ES_PHASE_VERIFY, ES_PHASE_RETIRE, ES_SAGA_COMPLETE,
ES_COMPENSATION_START, ES_COMPENSATION_COMPLETE, ES_LEAK_CHECK_PASSED,
ES_LEAK_CHECK_FAILED, ES_CRASH_RECOVERY, ES_CANCEL_REQUESTED, ES_AUDIT_EMITTED

## Compensation Matrix

| Phase | Action | L2 | L3 |
|-------|--------|----|----|
| Uploading | AbortUpload | Intact | Cleared |
| Verifying | CleanupL3 | Intact | Cleared |
| Retiring | CompleteRetirement | Removed | Confirmed |

## Test Results

- **17 Rust unit tests** in module -- all passing
- **12 verification checks** -- all passing (PASS)
- **22 Python unit tests** -- all passing
- **Coverage:** full saga lifecycle, cancellation at each phase, leak detection, crash recovery, deterministic hashing, audit JSONL export, RemoteCap gating, invalid transitions, multiple concurrent sagas

## Operations

| Operation | Purpose |
|-----------|---------|
| `new()` | Construct empty manager |
| `init(trace_id)` | Construct with initialization audit event |
| `start_saga()` | Create saga (requires RemoteCap) |
| `begin_upload()` | Created -> Uploading |
| `complete_upload()` | Uploading -> Verifying (sets l3_present) |
| `complete_verify()` | Verifying -> Retiring (sets l3_verified) |
| `complete_retire()` | Retiring -> Complete (clears l2_present) |
| `cancel_saga()` | Cancel with deterministic compensation |
| `recover_saga()` | Crash recovery: determine compensation |
| `leak_check()` | Scan for orphaned artifacts |
| `get_saga()` | Look up saga by ID |
| `export_audit_log_jsonl()` | Export audit log as JSONL |
| `export_saga_trace_jsonl()` | Export transitions as JSONL |
| `content_hash()` | SHA-256 of canonical state |
| `saga_count()` | Number of tracked sagas |
