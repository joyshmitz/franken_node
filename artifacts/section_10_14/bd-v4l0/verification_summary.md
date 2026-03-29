# bd-v4l0: Verification Summary

## Global Remote Bulkhead with Deterministic Backpressure

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (16/16 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-21

## Implementation

- **Module:** `crates/franken-node/src/remote/remote_bulkhead.rs`
- **Spec:** `docs/specs/section_10_14/bd-v4l0_contract.md`
- **Verification:** `scripts/check_remote_bulkhead.py`
- **Unit tests:** `tests/test_check_remote_bulkhead.py`

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-RB-CAPPED | PASS | `acquire()` returns `AtCapacity` when `in_flight >= max_in_flight` under Reject policy |
| INV-RB-BACKPRESSURE | PASS | Both `Reject` and `Queue { max_depth, timeout_ms }` policies implemented and tested |
| INV-RB-SAFE-DRAIN | PASS | `set_max_in_flight()` activates `draining_target` when cap < in_flight; blocks new acquires |
| INV-RB-GATED | PASS | `has_remote_cap == false` yields `RemoteCapRequired` immediately |
| INV-RB-AUDITABLE | PASS | All state transitions emit `BulkheadEvent` with 8 stable event codes |
| INV-RB-DETERMINISTIC | PASS | `p99_foreground_latency_ms()` sort-then-rank is deterministic |

## Types Implemented

- `BackpressurePolicy` -- Reject or Queue with max_depth/timeout_ms
- `BulkheadPermit` -- permit_id, issued_at_ms, cap_snapshot
- `BulkheadEvent` -- event_code, now_ms, in_flight, max_in_flight, detail
- `ForegroundLatencySample` -- in_flight, latency_ms
- `BulkheadError` -- 11 error variants with stable RB_ERR_* codes
- `RemoteBulkhead` -- main concurrency limiter struct

## Event Codes

| Code | Verified |
|------|----------|
| RB_PERMIT_ACQUIRED | PASS |
| RB_PERMIT_RELEASED | PASS |
| RB_AT_CAPACITY | PASS |
| RB_REQUEST_QUEUED | PASS |
| RB_REQUEST_REJECTED | PASS |
| RB_CAP_CHANGED | PASS |
| RB_DRAIN_ACTIVE | PASS |
| RB_LATENCY_REPORT | PASS |

## Error Codes

| Code | Verified |
|------|----------|
| RB_ERR_NO_REMOTECAP | PASS |
| RB_ERR_AT_CAPACITY | PASS |
| RB_ERR_QUEUE_SATURATED | PASS |
| RB_ERR_QUEUED | PASS |
| RB_ERR_QUEUE_TIMEOUT | PASS |
| RB_ERR_UNKNOWN_REQUEST | PASS |
| RB_ERR_DUPLICATE_REQUEST | PASS |
| RB_ERR_UNKNOWN_PERMIT | PASS |
| RB_ERR_INVALID_REQUEST_ID | PASS |
| RB_ERR_DRAINING | PASS |
| RB_ERR_INVALID_CONFIG | PASS |

## Operations

| Operation | Purpose |
|-----------|---------|
| `new()` | Construct bulkhead with validated config |
| `acquire()` | Capability-gated permit acquisition with backpressure |
| `release()` | Return permit, decrement in-flight, clear drain if below target |
| `poll_queued()` | Retry admission for queued request |
| `set_max_in_flight()` | Hot-reload cap with drain semantics |
| `record_foreground_latency(latency_ms, now_ms)` | Record latency observation with an audit timestamp |
| `p99_foreground_latency_ms()` | Deterministic p99 computation |
| `latency_within_target()` | SLO gate: p99 <= target |

## Test Results

- **Rust unit tests** -- passing, including latency timestamp audit coverage
- **Verification checks** -- passing, including latency-event timestamp enforcement
- **Python unit tests** -- passing (structure, individual checks, self-test, CLI JSON, CLI self-test, human output)

## Verification Checks

| # | Check | Status | Detail |
|---|-------|--------|--------|
| 1 | SOURCE_EXISTS | PASS | Implementation file present |
| 2 | EVENT_CODES | PASS | 8/8 event codes |
| 3 | EVENT_CODES_MODULE | PASS | `pub mod event_codes` present |
| 4 | ERROR_CODES | PASS | 11/11 error codes |
| 5 | CORE_TYPES | PASS | 6/6 types |
| 6 | REMOTECAP_GATING | PASS | RemoteCap gating on acquire |
| 7 | DRAIN_MODE | PASS | drain mode on cap reduction |
| 8 | LATENCY_TRACKING | PASS | p99 latency tracking with target gate |
| 9 | LATENCY_EVENT_TIMESTAMP | PASS | latency events use caller-supplied now_ms |
| 10 | BACKPRESSURE_POLICY | PASS | Reject and Queue policies |
| 11 | CORE_OPERATIONS | PASS | 3/3 operations |
| 12 | PERMIT_LIFECYCLE | PASS | permit issuance and tracking |
| 13 | QUEUE_TIMEOUT | PASS | queue timeout eviction |
| 14 | SERDE_DERIVES | PASS | Serialize/Deserialize on public types |
| 15 | TEST_COVERAGE | PASS | 20 tests found (minimum 10) |
| 16 | SPEC_CONTRACT | PASS | spec contract exists |
