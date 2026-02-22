# Remote Bulkhead Contract (bd-v4l0)

## Goal
Enforce a global cap on in-flight remote operations so overload cannot cascade into
foreground latency collapse.

## Core API
- `RemoteBulkhead::new(max_in_flight, policy, p99_target_ms) -> Result<RemoteBulkhead>`
- `acquire(has_remote_cap, request_id, now_ms) -> Result<BulkheadPermit, BulkheadError>`
- `poll_queued(request_id, now_ms) -> Result<BulkheadPermit, BulkheadError>`
- `release(permit, now_ms) -> Result<(), BulkheadError>`
- `set_max_in_flight(new_cap, now_ms) -> Result<(), BulkheadError>`
- `current_in_flight() -> usize`

## Backpressure Policies
- `Reject`
- `Queue { max_depth, timeout_ms }`

Queue mode is deterministic and explicit:
1. `acquire` at capacity returns `BulkheadError::Queued`.
2. Caller retries with `poll_queued`.
3. Queue entries expire via `timeout_ms` and are fail-closed rejected.

## Runtime Cap Changes
- Increasing cap applies immediately.
- Decreasing cap enters drain mode if `in_flight > new_cap`.
- In drain mode, new acquires are rejected with `RB_ERR_DRAINING`.
- Existing in-flight operations are never force-cancelled.

## Remote Capability Requirement
All acquires require an explicit `RemoteCap` signal (`has_remote_cap=true`).
Missing capability fails closed (`RB_ERR_NO_REMOTECAP`).

## Latency Budget Contract
- Foreground latency samples are recorded and p99 is computed deterministically.
- Release gate target: `p99 <= 50ms` under saturation profiles (cap 8/32/128).

## Structured Event Codes
- `RB_PERMIT_ACQUIRED`
- `RB_PERMIT_RELEASED`
- `RB_AT_CAPACITY`
- `RB_REQUEST_QUEUED`
- `RB_REQUEST_REJECTED`
- `RB_CAP_CHANGED`
- `RB_DRAIN_ACTIVE`
- `RB_LATENCY_REPORT`

## Required Artifacts
- `artifacts/10.14/remote_bulkhead_latency_report.csv`
- `artifacts/section_10_14/bd-v4l0/verification_evidence.json`
- `artifacts/section_10_14/bd-v4l0/verification_summary.md`
