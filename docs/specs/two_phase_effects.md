# Two-Phase Effects Channel Contract

## Overview

All side-effecting operations in the connector layer MUST use obligation-tracked
two-phase channels. This contract defines the reserve/commit/rollback protocol
that prevents obligation leaks, partial commits, and orphaned state transitions.

## Protocol

### Phase 1: Reserve

The caller requests an obligation slot by calling `reserve()` with a flow identifier
and an operation-specific payload. The tracker allocates an `ObligationId` and records
the tentative effect. No external state changes are visible until commit.

```
obligation_id = tracker.reserve(flow, payload, trace_id)
```

### Phase 2a: Commit

If all preconditions are satisfied, the caller finalizes the obligation:

```
tracker.commit(obligation_id, trace_id)
```

The effect becomes permanent and visible. The obligation transitions to `Committed`.

### Phase 2b: Rollback

If any precondition fails, the caller rolls back the obligation:

```
tracker.rollback(obligation_id, trace_id)
```

All tentative resources are released. The obligation transitions to `RolledBack`.

## Leak Detection

Obligations that remain in `Reserved` state beyond `leak_timeout_secs` (default: 30)
are detected by the periodic leak scan. The scanner:

1. Iterates all obligations in `Reserved` state
2. Computes elapsed time since reservation
3. Force-rolls-back any obligation exceeding the timeout
4. Emits OBL-004 for each leaked obligation
5. Emits OBL-005 when the scan completes

## Tracked Flows

| Flow | Description |
|------|-------------|
| publish | Trust object publication to peers |
| revoke | Trust object revocation broadcast |
| quarantine | Quarantine state transition |
| migration | Schema or data migration step |
| fencing | Fencing token acquisition/release |

## Invariants

- **INV-OBL-TWO-PHASE**: Every side-effecting operation goes through reserve/commit/rollback
- **INV-OBL-NO-LEAK**: No obligation remains in Reserved state beyond the leak timeout
- **INV-OBL-ATOMIC-COMMIT**: Commit is all-or-nothing
- **INV-OBL-ROLLBACK-SAFE**: Rollback is idempotent and always succeeds
- **INV-OBL-AUDIT-COMPLETE**: Every lifecycle event is auditable
- **INV-OBL-SCAN-PERIODIC**: The leak oracle runs on a configurable interval

## Event Codes

| Code | Meaning |
|------|---------|
| OBL-001 | Obligation reserved |
| OBL-002 | Obligation committed |
| OBL-003 | Obligation rolled back |
| OBL-004 | Obligation leak detected |
| OBL-005 | Leak scan completed |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_OBL_ALREADY_COMMITTED | Cannot rollback or re-commit a committed obligation |
| ERR_OBL_ALREADY_ROLLED_BACK | Cannot commit or re-rollback a rolled-back obligation |
| ERR_OBL_NOT_FOUND | Unknown obligation ID |
| ERR_OBL_LEAK_TIMEOUT | Obligation exceeded leak timeout |
| ERR_OBL_DUPLICATE_RESERVE | Duplicate reservation for same flow+key |
