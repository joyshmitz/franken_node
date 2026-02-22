# bd-2ms: Rollback/Fork Detection in Control-Plane State Propagation

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-02-21

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 128 | 128 |
| Rust unit tests | 45 | 45 |
| Python unit tests | 33 | 33 |

## Implementation

**File:** `crates/franken-node/src/control_plane/divergence_gate.rs`

### Core Types
- `ControlPlaneDivergenceGate` — product-level gate with state machine
- `ResponseMode` — HALT, QUARANTINE, ALERT, RECOVER
- `GateState` — Normal, Diverged, Quarantined, Alerted, Recovering
- `MutationKind` — PolicyUpdate, TokenIssuance, ZoneBoundaryChange, RevocationPublish, EpochTransition, QuarantinePromotion
- `DivergenceGateError` — DivergenceBlock, InvalidTransition, UnauthorizedRecovery, FreshnessFailed
- `OperatorAuthorization` — SHA-256 signed authorization for recovery
- `QuarantinePartition`, `OperatorAlert`, `GateAuditEntry`, `MutationCheckResult`, `RecoveryResult`

### Key API Methods
- `check_propagation()` — compare state vectors, detect divergence
- `check_mutation()` — gate mutations, block during active divergence
- `respond_halt()` — HALT response (mutations blocked)
- `respond_quarantine()` — isolate divergent partition
- `respond_alert()` — dispatch structured operator alert
- `respond_recover()` — re-sync with operator authorization

### Event Codes (8)
| Code | Description |
|------|-------------|
| DG-001 | Divergence detected |
| DG-002 | Mutation blocked |
| DG-003 | Response mode activated |
| DG-004 | Recovery completed |
| DG-005 | Freshness verified |
| DG-006 | Partition quarantined |
| DG-007 | Operator alerted |
| DG-008 | Marker proof verified |

### Invariants (4)
- **INV-DG-NO-MUTATION**: No mutation during active divergence
- **INV-DG-OPERATOR-RECOVERY**: Recovery requires signed operator authorization
- **INV-DG-ONE-CYCLE**: Divergence detected within one propagation cycle
- **INV-DG-VALID-TRANSITIONS**: State machine transitions follow valid paths

### Upstream Integration
Wraps primitives from:
- `fork_detection.rs` — DivergenceDetector, MarkerProofVerifier, StateVector
- `marker_stream.rs` — MarkerStream
- `mmr_proofs.rs` — MMR checkpoint/proof APIs
