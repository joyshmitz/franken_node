# bd-1cs7: Implement REQUEST -> DRAIN -> FINALIZE Cancellation Protocol

---
schema_version: cancel-v1.0
bead_id: bd-1cs7
section: "10.15"
---

## Summary

Implements a three-phase cancellation protocol (REQUEST, DRAIN, FINALIZE) across
high-impact workflows in the connector lifecycle, rollout state, and health gate
subsystems. The protocol ensures that cancellation of long-running operations is
orderly: in-flight work is drained before resources are released, preventing
resource leaks and half-committed state.

## Three-Phase Protocol

| Phase | Description | Event Code |
|-------|-------------|------------|
| REQUEST | Cancellation signal received; no new work accepted | CAN-001 |
| DRAIN | In-flight operations complete or timeout | CAN-002 (start), CAN-003 (complete), CAN-004 (timeout) |
| FINALIZE | Resources released, state committed to terminal | CAN-005 (complete), CAN-006 (resource leak detected) |

### Per-Workflow Cleanup Budgets

| Workflow | Budget (ms) | Rationale |
|----------|-------------|-----------|
| lifecycle | 5000 | Long-running init/shutdown with persistent state |
| rollout | 3000 | Peer notification and canary checks |
| publish | 2000 | Evidence publication and commit |
| revoke | 2000 | Credential/token revocation propagation |
| quarantine | 3000 | Quarantine promotion with trust verification |
| migration | 5000 | Schema migration with data transfer |

### Timeout Behavior

When a phase exceeds its cleanup budget:
1. CAN-004 (drain timeout) is emitted
2. Force-finalize is triggered with error evidence attached
3. Any outstanding resources are tracked and CAN-006 emitted if leaked
4. The protocol transitions to Completed with `force_finalized = true`

### Cx Integration

The cancellation protocol integrates with the Cx tracing context:
- Each phase transition carries a `trace_id` from the originating Cx
- Audit events reference the Cx span for correlation
- Budget timeouts include the Cx context in their error evidence

## Protocol State Machine

```
IDLE --> REQUESTED --> DRAINING --> FINALIZING --> COMPLETED
              |            |              |
              v            v              v
          (idempotent) DRAIN_TIMEOUT   LEAK_DETECTED
                           |              |
                           v              v
                       FINALIZING    COMPLETED(err)
```

## Invariants

| ID | Statement |
|----|-----------|
| INV-CAN-THREE-PHASE | All cancellations pass through REQUEST, DRAIN, FINALIZE in order |
| INV-CAN-BUDGET-BOUNDED | Every workflow has a finite cleanup budget; exceeded triggers force-finalize |
| INV-CAN-PROPAGATION | Cancellation propagates to all child operations within a workflow |
| INV-CAN-NO-LEAK | After FINALIZE, no resource leaks exist (CAN-006 on violation) |

## Event Codes

| Code | Description |
|------|-------------|
| CAN-001 | Cancel requested |
| CAN-002 | Drain started |
| CAN-003 | Drain completed |
| CAN-004 | Drain timeout |
| CAN-005 | Finalize completed |
| CAN-006 | Resource leak detected |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_CANCEL_INVALID_PHASE | Phase transition not allowed from current state |
| ERR_CANCEL_ALREADY_FINAL | Cancellation attempted on already-finalized workflow |
| ERR_CANCEL_DRAIN_TIMEOUT | Drain exceeded configured timeout |
| ERR_CANCEL_LEAK | Resources leaked during finalization |

## Gate Behavior

The gate script (`scripts/check_cancellation_protocol.py`) verifies:
1. Rust module exists at `crates/franken-node/src/connector/cancellation_protocol.rs`
2. Module is wired in `connector/mod.rs`
3. Spec contract exists
4. All four invariant constants are present in source
5. All six event codes (CAN-001 through CAN-006) are present
6. Timing CSV exists at `artifacts/10.15/cancel_protocol_timing.csv`
7. Unit tests >= 15 present in source module
8. Phase enum includes all five states
9. Budget struct with timeout durations exists
10. ResourceGuard with Drop safety exists

Exit 0 on PASS, exit 1 on FAIL.

## Acceptance Criteria

1. Three-phase protocol types exist in `cancellation_protocol.rs`
2. CancellationPhase enum covers Idle, Requested, Draining, Finalizing, Completed
3. CancellationBudget struct with per-workflow timeout durations
4. CancellationProtocol struct managing phase transitions as a state machine
5. request() -> drain() -> finalize() state machine methods
6. Force-finalize on budget timeout
7. ResourceGuard with Drop safety
8. All six event codes emitted at correct phase boundaries
9. Resource leak detection in finalize phase
10. Timing artifact at `artifacts/10.15/cancel_protocol_timing.csv`
11. Gate script passes all checks

## Dependencies

- **Upstream**: bd-876n (cancellation injection framework, 10.14)
- **Upstream**: bd-1vsr (transition abort semantics, 10.14)

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_15/bd-1cs7_contract.md` |
| Protocol implementation | `crates/franken-node/src/connector/cancellation_protocol.rs` |
| Timing CSV | `artifacts/10.15/cancel_protocol_timing.csv` |
| Verification script | `scripts/check_cancellation_protocol.py` |
| Python tests | `tests/test_check_cancellation_protocol.py` |
| Verification evidence | `artifacts/section_10_15/bd-1cs7/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-1cs7/verification_summary.md` |
