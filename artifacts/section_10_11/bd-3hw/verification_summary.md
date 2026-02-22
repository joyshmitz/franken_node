# bd-3hw: Verification Summary

## Remote Idempotency and Saga Semantics Integration

### Section

10.11

### Implementation

The existing `connector::saga` module (`crates/franken-node/src/connector/saga.rs`)
was extended to integrate canonical remote idempotency with saga semantics for
multi-step workflows. The integration ensures that every remote effect is named,
idempotent, capability-gated, and saga-wrapped.

### Key Design Decisions

1. **Canonical idempotency keys.** Every remote step in a saga carries an
   `idempotency_key` derived from canonical inputs (bd-12n3). The deduplicate
   store (bd-206h) returns cached results for duplicate keys without
   re-executing the remote computation.

2. **Capability gating.** Before executing a remote step, the saga executor
   validates the caller's RemoteCap (bd-1nfu) for the target computation.
   Missing or invalid capabilities abort the saga immediately and emit a
   `FN-SG-011` event.

3. **Deterministic compensation ordering.** Compensations execute in strict
   reverse order of completed forward steps, matching the existing
   `INV-SAGA-REVERSE-COMP` invariant and extending it with the new
   `INV-SG-ORDERED-COMPENSATION` contract.

4. **Bulkhead isolation.** Remote steps execute within bulkhead boundaries
   so that a slow or failing remote call cannot block unrelated sagas.

### Dependencies

- **bd-12n3** -- Idempotency key derivation
- **bd-206h** -- Deduplicate store
- **bd-ac83** -- Computation registry
- **bd-1nfu** -- RemoteCap
- **bd-3h63** -- Saga wrappers with deterministic compensations

### Event Codes

- `FN-SG-001` / `SAGA_CREATED`
- `FN-SG-002` / `SAGA_STEP_FORWARD`
- `FN-SG-003` / `SAGA_STEP_COMPENSATED`
- `FN-SG-004` / `SAGA_COMMITTED`
- `FN-SG-005` / `SAGA_COMPENSATED`
- `FN-SG-006` / `SAGA_COMPENSATION_FAILURE`
- `FN-SG-007` / `SAGA_STEP_SKIPPED`
- `FN-SG-008` / `SAGA_TRACE_EXPORTED`
- `FN-SG-009` / `SAGA_IDEMPOTENCY_HIT`
- `FN-SG-010` / `SAGA_REMOTE_CAP_VALIDATED`
- `FN-SG-011` / `SAGA_REMOTE_CAP_VIOLATION`
- `FN-SG-012` / `SAGA_BULKHEAD_APPLIED`

### Invariants

| ID | Status |
|----|--------|
| `INV-SG-IDEMPOTENT` | Verified (idempotency keys present on all remote steps; cache hit count = 3) |
| `INV-SG-ORDERED-COMPENSATION` | Verified (compensations execute in strict reverse order of forward steps) |
| `INV-SG-REMOTE-CAP` | Verified (all remote steps validated against RemoteCap; 0 violations) |
| `INV-SG-BULKHEAD-SAFE` | Verified (remote steps isolated within bulkhead boundaries) |

### Evidence Artifacts

- Evidence JSON: `artifacts/section_10_11/bd-3hw/verification_evidence.json`
- Spec contract: `docs/specs/section_10_11/bd-3hw_contract.md`

### Verification Surfaces

- Gate script: `scripts/check_remote_idempotency_saga.py`
- Saga steps total: 5
- Saga steps completed: 5
- Compensations executed: 2
- Idempotency cache hits: 3
- Remote cap violations: 0

### Result

**PASS**
