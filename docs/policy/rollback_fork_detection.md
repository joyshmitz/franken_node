# Rollback/Fork Detection Policy

**Bead:** bd-2ms
**Section:** 10.10 (FCP-Inspired Hardening)
**Effective:** 2026-02-20

## Overview

This policy defines the control-plane behavior when rollback or fork conditions
are detected across distributed nodes. It establishes mandatory responses,
operator workflows, and audit requirements.

## Detection Classes

### CONVERGED
Both replicas share identical state at the same epoch. No action required.

### FORKED
Replicas report different state hashes at the same epoch. This indicates either
a Byzantine fault or a software bug. All control-plane mutations MUST be halted
until operator review.

### GAP_DETECTED
Epoch difference exceeds 1 between replicas. This may indicate network partition
or delayed propagation. The system returns the range of missing epochs for
operator triage.

### ROLLBACK_DETECTED
The parent_state_hash of a newer state does not match the state_hash of the
older state. This indicates an unauthorized rollback. All mutations MUST be
halted and a RollbackProof emitted for audit.

## Mandatory Responses

1. **HALT**: On FORKED or ROLLBACK_DETECTED, all control-plane mutations
   (policy updates, token issuance, zone boundary changes) are blocked.

2. **ALERT**: Structured CRITICAL-severity log event with full divergence
   evidence including both state vectors, trace_id, and detection timestamp.

3. **AUDIT**: RollbackProof is persisted to the audit log for post-incident
   analysis and compliance reporting.

4. **RECONCILIATION**: System generates a ReconciliationSuggestion with
   actionable information:
   - For GAP_DETECTED: missing epoch range
   - For FORKED: both competing state hashes

## Recovery Requirements

- Recovery from FORKED or ROLLBACK_DETECTED requires explicit operator approval.
- No automatic recovery from divergence states.
- Operator must review the RollbackProof before authorizing re-sync.

## Invariant Enforcement

All four invariants (INV-RFD-DETECT-FORK, INV-RFD-DETECT-ROLLBACK,
INV-RFD-HALT-ON-DIVERGENCE, INV-RFD-PROOF-SERIALIZABLE) are enforced at the
type system level. Violations are compile-time errors where possible and
runtime CRITICAL alerts otherwise.

## Compliance

Evidence of detection and response is maintained in structured JSON format
for reproducible verification and independent audit.
