# bd-2ms Contract: Rollback/Fork Detection in Control-Plane State

**Bead:** bd-2ms
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Implement rollback and fork detection for control-plane state propagation. When
distributed nodes in the three-kernel architecture (franken_engine + asupersync +
franken_node) observe divergent state histories, the system must detect the
divergence immediately and halt unsafe operations. Without this, a compromised
or partitioned node could silently operate under a stale or forked policy,
violating the no-ambient-authority invariant (8.5).

## Dependencies

- **Upstream:** bd-126h (append-only marker stream)
- **Upstream:** bd-xwk5 (fork/divergence detection via marker-id prefix comparison)
- **Upstream:** bd-1dar (optional MMR checkpoints and inclusion/prefix proof APIs)
- **Upstream:** bd-174 (policy checkpoint chain)
- **Downstream:** bd-1r2 (audience-bound token chains)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Structures

### StateVector

A canonical snapshot of control-plane state at a specific epoch:

| Field              | Type          | Description                                     |
|--------------------|---------------|-------------------------------------------------|
| epoch              | u64           | Control epoch number                            |
| marker_id          | String        | TrustObjectId (MARKER domain from bd-1l5)       |
| state_hash         | String        | SHA-256 of canonical-serialized state            |
| parent_state_hash  | String        | SHA-256 of previous epoch state                  |
| timestamp          | u64           | Unix timestamp of state snapshot                 |
| node_id            | String        | Originating node identifier                      |

### DivergenceDetector

Compares two StateVectors from different replicas:

| Epochs Match | State Hashes Match | Parent Hash Valid | Result             |
|-------------|-------------------|-------------------|--------------------|
| Yes         | Yes               | Yes               | CONVERGED          |
| Yes         | No                | -                 | FORKED             |
| Differ > 1  | -                 | -                 | GAP_DETECTED       |
| -           | -                 | No                | ROLLBACK_DETECTED  |

### RollbackProof

Serializable proof for audit logging:

| Field                | Type        | Description                           |
|---------------------|-------------|---------------------------------------|
| local_state         | StateVector | Local state vector                    |
| remote_state        | StateVector | Remote/divergent state vector         |
| expected_parent_hash| String      | Expected parent hash                  |
| actual_parent_hash  | String      | Actual (incorrect) parent hash        |
| detection_timestamp | u64         | When divergence was detected          |
| trace_id            | String      | Correlation trace identifier          |

### MarkerProofVerifier

Validates that a state vector's marker_id appears in the append-only marker
stream at the claimed epoch.

### ReconciliationSuggestion

For GAP_DETECTED: returns the range of missing epochs.
For FORKED: returns both state hashes for operator review.

## Invariants

- **INV-RFD-DETECT-FORK:** Any fork in state history must be detected within one
  propagation cycle.
- **INV-RFD-DETECT-ROLLBACK:** Unauthorized rollbacks are detected by
  parent-hash chain validation.
- **INV-RFD-HALT-ON-DIVERGENCE:** On fork or rollback detection, emit CRITICAL
  log and block further mutations.
- **INV-RFD-PROOF-SERIALIZABLE:** RollbackProof must be serializable for audit
  and external verification.

## Event Codes

| Code                    | Severity | Description                               |
|------------------------|----------|-------------------------------------------|
| RFD_DIVERGENCE_DETECTED | CRITICAL | Fork or rollback detected                 |
| RFD_CONVERGENCE_VERIFIED| INFO     | Two replicas confirmed converged          |
| RFD_MARKER_VERIFIED     | INFO     | Marker proof validated successfully        |
| RFD_RECONCILIATION_SUGGESTED | WARN | Reconciliation suggestion generated   |

## Error Codes

| Code                     | Description                                      |
|-------------------------|--------------------------------------------------|
| RFD_FORK_DETECTED       | State hashes diverge at same epoch                |
| RFD_ROLLBACK_DETECTED   | Parent hash chain broken                          |
| RFD_GAP_DETECTED        | Epoch gap exceeds 1                               |
| RFD_MARKER_NOT_FOUND    | Marker not found in stream at claimed epoch        |

## Acceptance Criteria

1. StateVector struct with epoch, marker_id, state_hash, parent_state_hash,
   timestamp, and node_id fields.
2. DivergenceDetector correctly classifies CONVERGED, FORKED, GAP_DETECTED,
   and ROLLBACK_DETECTED cases.
3. MarkerProofVerifier validates marker_id presence in stream.
4. RollbackProof is serializable (serde round-trip verified).
5. CRITICAL-severity structured log emitted on fork/rollback detection.
6. ReconciliationSuggestion returns missing epoch ranges for gaps and both
   hashes for forks.
7. Unit tests cover all four detection cases plus marker proof valid/invalid,
   RollbackProof serialization, and 100-epoch simulation with fork injection.
8. Integration with 100-epoch sequence, fork at epoch 50, detection at epoch 51.

## Verification

- Script: `scripts/check_fork_detection.py --json`
- Evidence: `artifacts/section_10_10/bd-2ms/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-2ms/verification_summary.md`
