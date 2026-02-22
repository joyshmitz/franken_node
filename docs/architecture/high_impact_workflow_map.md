---
schema_version: "wfm-v1.0"
bead_id: "bd-2177"
section: "10.15"
canonical_primitive_source: "docs/architecture/tri_kernel_ownership_contract.md#canonical_asupersync_primitives"
canonical_primitives:
  - cx_propagation
  - region_ownership_scope
  - cancellation_protocol
  - obligation_tracking
  - remote_computation_registry
  - epoch_validity_window
  - evidence_ledger_emission
workflows:
  - workflow_id: connector_lifecycle
    workflow_name: Connector Lifecycle
    module_paths:
      - crates/franken-node/src/connector/lifecycle.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - cancellation_protocol
      - obligation_tracking
      - evidence_ledger_emission
    mapped: true
  - workflow_id: rollout_state_machine
    workflow_name: Rollout State Machine
    module_paths:
      - crates/franken-node/src/connector/rollout_state.rs
      - crates/franken-node/src/connector/state_model.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
  - workflow_id: health_gate_evaluation
    workflow_name: Health Gate Evaluation
    module_paths:
      - crates/franken-node/src/connector/health_gate.rs
    required_primitives:
      - cx_propagation
      - evidence_ledger_emission
    mapped: true
  - workflow_id: publish_flow
    workflow_name: Publish Flow
    module_paths:
      - crates/franken-node/src/supply_chain/artifact_signing.rs
      - crates/franken-node/src/supply_chain/manifest.rs
      - crates/franken-node/src/supply_chain/provenance.rs
    required_primitives:
      - cx_propagation
      - obligation_tracking
      - remote_computation_registry
      - evidence_ledger_emission
    mapped: true
  - workflow_id: revocation_flow
    workflow_name: Revocation Flow
    module_paths:
      - crates/franken-node/src/security/revocation_freshness.rs
      - crates/franken-node/src/security/revocation_freshness_gate.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - cancellation_protocol
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
  - workflow_id: quarantine_promotion
    workflow_name: Quarantine Promotion
    module_paths:
      - crates/franken-node/src/api/fleet_quarantine.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - obligation_tracking
      - evidence_ledger_emission
    mapped: true
  - workflow_id: migration_orchestration
    workflow_name: Migration Orchestration
    module_paths:
      - crates/franken-node/src/migration/mod.rs
      - crates/franken-node/src/migration/bpet_migration_gate.rs
      - crates/franken-node/src/migration/dgis_migration_gate.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - cancellation_protocol
      - obligation_tracking
      - remote_computation_registry
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
  - workflow_id: fencing_token_acquisition_release
    workflow_name: Fencing Token Acquisition/Release
    module_paths:
      - crates/franken-node/src/connector/fencing.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
  - workflow_id: epoch_transition
    workflow_name: Epoch Transition
    module_paths:
      - crates/franken-node/src/control_plane/control_epoch.rs
      - crates/franken-node/src/control_plane/epoch_transition_barrier.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - cancellation_protocol
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
  - workflow_id: trust_rotation
    workflow_name: Trust Rotation
    module_paths:
      - crates/franken-node/src/security/epoch_scoped_keys.rs
      - crates/franken-node/src/security/trust_zone.rs
    required_primitives:
      - cx_propagation
      - region_ownership_scope
      - obligation_tracking
      - epoch_validity_window
      - evidence_ledger_emission
    mapped: true
coverage:
  total_workflows: 10
  fully_mapped: 10
  partially_mapped: 0
  unmapped: 0
---

# High-Impact Workflow to Asupersync Primitive Map

## Overview

This document maps every high-impact control-plane workflow in franken_node to the
specific asupersync primitives required by the tri-kernel ownership contract
(`docs/architecture/tri_kernel_ownership_contract.md`, bd-1id0).

Product-plane code in `franken_node` must consume correctness behavior exclusively
through the stable facade APIs exposed by `asupersync`. Each workflow listed below
declares the exact subset of canonical primitives it depends on, establishing the
minimum correctness surface that must be available for the workflow to operate
safely.

The machine-readable source of truth is:

- `artifacts/10.15/workflow_primitive_matrix.json`

## Primitive Taxonomy

The seven canonical asupersync primitives are declared in the tri-kernel ownership
contract frontmatter under `canonical_asupersync_primitives`.

| ID  | Primitive                    | Shorthand    | Description                                                        |
|-----|------------------------------|--------------|--------------------------------------------------------------------|
| P1  | `cx_propagation`             | Cx           | Structured context threading through all operations (`TraceContext`, `trace_id`, `span_id`, `parent_span_id`). Every high-impact flow must carry a valid Cx; missing context is a conformance failure (bd-1gnb). |
| P2  | `region_ownership_scope`     | Region       | Scoped ownership of execution trees. Limits blast-radius of mutations to a declared zone/tenant boundary (e.g., `QuarantineScope.zone_id`). |
| P3  | `cancellation_protocol`      | Cancellation | Three-phase cancellation lifecycle: `request -> drain -> finalize`. Used by epoch barriers, connector shutdown, and migration abort paths. |
| P4  | `obligation_tracking`        | Obligation   | Reserve/commit obligation lifecycle. Tracks in-flight work items that must reach a terminal state before the owning scope can close. |
| P5  | `remote_computation_registry`| Remote       | Registry of remote effect computations. Records off-node side-effects so they can be replayed, audited, or rolled back. |
| P6  | `epoch_validity_window`      | Epoch        | Monotonic epoch transition management with fail-closed validity windows (`ControlEpoch`, `ValidityWindowPolicy`, bd-3hdv / bd-2xv8). |
| P7  | `evidence_ledger_emission`   | Evidence     | Structured evidence ledger entries. Every state-changing decision must emit a signed, traceable event with a stable event code. |

## Workflow Inventory

### 1. Connector Lifecycle

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `connector_lifecycle` |
| **Source**      | `crates/franken-node/src/connector/lifecycle.rs` |
| **Bead**        | bd-1gnb (trace context) |
| **Description** | Eight-state FSM governing connector startup through shutdown (`Discovered -> Verified -> Installed -> Configured -> Active -> Paused -> Stopped -> Failed`). Every transition validates preconditions via `ConnectorState::can_transition_to()` and emits a state-change event. Illegal transitions are rejected with stable error codes. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Every lifecycle transition carries a `TraceContext` for distributed correlation. |
| Region       | Connector state is scoped to a zone/tenant boundary; transitions are region-local. |
| Cancellation | Shutdown path (`Active -> Stopped`) invokes the drain phase to quiesce in-flight work before the state flip. |
| Obligation   | In-flight requests are tracked as obligations; the `Stopped` transition blocks until all obligations resolve. |
| Evidence     | Each state transition emits a signed lifecycle event with stable event codes. |

---

### 2. Rollout State Machine

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `rollout_state_machine` |
| **Source**      | `crates/franken-node/src/connector/rollout_state.rs` |
| **Bead**        | bd-rollout |
| **Description** | Staged rollout phases (`Shadow -> Canary -> Ramp -> Default`) with versioned writes, conflict detection, and epoch-scoped validity. Persists `RolloutState` to durable JSON with a `rollout_epoch` field validated against `ValidityWindowPolicy`. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Rollout transitions propagate trace context end-to-end for observability. |
| Region       | Rollout scope is bound to a connector/zone pair; cross-region rollout is prohibited. |
| Epoch        | `rollout_epoch` is checked against the `ValidityWindowPolicy`; stale or future-epoch rollout states are fail-closed rejected (EPV-002, EPV-003). |
| Evidence     | Phase transitions emit structured `epoch_event_codes` (EPV-001 through EPV-004) and rollout-state change events. |

---

### 3. Health Gate Evaluation

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `health_gate_evaluation` |
| **Source**      | `crates/franken-node/src/connector/health_gate.rs` |
| **Bead**        | bd-health |
| **Description** | Evaluates a set of precondition checks before allowing a connector to transition to `Active`. The gate passes if and only if all required checks pass (`HealthGateResult::evaluate()`). Results feed into the rollout state machine. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Health check evaluation is traced; each check carries the parent trace context. |
| Evidence     | Gate pass/fail decisions are emitted as structured events with the list of failing required checks for audit. |

---

### 4. Publish Flow

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `publish_flow` |
| **Source**      | `crates/franken-node/src/supply_chain/artifact_signing.rs`, `crates/franken-node/src/supply_chain/manifest.rs`, `crates/franken-node/src/supply_chain/provenance.rs` |
| **Bead**        | bd-publish |
| **Description** | Publishing artifacts with integrity checks: signing, manifest assembly, provenance recording, and transparency log submission. Remote side-effects include registry writes and transparency verifier calls. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | End-to-end trace context across signing, registry upload, and transparency submission steps. |
| Obligation   | Publish is a multi-step obligation: sign -> upload -> record provenance -> submit transparency. Partial completion is tracked until all steps finalize. |
| Remote       | Registry writes and transparency verifier calls are registered as remote computations for replay and audit. |
| Evidence     | Every publish step emits evidence: signing event, upload receipt, provenance record, transparency submission confirmation. |

---

### 5. Revocation Flow

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `revocation_flow` |
| **Source**      | `crates/franken-node/src/security/revocation_freshness.rs`, `crates/franken-node/src/security/revocation_freshness_gate.rs` |
| **Bead**        | bd-revoc |
| **Description** | Revoking compromised keys or artifacts. Requires epoch-fenced freshness checks, zone-scoped blast-radius control, and a drain phase to ensure in-flight operations using revoked material complete or abort before finalization. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Revocation operations carry trace context for correlation across affected nodes. |
| Region       | Revocation scope is zone-bounded (`RevocationScope.zone_id`); blast-radius is enforced at the region level. |
| Cancellation | In-flight operations using revoked material enter the cancellation drain phase before finalization. |
| Epoch        | Revocation freshness is epoch-gated; stale revocation lists from expired epochs are fail-closed rejected. |
| Evidence     | Revocation decisions, freshness checks, and cancellation completions all emit structured evidence events. |

---

### 6. Quarantine Promotion

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `quarantine_promotion` |
| **Source**      | `crates/franken-node/src/api/fleet_quarantine.rs` |
| **Bead**        | bd-tg2 |
| **Description** | Promoting nodes from quarantine involves quarantine, revocation, release, status, and reconcile operations with convergence tracking. Starts in safe-start read-only mode (INV-FLEET-SAFE-START) and requires explicit activation before mutation operations are permitted. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | All fleet operations carry `TraceContext` (`trace_id`) for distributed correlation. |
| Region       | Every operation is scoped to a zone/tenant (`QuarantineScope.zone_id`, INV-FLEET-ZONE-SCOPE). Empty zone IDs are rejected with `FLEET_SCOPE_INVALID`. |
| Obligation   | Convergence tracking (`ConvergenceState`) monitors in-flight propagation obligations across affected nodes until all converge or timeout (INV-FLEET-CONVERGENCE). |
| Evidence     | All operations produce signed `DecisionReceipt` entries (INV-FLEET-RECEIPT) and emit structured `FleetControlEvent` codes (FLEET-001 through FLEET-005). |

---

### 7. Migration Orchestration

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `migration_orchestration` |
| **Source**      | `crates/franken-node/src/migration/mod.rs`, `crates/franken-node/src/migration/bpet_migration_gate.rs`, `crates/franken-node/src/migration/dgis_migration_gate.rs` |
| **Bead**        | bd-migration |
| **Description** | Cross-version migration coordination including BPET and DGIS migration stability gates. Orchestrates data movement, schema evolution, and rollback across node versions with multi-phase commit semantics. This is the only workflow that requires all seven canonical primitives. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Migration spans carry trace context for end-to-end observability across participating nodes. |
| Region       | Migration scope is region-partitioned; cross-region migration requires explicit coordination. |
| Cancellation | Migration abort path uses the cancellation protocol to drain in-flight migration work before rolling back. |
| Obligation   | Each migration step is an obligation: schema preparation, data transfer, validation, cutover. Partial completion is tracked until terminal state. |
| Remote       | Off-node data movement and schema changes are registered as remote computations for deterministic replay. |
| Epoch        | Migration validity is epoch-bounded; migration steps are rejected if the epoch advances past the migration's validity window. |
| Evidence     | Every migration phase emits structured evidence: preparation, transfer, validation, cutover, or rollback events. |

---

### 8. Fencing Token Acquisition/Release

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `fencing_token_acquisition_release` |
| **Source**      | `crates/franken-node/src/connector/fencing.rs` |
| **Bead**        | bd-fencing |
| **Description** | Distributed lock coordination via lease-based fencing tokens. Each writer must hold a valid, non-stale `Lease` with a matching `object_id` before writes are permitted. Fencing tokens carry a `ControlEpoch` and `lease_seq` for staleness detection. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Lease acquisition and fenced write operations carry trace context for correlation. |
| Region       | Leases are scoped to a specific `object_id` within a region; cross-region lease acquisition is prohibited. |
| Epoch        | Lease validity is epoch-checked via `check_artifact_epoch()`; leases from expired or future epochs are rejected with `LEASE_EPOCH_REJECTED` (EPV-002, EPV-003). |
| Evidence     | Lease acquisition, release, and fencing rejections (`WRITE_UNFENCED`, `WRITE_STALE_FENCE`, `LEASE_EXPIRED`, `LEASE_OBJECT_MISMATCH`, `LEASE_EPOCH_REJECTED`) are all emitted as structured evidence events. |

---

### 9. Epoch Transition

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `epoch_transition` |
| **Source**      | `crates/franken-node/src/control_plane/control_epoch.rs`, `crates/franken-node/src/control_plane/epoch_transition_barrier.rs` |
| **Bead**        | bd-3hdv (epoch store), bd-2wsm (barrier protocol) |
| **Description** | Epoch boundary management via the `EpochStore` and the epoch transition barrier protocol. The barrier coordinates propose/drain/commit across all registered participants to ensure no split-brain epoch state (INV-BARRIER-ALL-ACK, INV-BARRIER-NO-PARTIAL). Concurrent barrier attempts are serialized (INV-BARRIER-SERIALIZED). |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Barrier protocol phases (propose, drain-ack, commit/abort) carry trace context for distributed correlation (`trace_id` on `EpochTransition`). |
| Region       | Epoch transitions affect a region of participants; barrier registration scopes participants to the region. |
| Cancellation | The drain phase of the barrier protocol is a cancellation drain: each participant quiesces in-flight work before acknowledging. The abort path uses cancellation finalize semantics (INV-BARRIER-ABORT-SAFE). Timeout triggers abort (INV-BARRIER-TIMEOUT). |
| Epoch        | The `EpochStore` enforces INV-EPOCH-MONOTONIC, INV-EPOCH-NO-GAP, and INV-EPOCH-DURABLE. Barrier commit atomically advances the epoch via `epoch_advance()` with a signed `EpochTransition` event carrying a MAC. |
| Evidence     | Every barrier phase emits structured events: `BARRIER_PROPOSED`, `BARRIER_DRAIN_ACK`, `BARRIER_COMMITTED`, `BARRIER_ABORTED`, `BARRIER_TIMEOUT`, `BARRIER_DRAIN_FAILED`, `BARRIER_CONCURRENT_REJECTED`. Complete audit transcripts are exported (INV-BARRIER-TRANSCRIPT). |

---

### 10. Trust Rotation

| Attribute       | Value |
|-----------------|-------|
| **Workflow ID** | `trust_rotation` |
| **Source**      | `crates/franken-node/src/security/epoch_scoped_keys.rs`, `crates/franken-node/src/security/trust_zone.rs` |
| **Bead**        | bd-trust-rotation |
| **Description** | Rotating trust keys and certificates. Key material is epoch-scoped; rotation involves deriving new keys for the next epoch, distributing them within the trust zone, and retiring old keys after the validity window expires. |

**Required Primitives:**

| Primitive    | Usage |
|--------------|-------|
| Cx           | Key rotation operations carry trace context for end-to-end auditability. |
| Region       | Key distribution is scoped to a trust zone region; cross-zone key sharing is prohibited. |
| Obligation   | Key rotation is a multi-step obligation: derive -> distribute -> verify -> activate -> retire. Each step must complete before the next begins. |
| Epoch        | Keys are scoped to an epoch validity window; the new key is derived for epoch N+1 and activated only after the epoch transition barrier commits. Old keys are retired when they fall outside the `ValidityWindowPolicy` lookback. |
| Evidence     | Key derivation, distribution, activation, and retirement events are emitted as structured evidence with the epoch scope and trust zone identifier. |

## Coverage Summary

| Metric             | Count |
|--------------------|-------|
| Total workflows    | 10    |
| Fully mapped       | 10    |
| Partially mapped   | 0     |
| Unmapped           | 0     |

All ten high-impact control-plane workflows have been mapped to their required
asupersync primitive subset. No workflow operates without at least Cx (context
propagation) and Evidence (evidence ledger emission), confirming these two
primitives as universal dependencies.

## Primitive Usage Distribution

The table below shows how many of the 10 workflows require each primitive.

| Primitive    | ID | Workflows Using | Usage Rate |
|--------------|----|-----------------|------------|
| Cx           | P1 | 10              | 100%       |
| Evidence     | P7 | 10              | 100%       |
| Region       | P2 | 9               | 90%        |
| Epoch        | P6 | 7               | 70%        |
| Obligation   | P4 | 5               | 50%        |
| Cancellation | P3 | 4               | 40%        |
| Remote       | P5 | 2               | 20%        |

### Observations

1. **Cx and Evidence are universal.** Every workflow requires context propagation
   and evidence emission. These two primitives form the non-negotiable baseline
   for any control-plane operation.

2. **Region is near-universal.** Only the Health Gate Evaluation workflow does
   not require explicit region scoping, because it operates within the context
   of an already-scoped connector lifecycle transition.

3. **Epoch is heavily used.** Seven of ten workflows are epoch-sensitive,
   reflecting the system's design around monotonic epoch fencing for all trust
   and state decisions.

4. **Obligation and Cancellation appear in multi-phase workflows.** These
   primitives cluster in workflows with complex commit semantics (migration,
   lifecycle shutdown, revocation drain, quarantine convergence, trust rotation).

5. **Remote is the most specialized.** Only Publish Flow and Migration
   Orchestration require the remote computation registry, as they are the only
   workflows that produce off-node side-effects requiring replay guarantees.

## Cross-Reference Matrix

The following matrix provides a compact view of primitive coverage per workflow.

| Workflow                       | Cx | Region | Cancel | Oblig | Remote | Epoch | Evidence |
|--------------------------------|----|--------|--------|-------|--------|-------|----------|
| 1. Connector Lifecycle         | x  | x      | x      | x     |        |       | x        |
| 2. Rollout State Machine       | x  | x      |        |       |        | x     | x        |
| 3. Health Gate Evaluation      | x  |        |        |       |        |       | x        |
| 4. Publish Flow                | x  |        |        | x     | x      |       | x        |
| 5. Revocation Flow             | x  | x      | x      |       |        | x     | x        |
| 6. Quarantine Promotion        | x  | x      |        | x     |        |       | x        |
| 7. Migration Orchestration     | x  | x      | x      | x     | x      | x     | x        |
| 8. Fencing Token Acq/Release   | x  | x      |        |       |        | x     | x        |
| 9. Epoch Transition            | x  | x      | x      |       |        | x     | x        |
| 10. Trust Rotation             | x  | x      |        | x     |        | x     | x        |
| **Total**                      | 10 | 9      | 4      | 5     | 2      | 7     | 10       |

## Structured Event Codes

- `WFM-001`: workflow mapped
- `WFM-002`: workflow unmapped with approved exception
- `WFM-003`: workflow unmapped without approved exception (gate failure)
- `WFM-004`: primitive reference validation

## Governance Rules

- Critical workflows marked `mapped: false` must include an approved exception
  in the matrix (`approved_by`, `ticket`, `expires_at`, `unmapped_reason`).
- Missing exception metadata is a fail-closed gate condition.
- Primitive references outside the canonical list are gate failures.
- Any new high-impact workflow added to the codebase must be registered in this
  map with its full primitive dependency set before the CI gate will pass.

## CI Enforcement

This workflow map is validated by the Section 10.15 ownership boundary gate:

- **Gate script:** `scripts/check_section_10_15_gate.py` (verifies all declared
  workflows reference valid primitives from the canonical list)
- **Primary artifact:** `artifacts/10.15/ownership_boundary_report.json`
- **Conformance test:** `tests/conformance/ownership_boundary_checks.rs`

## Exception Inventory

No active exceptions.
