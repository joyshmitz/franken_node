# Asupersync Control Surface Migration Plan

**Bead:** bd-2h2s | **Section:** 10.15 | **Version:** mig-v1.0
**Date:** 2026-02-21 | **Owner:** franken-node control-plane team

## Overview

This document defines the migration plan for existing non-asupersync control surfaces
in the `connector/` and `conformance/` modules. The asupersync pattern requires that all
control surfaces participating in epoch-scoped state transitions use the canonical
asupersync protocol: deterministic serialization, epoch-bounded validity, idempotent
replay, and fail-closed rejection of stale artifacts.

Modules that predate the asupersync contract must be migrated or granted a time-boxed
exception with owner and expiry.

## Inventory of Non-Asupersync Control Surfaces

### connector/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 1 | connector/lifecycle.rs | `transition()` | INV-MIG-EPOCH-SCOPED | Epoch-bounded transition validation | bd-1cs7 | completed | Transition calls check_artifact_epoch before state change |
| 2 | connector/rollout_state.rs | `persist_state()` | INV-MIG-DETERMINISTIC-SER | Canonical deterministic serialization | bd-1cwp | completed | Uses canonical_serializer for all persisted state |
| 3 | connector/health_gate.rs | `evaluate()` | INV-MIG-EPOCH-SCOPED | Epoch-bounded health evaluation | bd-145n | in_progress | Health gate results carry epoch scope tags |
| 4 | connector/fencing.rs | `validate_fence()` | INV-MIG-IDEMPOTENT | Idempotent fence token validation | bd-3h63 | in_progress | Fence validation is idempotent across replays |
| 5 | connector/repair_controller.rs | `run_cycle()` | INV-MIG-FAIL-CLOSED | Fail-closed on stale repair directives | bd-3014 | not_started | Repair cycles reject stale-epoch directives |
| 6 | connector/retention_policy.rs | `enforce()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped retention enforcement | bd-25oa | not_started | Retention decisions are epoch-bounded |
| 7 | connector/snapshot_policy.rs | `should_snapshot()` | INV-MIG-DETERMINISTIC-SER | Deterministic snapshot trigger evaluation | bd-3tpg | in_progress | Snapshot decisions use canonical serialization |
| 8 | connector/activation_pipeline.rs | `activate()` | INV-MIG-FAIL-CLOSED | Fail-closed activation with epoch check | bd-3u6o | not_started | Activation rejects artifacts from wrong epoch |
| 9 | connector/quarantine_promotion.rs | `promote()` | INV-MIG-IDEMPOTENT | Idempotent promotion with replay safety | bd-cuut | completed | Promotion is idempotent; replays produce same result |

### conformance/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 10 | conformance/protocol_harness.rs | `run_harness()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped conformance evaluation | bd-1hbw | in_progress | Harness results carry epoch metadata |
| 11 | conformance/connector_method_validator.rs | `validate_contract()` | INV-MIG-DETERMINISTIC-SER | Deterministic validation report output | bd-3014 | not_started | Validation reports use canonical serialization |

### supply_chain/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 12 | supply_chain/artifact_signing.rs | `sign_artifact()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped signing with validity window | bd-1cwp | completed | Signatures include epoch scope in signed payload |
| 13 | supply_chain/manifest.rs | `validate()` | INV-MIG-FAIL-CLOSED | Fail-closed manifest validation | bd-3h63 | in_progress | Manifest validation rejects stale-epoch manifests |
| 14 | supply_chain/provenance_gate.rs | `check_provenance()` | INV-MIG-IDEMPOTENT | Idempotent provenance checks | bd-25oa | not_started | Provenance checks produce identical results on replay |

## Exception Surfaces

The following surfaces are granted time-boxed exceptions from the asupersync migration.
Each exception has a documented justification, designated owner, and hard expiry date.

| # | Module | Function | Justification | Owner | Expiry |
|---|--------|----------|---------------|-------|--------|
| E1 | connector/repair_controller.rs | `emergency_repair()` | Emergency repair path must bypass epoch checks for disaster recovery; gated by operator escalation token | @infra-oncall | 2026-06-30 |
| E2 | conformance/connector_method_validator.rs | `validate_legacy_v0()` | Legacy v0 connectors do not support epoch metadata; scheduled for deprecation in v2.0 | @connector-team | 2026-09-30 |

## Burn-Down Schedule

### Milestone 1: Foundation (2026-02-28)
- Complete migration of all `completed` surfaces (lifecycle, rollout_state, quarantine_promotion, artifact_signing)
- Verify epoch-scoped tags in completed modules

### Milestone 2: In-Progress Closure (2026-03-31)
- Close all `in_progress` surfaces (health_gate, fencing, snapshot_policy, protocol_harness, manifest)
- Integration tests for epoch-bounded behavior in each module

### Milestone 3: Remaining Surfaces (2026-05-31)
- Migrate all `not_started` surfaces (repair_controller, retention_policy, activation_pipeline, connector_method_validator, provenance_gate)
- Exceptions reviewed and renewed or closed

### Milestone 4: Full Closure (2026-06-30)
- All non-excepted surfaces migrated
- Exception E1 reviewed for renewal or closure
- Burn-down CSV shows 100% completion (excluding active exceptions)

## Tracking

The burn-down CSV at `artifacts/10.15/control_surface_burndown.csv` is the machine-readable
source of truth. The gate script `scripts/check_control_surface_burndown.py` validates
consistency between this CSV and the migration plan.

## Invariants

| ID | Statement |
|----|-----------|
| INV-MIG-INVENTORIED | Every non-asupersync control surface is inventoried in the burn-down CSV |
| INV-MIG-STATUS-VERIFIED | Migration status in CSV matches implementation state |
| INV-MIG-EXPIRY-ENFORCED | No exception surface has an expired exception date |
| INV-MIG-EPOCH-SCOPED | Migrated surfaces use epoch-bounded validity |
| INV-MIG-DETERMINISTIC-SER | Migrated surfaces use canonical deterministic serialization |
| INV-MIG-IDEMPOTENT | Migrated surfaces support idempotent replay |
| INV-MIG-FAIL-CLOSED | Migrated surfaces fail closed on stale artifacts |

## Event Codes

| Code | Description |
|------|-------------|
| MIG-001 | Surface migration completed successfully |
| MIG-002 | Surface migration in progress |
| MIG-003 | Exception granted for surface |
| MIG-004 | Exception expired; surface must be migrated |
| MIG-005 | Burn-down milestone reached |
