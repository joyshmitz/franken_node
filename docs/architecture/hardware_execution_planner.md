# Heterogeneous Hardware Planner with Policy-Evidenced Placements (bd-2o8b)

## Scope

This document defines the architecture for the heterogeneous hardware planner
in `franken_node`. The planner assigns workloads to hardware targets while
producing machine-readable `PolicyEvidence` for every placement decision.

Section: **10.17**
Bead: **bd-2o8b**

## Core Invariants

- `INV-PLANNER-REPRODUCIBLE`: identical inputs yield identical placement decisions.
- `INV-PLANNER-CONSTRAINT-SATISFIED`: workload placed only when capability and risk constraints are met.
- `INV-PLANNER-FALLBACK-PATH`: resource contention triggers a fallback path with recorded reasoning.
- `INV-PLANNER-APPROVED-DISPATCH`: dispatch executes only through approved runtime/engine interfaces.

## Design

### Hardware Profiles

Each hardware target is described by a `HardwareProfile` containing:

- `profile_id`: unique identifier
- `capabilities`: set of capabilities (e.g. `gpu`, `fpga`, `tee`, `compute`)
- `risk_level`: risk rating [0, 100]
- `total_slots` / `used_slots`: capacity tracking
- `metadata`: key-value pairs for policy evaluation

### Placement Policies

A `PlacementPolicy` defines preference rules:

- `prefer_lowest_risk`: select hardware with lowest risk among candidates
- `prefer_most_capacity`: select hardware with most available slots
- `max_risk_tolerance`: upper bound on acceptable risk
- `required_metadata_keys`: mandatory hardware metadata

### Placement Lifecycle

1. **PLANNER_PLACEMENT_START**: Workload requests placement, specifying
   required capabilities, maximum risk tolerance, and policy ID.
2. **PLANNER_CONSTRAINT_EVALUATED**: Each registered hardware profile is
   evaluated against capability, risk, and capacity constraints. Rejections
   are recorded in the evidence chain.
3. **PLANNER_PLACEMENT_DECIDED**: The best candidate is selected per policy
   preferences, or the request is rejected with detailed reasoning.
4. **PLANNER_FALLBACK_ACTIVATED**: If all primary candidates are at capacity,
   the planner attempts a fallback path with relaxed parameters.
5. **PLANNER_DISPATCH_APPROVED**: The placed workload is dispatched through
   an approved runtime/engine interface.

### Deterministic Selection

All internal data structures use `BTreeMap` and `BTreeSet` to ensure
deterministic iteration order. Given identical inputs (profiles, policies,
workload request), the planner produces identical output.

### Fallback on Resource Contention

When primary targets are at capacity:

1. The planner records contention evidence.
2. If `request_placement_with_fallback` is used, risk tolerance is relaxed
   by a configurable delta.
3. A second placement pass runs with relaxed constraints.
4. If the second pass succeeds, the decision is marked `PlacedViaFallback`.
5. If all paths are exhausted, the request fails with
   `ERR_PLANNER_NO_FALLBACK`.

### Dispatch Gating

Dispatch tokens are only issued when:

- The target hardware profile exists.
- The dispatch interface is in the planner's approved interface set.
- Default approved interfaces: `franken_engine`, `asupersync`.

## Event Codes

| Code | Description |
|------|-------------|
| `PLANNER_PLACEMENT_START` | Placement evaluation begins |
| `PLANNER_CONSTRAINT_EVALUATED` | Constraint evaluated against a candidate |
| `PLANNER_PLACEMENT_DECIDED` | Placement decision made |
| `PLANNER_FALLBACK_ACTIVATED` | Fallback path activated after contention |
| `PLANNER_DISPATCH_APPROVED` | Dispatch approved through gated interface |

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_PLANNER_CONSTRAINT_VIOLATED` | Constraint violation (capability or risk) |
| `ERR_PLANNER_RESOURCE_CONTENTION` | Resource contention prevents placement |
| `ERR_PLANNER_NO_FALLBACK` | No fallback path after contention |
| `ERR_PLANNER_DISPATCH_DENIED` | Dispatch denied (ungated interface) |
| `ERR_PLANNER_REPRODUCIBILITY_FAILED` | Reproducibility check failed |
| `ERR_PLANNER_INTERFACE_UNAPPROVED` | Unapproved dispatch interface |

## Policy Evidence

Every placement decision produces a `PolicyEvidence` record containing:

- `policy_id`: which policy was used
- `candidates_considered`: all hardware profiles evaluated
- `rejections`: map of rejected profiles to reasons
- `selected_target`: chosen hardware (if placed)
- `fallback_attempted` / `fallback_reason`: contention details
- `reasoning_chain`: step-by-step reasoning trace

## Required Artifacts

- `crates/franken-node/src/runtime/hardware_planner.rs`
- `tests/perf/hardware_planner_policy_conformance.rs`
- `scripts/check_hardware_planner.py`
- `tests/test_check_hardware_planner.py`
- `artifacts/10.17/hardware_placement_trace.json`
- `artifacts/section_10_17/bd-2o8b/verification_evidence.json`
- `artifacts/section_10_17/bd-2o8b/verification_summary.md`
