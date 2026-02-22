# Adaptive Multi-Rail Isolation Mesh with Hot-Elevation Policy

**Bead**: bd-gad3
**Section**: 10.17
**Status**: Implemented

## Overview

The isolation mesh provides a multi-rail workload isolation system where
each rail enforces progressively stricter security policies. Workloads are
assigned to rails based on their trust profile and can be promoted
("hot-elevated") to stricter rails at runtime without restarting and without
losing policy continuity.

## Rail Hierarchy

| Rail           | Level | Description                           | Default Latency Budget |
|----------------|-------|---------------------------------------|------------------------|
| Standard       | 0     | Baseline isolation for untrusted code | 10 ms                  |
| Elevated       | 1     | Network egress denied                 | 5 ms                   |
| HighAssurance  | 2     | Filesystem write denied               | 2 ms                   |
| Critical       | 3     | IPC denied, maximum restriction       | 0.5 ms                 |

## Trust Profiles

Each workload carries a `TrustProfile` that maps to its minimum initial rail:

- `Untrusted` -> Standard
- `Verified` -> Elevated
- `HighAssurance` -> HighAssurance
- `PlatformCritical` -> Critical

## Hot-Elevation Policy

Workloads may only move to **strictly more-restrictive** rails at runtime.
Downgrades are never permitted. Before any elevation, the mesh verifies:

1. **Policy continuity** (INV-ISOLATION-POLICY-CONTINUITY): every policy
   rule active on the current rail must also exist on the target rail.
2. **Mesh connectivity**: the source and target rails must both be available.
3. **Fail-safe** (INV-ISOLATION-FAIL-SAFE): if any check fails, the
   workload remains on its current rail with no state change.

## Latency Budget Enforcement

Latency-sensitive trusted workloads remain on high-performance rails only
while their cumulative latency budget is not exceeded
(INV-ISOLATION-BUDGET-BOUND). Budget consumption is tracked per-workload
and checked on each operation.

## Event Codes

| Code                          | Description                               |
|-------------------------------|-------------------------------------------|
| ISOLATION_RAIL_ASSIGNED       | Workload placed on initial rail            |
| ISOLATION_ELEVATION_START     | Hot-elevation transition initiated         |
| ISOLATION_ELEVATION_COMPLETE  | Hot-elevation transition completed         |
| ISOLATION_POLICY_PRESERVED    | Policy continuity verified after elevation |
| ISOLATION_BUDGET_CHECK        | Latency budget evaluated for workload      |

## Error Codes

| Code                              | Description                                 |
|-----------------------------------|---------------------------------------------|
| ERR_ISOLATION_RAIL_UNAVAILABLE    | Requested rail is not available              |
| ERR_ISOLATION_ELEVATION_DENIED    | Elevation blocked (e.g. downgrade attempt)   |
| ERR_ISOLATION_POLICY_BREAK        | Policy continuity violation detected         |
| ERR_ISOLATION_BUDGET_EXCEEDED     | Latency budget exceeded for workload         |
| ERR_ISOLATION_MESH_PARTITION      | Mesh connectivity lost between rails         |
| ERR_ISOLATION_WORKLOAD_REJECTED   | Workload cannot be admitted to any rail      |

## Invariants

| Tag                             | Rule                                                       |
|---------------------------------|------------------------------------------------------------|
| INV-ISOLATION-POLICY-CONTINUITY | No policy rule active before elevation may be weakened      |
| INV-ISOLATION-HOT-ELEVATION     | Only promotion to strictly more-restrictive rails allowed   |
| INV-ISOLATION-BUDGET-BOUND      | Latency-sensitive workloads stay within configured budget   |
| INV-ISOLATION-FAIL-SAFE         | On error, workload remains on current rail unchanged        |

## Implementation

- **Router**: `crates/franken-node/src/security/isolation_rail_router.rs`
- **Integration test**: `tests/integration/isolation_hot_elevation.rs`
- **Check script**: `scripts/check_isolation_mesh.py`
