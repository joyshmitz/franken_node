# Control-Plane Cancellation Injection Gate

**Bead:** bd-3tpg | **Section:** 10.15 | **Upstream:** bd-876n (10.14)

## Overview

This document defines the adoption of the canonical all-point cancellation injection
framework (bd-876n, `CancellationInjectionFramework`) for all critical control-plane
workflows in franken_node. Every high-impact protocol must survive cancellation at
every await point without obligation leaks, half-commit outcomes, or quiescence violations.

## All-Point Injection Model

The cancellation injection model systematically cancels workflows at **every identified
await point** to verify that the system maintains its invariants under all possible
cancellation timings. This is not sampling-based: every (workflow, await_point) pair
is exercised. The canonical `CancellationInjectionFramework` from 10.14 is the sole
injection mechanism; custom injection logic is prohibited (INV-CIG-CANONICAL-ONLY).

For each injection point the framework:

1. Captures a pre-cancellation `ResourceSnapshot` (file handles, locks, allocations, temp files)
2. Captures a pre-cancellation `StateSnapshot` (epoch, marker head, root pointer, saga phase)
3. Injects cancellation at the await point
4. Captures post-cancellation snapshots
5. Asserts no resource leaks (INV-CANCEL-LEAK-FREE)
6. Asserts no half-commit state (INV-CANCEL-HALFCOMMIT-FREE)
7. Asserts quiescence is maintained (no dangling obligations)

## Critical Workflows

The following 6 critical control-plane workflows are subject to all-point cancellation injection:

### 1. Lifecycle (connector_lifecycle)

**Module:** `crates/franken-node/src/connector/lifecycle.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | init_start | Before connector initialization |
| 1 | health_probe | During health probe request |
| 2 | state_load | During persistent state load |
| 3 | ready_signal | Before emitting ready signal |
| 4 | shutdown_drain | During graceful shutdown drain |
| 5 | shutdown_confirm | Before shutdown confirmation |

**Invariant:** No obligation leaks after cancellation at any await point. A cancelled
lifecycle must not leave the connector in an inconsistent state where it appears ready
but has not completed initialization, or appears shut down but still holds resources.

### 2. Rollout (rollout_transition)

**Module:** `crates/franken-node/src/connector/rollout_state.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | canary_check | Before canary health check |
| 1 | promote_prepare | During promotion preparation |
| 2 | state_commit | During state commitment |
| 3 | notify_peers | Before peer notification |
| 4 | rollback_check | During rollback eligibility check |

**Invariant:** No half-commits. A cancelled rollout must either complete the full
promote-commit-notify cycle or leave the rollout in its previous state with no
partially visible promotion.

### 3. Quarantine (quarantine_promotion)

**Module:** `crates/franken-node/src/api/fleet_quarantine.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | quarantine_check | Before quarantine status check |
| 1 | trust_verify | During trust verification |
| 2 | promotion_commit | During promotion commitment |
| 3 | audit_log | Before audit log write |
| 4 | notify_fleet | Before fleet notification |

**Invariant:** No half-commits. A cancelled quarantine promotion must not leave
a node in a state where it is partially promoted but the fleet has not been notified,
or where trust verification passed but the promotion was not committed.

### 4. Migration (migration_orchestration)

**Module:** `crates/franken-node/src/connector/lifecycle.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | schema_check | Before schema compatibility check |
| 1 | data_migrate | During data migration transfer |
| 2 | validate_result | During result validation |
| 3 | finalize | Before migration finalization |
| 4 | cleanup | During cleanup of old state |
| 5 | report | Before migration report write |

**Invariant:** No obligation leaks. A cancelled migration must not leave data in
a half-migrated state. Either the old schema is intact or the new schema is fully
committed. No partial transfers.

### 5. Fencing (fencing_acquire)

**Module:** `crates/franken-node/src/connector/fencing.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | token_request | Before fencing token request |
| 1 | epoch_validate | During epoch validation |
| 2 | token_commit | During token commitment |
| 3 | fence_activate | Before fence activation |

**Invariant:** No quiescence violations. A cancelled fencing acquisition must not
leave a dangling fence token that blocks other operations. Either the fence is fully
acquired or the token is released/expired.

### 6. Health-Gate (health_gate_evaluation)

**Module:** `crates/franken-node/src/connector/health_gate.rs`

| Index | Await Point | Description |
|-------|-------------|-------------|
| 0 | probe_collect | Before probe data collection |
| 1 | score_compute | During health score computation |
| 2 | verdict_emit | Before verdict emission |
| 3 | threshold_update | During threshold update |
| 4 | alert_dispatch | Before alert dispatch |

**Invariant:** No obligation leaks. A cancelled health-gate evaluation must not
leave stale health scores or miss an alert dispatch. The previous health state
must remain valid until a complete evaluation succeeds.

## Per-Workflow Invariant Assertions

For every workflow, the following three invariant classes are asserted at every
injection point:

### No Obligation Leaks (INV-CIG-LEAK-FREE)

After cancellation at any await point, the resource delta (file handles, locks held,
memory allocations, temp files) between pre- and post-cancellation snapshots must be
zero or negative. A positive delta indicates a leaked resource.

### No Half-Commits (INV-CIG-HALFCOMMIT-FREE)

After cancellation at any await point, the state snapshot (epoch, marker head, root
pointer, saga phase) must either be unchanged from the pre-cancellation snapshot or
reflect a fully committed state. Any partial state change is a half-commit violation.

### No Quiescence Violations (INV-CIG-QUIESCENCE-SAFE)

After cancellation at any await point, no dangling obligations (pending notifications,
uncommitted tokens, incomplete saga steps) may remain. The system must return to a
quiescent state that permits retry or fresh execution.

## Event Codes

| Code | Description |
|------|-------------|
| CIJ-001 | Control workflow registered for cancellation injection |
| CIJ-002 | Cancellation injected at await point |
| CIJ-003 | Post-cancel invariant assertion passed |
| CIJ-004 | Post-cancel invariant assertion failed (obligation leak or half-commit) |
| CIJ-005 | Gate verdict emitted (PASS/FAIL with summary) |
| CIJ-006 | Rust lab model exercised and validated |

## Invariants

| ID | Rule |
|----|------|
| INV-CIG-CANONICAL-ONLY | All injection uses the canonical CancellationInjectionFramework from 10.14 |
| INV-CIG-ALL-WORKFLOWS | All 6 critical control workflows are registered |
| INV-CIG-FULL-MATRIX | Every (workflow, await_point) pair is tested |
| INV-CIG-ZERO-FAILURES | A single failure at any injection point fails the gate |
| INV-CIG-LEAK-FREE | No resource leaks after cancellation at any await point |
| INV-CIG-HALFCOMMIT-FREE | No half-commit state after cancellation at any await point |
| INV-CIG-QUIESCENCE-SAFE | No quiescence violations after cancellation |
| INV-CIG-REPORT-COMPLETE | Injection report includes per-workflow per-point results |

## Prohibition on Custom Injection Logic

Custom cancellation injection is prohibited in connector and control-plane modules.
All cancellation testing must use the canonical `CancellationInjectionFramework`
from `crates/franken-node/src/control_plane/cancellation_injection.rs`. This ensures:

- Consistent resource snapshot and state snapshot capture
- Uniform leak and half-commit detection
- Centralized audit logging with schema versioning
- Matrix completeness enforcement (MIN_MATRIX_CASES >= 20)

## Upstream Dependency

This bead adopts the framework defined by:

- **bd-876n** (Section 10.14): `CancellationInjectionFramework` implementation
- **Source:** `crates/franken-node/src/control_plane/cancellation_injection.rs`

The framework provides `WorkflowRegistration`, `AwaitPoint`, `ResourceSnapshot`,
`StateSnapshot`, `CancelInjectionMatrix`, and audit log export capabilities.
