# bd-3he: Supervision Tree with Restart Budgets and Escalation Policies

## Purpose

Implement an Erlang-inspired supervision tree with `Supervisor`, `ChildSpec`,
`SupervisionStrategy` (OneForOne, OneForAll, RestForOne), sliding-window
restart budgets, bounded escalation policies, graceful shutdown in reverse
start order, and structured health reporting.

## Section

10.11

## Status

Implemented

## Dependencies

None (foundational module).

## Contract Summary

The supervision tree provides fault-tolerance primitives for managing child
processes. Each supervisor enforces:

1. **Strategy-based restart** -- When a child fails, the supervisor applies
   one of three deterministic strategies: restart only the failed child
   (OneForOne), restart all children (OneForAll), or restart the failed
   child and all children started after it (RestForOne).

2. **Sliding-window restart budget** -- The supervisor tracks restart
   timestamps within a configurable time window. When the budget is
   exhausted, the failure is escalated instead of restarted.

3. **Bounded escalation** -- Escalation chains are bounded by
   `max_escalation_depth`. Exceeding this depth triggers a full shutdown.

4. **Graceful shutdown** -- Children are stopped in reverse start order,
   respecting per-child shutdown timeouts.

5. **Health reporting** -- A snapshot of active children, restart count,
   budget remaining, and escalation depth is available at any time.

## Interface Boundary

- **Module:** `connector::supervision`
- **Crate path:** `crates/franken-node/src/connector/supervision.rs`

### Key Types

#### `SupervisionStrategy`

Enum with variants: `OneForOne`, `OneForAll`, `RestForOne`.

#### `RestartType`

Enum with variants: `Permanent`, `Transient`, `Temporary`.

#### `ChildSpec`

Struct with fields: `name`, `restart_type`, `shutdown_timeout_ms`.

#### `ChildState`

Enum with variants: `Running`, `Stopped`, `Failed`, `Restarting`.

#### `Supervisor`

Manages children with:
- `add_child(&mut self, spec: ChildSpec) -> Result<(), SupervisionError>`
- `remove_child(&mut self, name: &str) -> Result<ChildSpec, SupervisionError>`
- `handle_failure(&mut self, child_name: &str) -> Result<SupervisionAction, SupervisionError>`
- `shutdown(&mut self) -> ShutdownReport`
- `health_status(&self) -> SupervisorHealth`

#### `SupervisionAction`

Enum: `Restart`, `Escalate`, `Shutdown`, `Ignore`.

#### `ShutdownReport`

Struct: `children_stopped`, `force_terminated`, `duration_ms`.

#### `SupervisorHealth`

Struct: `active_children`, `restart_count`, `budget_remaining`, `escalation_depth`.

#### `SupervisionEvent`

Enum for structured logging of all supervision events.

#### `SupervisionError`

Enum covering all error conditions.

## Event Codes

| Code | Event |
|------|-------|
| `SUP-001` | `supervisor.child_started` |
| `SUP-002` | `supervisor.child_failed` |
| `SUP-003` | `supervisor.child_restarted` |
| `SUP-004` | `supervisor.budget_exhausted` |
| `SUP-005` | `supervisor.escalation` |
| `SUP-006` | `supervisor.shutdown_started` |
| `SUP-007` | `supervisor.shutdown_complete` |
| `SUP-008` | `supervisor.health_report` |

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_SUP_CHILD_NOT_FOUND` | Named child does not exist in supervisor |
| `ERR_SUP_BUDGET_EXHAUSTED` | Sliding-window restart budget exhausted |
| `ERR_SUP_MAX_ESCALATION` | Escalation chain reached max depth |
| `ERR_SUP_SHUTDOWN_TIMEOUT` | Child did not stop within timeout |
| `ERR_SUP_DUPLICATE_CHILD` | Child with same name already exists |

## Invariants

| ID | Description |
|----|-------------|
| `INV-SUP-BUDGET-BOUND` | Restart count never exceeds budget within any sliding window |
| `INV-SUP-ESCALATION-BOUNDED` | Escalation chains terminate at max depth |
| `INV-SUP-SHUTDOWN-ORDER` | Children stopped in reverse start order |
| `INV-SUP-TIMEOUT-ENFORCED` | Shutdown timeout is respected per child |
| `INV-SUP-STRATEGY-DETERMINISTIC` | Strategy application is deterministic |

## Acceptance Criteria

1. `Supervisor` supports all three strategies with deterministic behaviour.
2. Sliding-window restart budget is enforced; exceeding it returns `Escalate`.
3. Escalation depth is bounded; exceeding it returns `Shutdown`.
4. `shutdown()` stops children in reverse start order.
5. `health_status()` returns accurate counts.
6. All event codes SUP-001 through SUP-008 are present.
7. All error codes are used and tested.
8. All invariant constants are defined.
9. Schema version is `sup-v1.0`.
10. At least 15 unit tests in `#[cfg(test)]`.
11. Gate script passes all checks.

## Artifacts

- Implementation: `crates/franken-node/src/connector/supervision.rs`
- Spec contract: `docs/specs/section_10_11/bd-3he_contract.md`
- Gate script: `scripts/check_supervision_tree.py`
- Tests: `tests/test_check_supervision_tree.py`
- Evidence: `artifacts/section_10_11/bd-3he/verification_evidence.json`
- Summary: `artifacts/section_10_11/bd-3he/verification_summary.md`
