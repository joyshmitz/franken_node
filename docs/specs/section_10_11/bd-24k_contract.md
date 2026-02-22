# bd-24k: Bounded Masking for Tiny Atomic Product Operations

## Purpose

Define a capability-context-first bounded masking primitive for tiny synchronous
critical sections. The primitive prevents cancellation from interrupting
atomic work mid-flight while preserving cancellation semantics by deferring and
delivering signals immediately after mask exit.

## Dependencies

- **Upstream:** bd-2g6r (Cx-first policy patterns), bd-7om (cancel-drain-finalize discipline)
- **Downstream:** bd-93k (checkpoint writes use bounded masking)

## Types

### `CapabilityContext`

Required invocation token for bounded masking. Includes:
- `cx_id`
- `principal`
- normalized `scopes`

### `CancellationState`

Cancellation carrier with deferred-delivery semantics:
- cancellation requested before entry -> mask denied
- cancellation requested during mask -> deferred
- deferred cancellation is delivered immediately at unmask

### `MaskPolicy`

Policy inputs:
- `max_duration_ns` timeout budget (default 1ms)
- `enforce_timeout` (fail on timeout)
- `test_mode` (enable budget-warning emission)
- `trace_id`

### `MaskError`

Stable errors:
- `MASK_MISSING_CAPABILITY_CONTEXT`
- `MASK_CANCELLED_BEFORE_ENTRY`
- `MASK_TIMEOUT_EXCEEDED`

### `BoundedMask<T>`

Result wrapper carrying:
- operation value
- invocation report (`bounded_mask.invocation`)
- structured mask events

## Event Codes

| Code | Event |
|------|-------|
| `FN-BM-001` | `MASK_ENTER` |
| `FN-BM-002` | `MASK_EXIT` |
| `FN-BM-003` | `MASK_BUDGET_EXCEEDED` |
| `FN-BM-004` | `MASK_NESTING_VIOLATION` |
| `FN-BM-005` | `MASK_TIMEOUT_EXCEEDED` |
| `FN-BM-006` | `MASK_CANCEL_DEFERRED` |

## Invariants

| ID | Description |
|----|-------------|
| `INV-BM-CX-FIRST` | bounded masking requires explicit capability context |
| `INV-BM-CANCEL-DEFERRED` | cancellation during mask is deferred, never dropped |
| `INV-BM-NON-NESTABLE` | nested masks panic with `MASK_NESTING_VIOLATION` |
| `INV-BM-TIME-BOUNDED` | timeout policy produces deterministic timeout errors |
| `INV-BM-AUDIT` | each invocation emits structured mask events and invocation report |

## Operations

### `bounded_mask(cx, cancellation, operation_name, op) -> Result<T, MaskError>`

Convenience API using default policy.

### `bounded_mask_with_report(cx, cancellation, operation_name, policy, op) -> Result<BoundedMask<T>, MaskError>`

Main API returning value + telemetry report + event stream.

### `bounded_mask_with_policy(optional_cx, cancellation, operation_name, policy, op)`

Internal entrypoint used for runtime context validation paths.

## Policy Budgets

- Compile-time warning threshold: `MAX_MASK_DURATION_NS = 1_000` (1 microsecond)
- Default timeout: 1 millisecond
- Timeout behavior controlled by `MaskPolicy.enforce_timeout`
- Test-mode over-budget warning controlled by `MaskPolicy.test_mode`

## Artifacts

- Implementation: `crates/franken-node/src/runtime/bounded_mask.rs`
- Module wiring: `crates/franken-node/src/runtime/mod.rs`
- Verification script: `scripts/check_bounded_masking.py`
- Script unit tests: `tests/test_check_bounded_masking.py`
- Evidence: `artifacts/section_10_11/bd-24k/verification_evidence.json`
- Summary: `artifacts/section_10_11/bd-24k/verification_summary.md`
