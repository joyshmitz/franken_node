# bd-137: Policy-Visible Compatibility Gate APIs

**Section:** 10.5 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust compat_gates tests | 72 | 72 |
| Rust compatibility_gate tests | 24 | 24 |
| Python verification checks | 126 | 126 |
| Python unit tests | 36 | 36 |

## Implementation

### Modules

| Module | Purpose |
|--------|---------|
| `compat_gates.rs` | Typed band-mode matrix, ShimRegistry with Serde, CompatGateEvaluator, non-interference/monotonicity, report |
| `compatibility_gate.rs` | GateEngine with request-based checks, mode transitions, divergence receipts, audit trail |

### Key Types (compat_gates.rs)

- `CompatibilityBand`: Core, HighValue, Edge, Unsafe (ordered by priority)
- `CompatibilityMode`: Strict, Balanced, LegacyRisky (ordered by risk)
- `DivergenceAction`: Error, Warn, Log, Blocked (band-mode matrix output)
- `ShimRegistry`: HashMap-based registry with typed metadata per shim
- `GateDecision`: Allow, Deny, Audit (with event codes PCG-001/002/005)
- `CompatGateEvaluator`: Central entry point for gate checks, mode management, queries
- `PolicyPredicate`: Machine-verifiable predicate with signature and attenuation
- `ModeSelectionReceipt`: Signed receipt for mode transitions

### Key Types (compatibility_gate.rs)

- `GateEngine`: Request-based gate check engine with signing key
- `DivergenceReceipt`: Signed divergence receipts with verification
- `ModeTransitionReceipt`: Signed transition receipts with approval workflow

## Band-Mode Divergence Matrix

| Band | Strict | Balanced | LegacyRisky |
|------|--------|----------|-------------|
| Core | Error | Error | Error |
| HighValue | Error | Warn | Warn |
| Edge | Warn | Log | Log |
| Unsafe | Blocked | Blocked | Warn |

## Formal Properties

1. **Non-interference**: Gate decisions in scope B are determined solely by scope B's mode. Policy predicates from scope A cannot leak to scope B.
2. **Monotonicity**: Replacing a shim with a less restrictive band is rejected. Adding new shims cannot weaken existing security guarantees.

## Event Codes

| Code | When Emitted |
|------|--------------|
| PCG-001 | Gate check passed |
| PCG-002 | Gate check denied |
| PCG-003 | Mode transition approved |
| PCG-004 | Divergence receipt issued |
| PCG-005 | Gate check resulted in audit |
| PCG-006 | Non-interference violation detected |
| PCG-007 | Monotonicity violation detected |
| PCG-008 | Shim registered in registry |

## Contract Compliance

- INV-PCG-VISIBLE: All gate decisions visible via structured API responses
- INV-PCG-AUDITABLE: Every decision emits structured audit events with trace IDs
- INV-PCG-RECEIPT: Mode transitions and divergences produce signed receipts
- INV-PCG-TRANSITION: Escalations require approval; de-escalations auto-approved
