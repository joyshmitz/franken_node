# bd-2gr Contract: Epoch Guard + Transition Barrier Integration

**Bead:** bd-2gr  
**Section:** 10.11 (FrankenSQLite-Inspired Runtime Systems)

## Purpose

Integrate canonical monotonic security epoch semantics and transition barriers into
product-runtime trust operations. Every trust-sensitive operation is epoch-bound,
all trust artifacts are creation-epoch tagged, and epoch changes are coordinated
through a drain barrier with abort-on-timeout semantics.

## Scope

- Runtime guard module: `crates/franken-node/src/runtime/epoch_guard.rs`
- Runtime transition coordinator: `crates/franken-node/src/runtime/epoch_transition.rs`
- Runtime module wiring: `crates/franken-node/src/runtime/mod.rs`

## Core Guarantees

1. **Epoch-bound operations**: operations with stale or future epochs are rejected.
2. **Fail-closed validation**: indeterminate epoch state rejects instead of allowing.
3. **Epoch-scoped signatures**: signatures are bound to `(payload, epoch, domain)`.
4. **Transition barrier**: new epoch activates only after all services drain.
5. **Abort-on-timeout**: failed quiescence aborts transition and preserves prior epoch.
6. **Immutable artifact epoch tags**: `creation_epoch` is immutable post-creation.

## Event Codes

### Guard Events

- `EPOCH_OPERATION_ACCEPTED`
- `STALE_EPOCH_REJECTED`
- `FUTURE_EPOCH_REJECTED`
- `EPOCH_UNAVAILABLE`
- `EPOCH_SIGNATURE_VERIFIED`
- `EPOCH_SIGNATURE_REJECTED`

### Transition Events

- `EPOCH_PROPOSED`
- `EPOCH_DRAIN_REQUESTED`
- `EPOCH_DRAIN_CONFIRMED`
- `EPOCH_ADVANCED`
- `EPOCH_TRANSITION_ABORTED`

## Error Codes

- `STALE_EPOCH_REJECTED`
- `FUTURE_EPOCH_REJECTED`
- `EPOCH_UNAVAILABLE`
- `EPOCH_TRANSITION_NO_ACTIVE`
- `ERR_BARRIER_CONCURRENT`
- `ERR_BARRIER_TIMEOUT`
- `EPOCH_TRANSITION_ADVANCE_MISMATCH`

## Invariants

- `INV-EP-MONOTONIC`: control epoch only advances; never regresses.
- `INV-EP-DRAIN-BARRIER`: no new-epoch activation before full drain ACK.
- `INV-EP-FAIL-CLOSED`: epoch indeterminacy rejects within bounded latency.
- `INV-EP-SPLIT-BRAIN-GUARD`: bounded `max_epoch_lag` protects replicas.
- `INV-EP-IMMUTABLE-CREATION-EPOCH`: artifact creation epoch is immutable.
- `INV-EP-AUDIT-HISTORY`: transition metadata is appended for every attempt.

## Acceptance Criteria

1. Stale operation/artifact epochs are rejected with `STALE_EPOCH_REJECTED`.
2. Future operation/artifact epochs are rejected with `FUTURE_EPOCH_REJECTED`.
3. Epoch-scoped signatures fail verification across epoch boundaries.
4. Transition sequence is enforced: propose -> drain -> commit (or abort).
5. Barrier blocks new-epoch operations before commit.
6. Timeout abort preserves pre-transition epoch and records abort metadata.
7. Split-brain guard rejects replica lag beyond `max_epoch_lag`.
8. Transition history logs transition timestamp, reason, initiator, outcome.
9. `EpochTaggedArtifact.creation_epoch` has no mutation API.

## Evidence Fields

Verification evidence JSON must include:

- `epoch_transitions_attempted`
- `epoch_transitions_completed`
- `epoch_transitions_aborted`
- `artifacts_rejected_stale_epoch`
- `quiescence_latency_ms`

## File Layout

```text
docs/specs/section_10_11/bd-2gr_contract.md
crates/franken-node/src/runtime/epoch_guard.rs
crates/franken-node/src/runtime/epoch_transition.rs
scripts/check_epoch_integration.py
tests/test_check_epoch_integration.py
artifacts/section_10_11/bd-2gr/verification_evidence.json
artifacts/section_10_11/bd-2gr/verification_summary.md
```
