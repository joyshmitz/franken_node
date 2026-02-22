# bd-2ah Contract: Obligation-Tracked Two-Phase Channel Contracts

**Bead:** bd-2ah
**Section:** 10.11 (FrankenSQLite-Inspired Runtime Systems)

## Summary

Adopt canonical obligation-tracked two-phase channel contracts (from section 10.15,
bd-1n5p) for critical product-layer flows. Provides `ObligationChannel`,
`ObligationLedger`, and `TwoPhaseFlow` abstractions that compose into
prepare/commit workflows with deadline tracking, timeout policies, and closure
proofs.

## Scope

- Runtime module: `crates/franken-node/src/runtime/obligation_channel.rs`
- Runtime module wiring: `crates/franken-node/src/runtime/mod.rs`

## Dependencies

| Dependency | Bead | Description |
|------------|------|-------------|
| Obligation Tracker (upstream) | bd-1n5p | Connector-layer two-phase obligation protocol |

## Invariants

| ID | Name | Description |
|----|------|-------------|
| INV-OCH-TRACKED | Tracked Obligations | Every obligation sent through a channel is tracked in the ledger |
| INV-OCH-DEADLINE | Deadline Enforcement | Every channel obligation has an explicit deadline |
| INV-OCH-LEDGER-COMPLETE | Ledger Completeness | The ledger records every state transition |
| INV-OCH-CLOSURE-SIGNED | Closure Proofs | Closure proofs list all obligations and their terminal states |
| INV-OCH-TWO-PHASE | Two-Phase Protocol | Critical flows use prepare/commit (never single-shot) |
| INV-OCH-ROLLBACK-ATOMIC | Atomic Rollback | Rollback releases all prepared obligations atomically |

## Event Codes

| Code | Name | Description |
|------|------|-------------|
| FN-OB-001 | Obligation Created | Obligation created and queued in channel |
| FN-OB-002 | Obligation Sent | Obligation sent to receiver |
| FN-OB-003 | Obligation Fulfilled | Obligation fulfilled by receiver |
| FN-OB-004 | Obligation Rejected | Obligation rejected by receiver |
| FN-OB-005 | Obligation Timed Out | Obligation exceeded its deadline |
| FN-OB-006 | Obligation Cancelled | Obligation cancelled by sender |
| FN-OB-007 | Prepare Initiated | Two-phase prepare initiated |
| FN-OB-008 | Prepare Succeeded | Two-phase prepare succeeded |
| FN-OB-009 | Commit Completed | Two-phase commit completed |
| FN-OB-010 | Rollback Completed | Two-phase rollback completed |
| FN-OB-011 | Closure Proof Generated | Closure proof generated |
| FN-OB-012 | Ledger Query Executed | Ledger query executed |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_OCH_NOT_FOUND | Obligation ID not found |
| ERR_OCH_ALREADY_FULFILLED | Obligation already fulfilled |
| ERR_OCH_ALREADY_REJECTED | Obligation already rejected |
| ERR_OCH_TIMED_OUT | Obligation timed out |
| ERR_OCH_CANCELLED | Obligation cancelled |
| ERR_OCH_PREPARE_FAILED | Prepare phase failed |
| ERR_OCH_COMMIT_FAILED | Commit phase failed |
| ERR_OCH_ROLLBACK_FAILED | Rollback failed |
| ERR_OCH_DEADLINE_EXCEEDED | Obligation deadline exceeded |
| ERR_OCH_INVALID_TRANSITION | Invalid state transition |

## Acceptance Criteria

1. `ObligationChannel<T>` struct exists with `send`, `fulfill`, `reject` methods.
2. `ObligationLedger` struct exists with `query_outstanding` and `generate_closure_proof` methods.
3. `TwoPhaseFlow` struct exists with `prepare`, `commit`, `rollback` methods.
4. `ChannelObligation` struct tracks obligation_id, deadline, trace_id, status.
5. `ObligationStatus` enum has Created, Fulfilled, Rejected, TimedOut, Cancelled variants.
6. `TimeoutPolicy` enum has Retry, Compensate, Escalate variants.
7. `ClosureProof` struct lists all obligations and their terminal states.
8. All event codes FN-OB-001 through FN-OB-012 are defined.
9. All error codes are defined.
10. All invariant constants are present.
11. Schema version constant is `och-v1.0`.
12. Module is wired in `runtime/mod.rs`.
13. At least 15 unit tests in `#[cfg(test)]` module.
14. All types have `Serialize`/`Deserialize` derives.
15. `BTreeMap` is used for ordered collections.

## Artifacts

| Artifact | Path |
|----------|------|
| Source module | `crates/franken-node/src/runtime/obligation_channel.rs` |
| Module wiring | `crates/franken-node/src/runtime/mod.rs` |
| Spec contract | `docs/specs/section_10_11/bd-2ah_contract.md` |
| Gate script | `scripts/check_obligation_channel_protocol.py` |
| Compatibility gate alias | `scripts/check_obligation_channels.py` |
| Test suite | `tests/test_check_obligation_channel_protocol.py` |
| Compatibility test alias | `tests/test_check_obligation_channels.py` |
| Verification evidence | `artifacts/section_10_11/bd-2ah/verification_evidence.json` |
| Verification summary | `artifacts/section_10_11/bd-2ah/verification_summary.md` |

## File Layout

```text
docs/specs/section_10_11/bd-2ah_contract.md
crates/franken-node/src/runtime/obligation_channel.rs
crates/franken-node/src/runtime/mod.rs
scripts/check_obligation_channel_protocol.py
tests/test_check_obligation_channel_protocol.py
scripts/check_obligation_channels.py
tests/test_check_obligation_channels.py
artifacts/section_10_11/bd-2ah/verification_evidence.json
artifacts/section_10_11/bd-2ah/verification_summary.md
```
