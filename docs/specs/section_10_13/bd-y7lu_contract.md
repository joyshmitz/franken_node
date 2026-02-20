# bd-y7lu: Revocation Registry with Monotonic Revocation-Head Checkpoints

## Bead: bd-y7lu | Section: 10.13

## Purpose

Implements a revocation registry that tracks revoked artifacts/capabilities
per zone/tenant using monotonic revocation-head checkpoints. Stale head
updates are rejected. Head state is recoverable from canonical storage.

## Invariants

| ID | Statement |
|----|-----------|
| INV-REV-MONOTONIC | Revocation heads are strictly monotonic per zone; a new head must have a sequence > current head. |
| INV-REV-STALE-REJECT | Updates with a sequence <= the current head are rejected as stale. |
| INV-REV-RECOVERABLE | Head state can be recovered from canonical storage (the revocation log). |
| INV-REV-ZONE-ISOLATED | Revocation heads are isolated per zone/tenant; one zone's head cannot affect another. |

## Types

### RevocationHead
- `zone_id: String`
- `sequence: u64` — monotonically increasing per zone.
- `revoked_artifact: String`
- `reason: String`
- `timestamp: String`
- `trace_id: String`

### RevocationRegistry
- Per-zone current head tracking.
- Canonical log for recovery.
- Methods: `advance_head`, `current_head`, `is_revoked`, `recover_from_log`.

### RevocationError
- `StaleHead { zone_id, offered, current }` — offered sequence <= current.
- `ZoneNotFound { zone_id }` — unknown zone lookup.
- `RecoveryFailed { reason }` — canonical log recovery error.

## Error Codes

| Code | Trigger |
|------|---------|
| `REV_STALE_HEAD` | Offered head sequence <= current head for zone. |
| `REV_ZONE_NOT_FOUND` | Query for an unknown zone. |
| `REV_RECOVERY_FAILED` | Recovery from canonical log failed. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-y7lu_contract.md` |
| Implementation | `crates/franken-node/src/supply_chain/revocation_registry.rs` |
| Conformance tests | `tests/conformance/revocation_head_monotonicity.rs` |
| Head history | `artifacts/section_10_13/bd-y7lu/revocation_head_history.json` |
| Verification evidence | `artifacts/section_10_13/bd-y7lu/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-y7lu/verification_summary.md` |
