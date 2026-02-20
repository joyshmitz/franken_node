# bd-bq6y: Generic Lease Service

## Bead: bd-bq6y | Section: 10.13

## Purpose

Implements a generic lease service supporting operation execution,
state writes, and migration handoff. Leases have deterministic expiry
and renewal behavior. Stale lease usage is rejected.

## Invariants

| ID | Statement |
|----|-----------|
| INV-LS-EXPIRY | Leases expire deterministically at the configured TTL; expired leases cannot be used. |
| INV-LS-RENEWAL | Lease renewal extends TTL only if the lease is still active; renewing expired leases is forbidden. |
| INV-LS-STALE-REJECT | Operations using a stale (expired or revoked) lease are rejected. |
| INV-LS-PURPOSE | Leases are typed by purpose (Operation, StateWrite, MigrationHandoff); purpose cannot change after creation. |

## Types

### LeasePurpose
- Enum: `Operation`, `StateWrite`, `MigrationHandoff`

### Lease
- `lease_id: String`
- `holder: String`
- `purpose: LeasePurpose`
- `ttl_secs: u64`
- `granted_at: u64` — epoch seconds.
- `renewed_at: u64` — epoch seconds of last renewal.
- `revoked: bool`

### LeaseService
- Per-lease tracking with grant, renew, use, revoke operations.
- Audit trail via `Vec<LeaseDecision>`.
- Methods: `grant`, `renew`, `use_lease`, `revoke`, `get`, `active_count`.

### LeaseDecision
- `lease_id: String`
- `action: String` — grant, renew, use, revoke.
- `allowed: bool`
- `reason: String`
- `trace_id: String`
- `timestamp: String`

### LeaseError
- `Expired { lease_id }`
- `StaleUse { lease_id }`
- `AlreadyRevoked { lease_id }`
- `PurposeMismatch { lease_id, expected, actual }`

## Error Codes

| Code | Trigger |
|------|---------|
| `LS_EXPIRED` | Lease has passed its TTL. |
| `LS_STALE_USE` | Attempt to use a stale/expired lease. |
| `LS_ALREADY_REVOKED` | Lease was already revoked. |
| `LS_PURPOSE_MISMATCH` | Lease purpose does not match required purpose. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-bq6y_contract.md` |
| Implementation | `crates/franken-node/src/connector/lease_service.rs` |
| Integration tests | `tests/integration/lease_service_contract.rs` |
| Lease contract | `artifacts/section_10_13/bd-bq6y/lease_service_contract.json` |
| Verification evidence | `artifacts/section_10_13/bd-bq6y/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-bq6y/verification_summary.md` |
