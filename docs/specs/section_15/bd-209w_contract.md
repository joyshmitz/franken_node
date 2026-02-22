# bd-209w: Signed Extension Registry with Provenance and Revocation

**Section:** 15 — Signed Extension Registry
**Status:** Implemented
**Module:** `crates/franken-node/src/supply_chain/extension_registry.rs`

## Purpose

Manages a registry of extensions where every entry is cryptographically signed, carries provenance attestations, and supports monotonic revocation. Extensions progress through a defined lifecycle (Submitted → Active → Deprecated → Revoked) with audit trails at every transition.

## Extension Status Lifecycle (4 states)

| Status | Label | Terminal | Description |
|--------|-------|----------|-------------|
| `Submitted` | submitted | No | Initial submission awaiting review |
| `Active` | active | No | Approved and available for use |
| `Deprecated` | deprecated | No | Marked for removal, still functional |
| `Revoked` | revoked | Yes | Permanently removed, irreversible |

## Signature Verification

- Every extension requires a valid `ExtensionSignature` with key_id, algorithm, and hex-encoded signature
- Signature must be >= 64 hex characters
- Configurable via `RegistryConfig.require_signature`

## Provenance Attestation

- Every extension requires a `ProvenanceAttestation` with publisher_id, build_system, source_repository, vcs_commit, and attestation_hash
- All fields must be non-empty for validation to pass
- Configurable via `RegistryConfig.require_provenance`

## Revocation Model

- Revocation is monotonic: sequence numbers strictly increase
- Revocation is irreversible: revoked extensions cannot be un-revoked
- 5 revocation reasons: SecurityVulnerability, PolicyViolation, MaintainerRequest, LicenseConflict, Superseded
- `RevocationRecord` captures extension_id, timestamp, reason, revoked_by, and monotonic sequence

## Version Lineage

- `VersionEntry` tracks version string, parent_version, content_hash, registration time, and compatible_with list
- Versions cannot be added to revoked extensions
- Lineage queryable via `version_lineage()` method

## Registry Operations

| Operation | Method | Gate |
|-----------|--------|------|
| Register | `register()` | Signature + provenance validation |
| Add version | `add_version()` | Not revoked |
| Deprecate | `deprecate()` | Not revoked |
| Revoke | `revoke()` | Not already revoked |
| Query | `query()` | None |
| List | `list()` | Optional status filter |

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-SER-SIGNED | Every extension entry carries a valid signature |
| INV-SER-PROVENANCE | Provenance chain required for all registrations |
| INV-SER-REVOCABLE | Revocation is monotonic and irreversible |
| INV-SER-MONOTONIC | Version sequences strictly increase within lineage |
| INV-SER-AUDITABLE | Every mutation produces an immutable audit record |
| INV-SER-DETERMINISTIC | Same inputs produce same registry state |

## Event Codes

| Code | Meaning |
|------|---------|
| SER-001 | Extension registered |
| SER-002 | Signature verified |
| SER-003 | Provenance validated |
| SER-004 | Version added |
| SER-005 | Extension deprecated |
| SER-006 | Extension revoked |
| SER-007 | Lineage checked |
| SER-008 | Audit exported |
| SER-009 | Integrity verified |
| SER-010 | Query executed |
| SER-ERR-001 | Invalid signature |
| SER-ERR-002 | Missing provenance |
| SER-ERR-003 | Already revoked |

## Test Coverage

- 30 Rust inline tests covering registration, signature validation, provenance validation, version management, deprecation, revocation (monotonic, irreversible), query/listing, status lifecycle, audit logging, JSONL export, content hashing, configuration, and determinism
- Python verification gate checks
- Python unit tests
