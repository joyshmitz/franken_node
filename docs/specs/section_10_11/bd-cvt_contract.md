# bd-cvt: Capability Profiles for Product Subsystems with Narrowing Enforcement

## Purpose

Define explicit capability profiles for product subsystems and enforce narrowing.
Each subsystem declares what capabilities it needs, and the runtime enforces that
declaration. Undeclared capability usage is rejected. This implements the
least-privilege capability narrowing required by Section 9G.1.

## Invariants

- **INV-CAP-LEAST-PRIVILEGE**: Subsystems receive only their declared capabilities.
- **INV-CAP-DENY-DEFAULT**: Any capability not explicitly granted is denied.
- **INV-CAP-AUDIT-COMPLETE**: Every grant/deny decision is recorded in the audit trail.
- **INV-CAP-PROFILE-VERSIONED**: Capability profiles carry a version; changes are detected
  and flagged for security review.
- **INV-CAP-DETERMINISTIC**: All outputs use BTreeMap for deterministic ordering.

## Capability Taxonomy

| Capability            | Description                                        | Risk Level | Audit Required |
|-----------------------|----------------------------------------------------|------------|----------------|
| `cap:network:listen`  | Bind a listening socket for inbound connections    | high       | yes            |
| `cap:network:connect` | Initiate outbound network connections              | medium     | yes            |
| `cap:fs:read`         | Read files from the file system                    | low        | no             |
| `cap:fs:write`        | Write files to the file system                     | medium     | yes            |
| `cap:fs:temp`         | Create and use temporary files                     | low        | no             |
| `cap:process:spawn`   | Spawn child processes                              | critical   | yes            |
| `cap:crypto:sign`     | Produce cryptographic signatures                   | critical   | yes            |
| `cap:crypto:verify`   | Verify cryptographic signatures                    | low        | no             |
| `cap:crypto:derive`   | Derive keys or key material                        | critical   | yes            |
| `cap:trust:read`      | Read trust state from the trust store              | low        | no             |
| `cap:trust:write`     | Mutate trust state in the trust store              | high       | yes            |
| `cap:trust:revoke`    | Revoke trust objects (irreversible)                | critical   | yes            |

## Implementation Surface

- `crates/franken-node/src/connector/capability_guard.rs`
  - `CapabilityProfile` -- subsystem capability declaration with justifications.
  - `CapabilityGuard` -- runtime enforcement of capability narrowing.
  - `CapabilityAuditEntry` -- audit trail entry for each grant/deny decision.
  - `CapabilityGuardError` -- structured errors for violations.
  - `ProfileChange` -- detects version/capability changes for security review.
  - `CapabilityName` -- validated capability identifier.
  - `RiskLevel` -- capability and subsystem risk classification.
  - `CAPABILITY_TAXONOMY` -- complete 12-capability taxonomy.
- `crates/franken-node/src/connector/mod.rs`
  - Wires `capability_guard` as a public submodule.
- `capabilities/` directory
  - TOML-based capability profiles for product subsystems.

## Event Codes

- `CAP-001` -- Capability granted to subsystem.
- `CAP-002` -- Capability denied to subsystem.
- `CAP-003` -- Capability profile changed (version mismatch).
- `CAP-004` -- Audit gap detected (missing audit entries).
- `CAP-005` -- Capability profile loaded.
- `CAP-006` -- Capability guard initialized.
- `CAP-007` -- Subsystem capability check completed.
- `CAP-008` -- Capability narrowing enforced.

## Error Codes

- `ERR_CAP_UNDECLARED` -- Capability not in the taxonomy.
- `ERR_CAP_DENIED` -- Capability not declared in subsystem profile.
- `ERR_CAP_PROFILE_MISSING` -- No profile registered for subsystem.
- `ERR_CAP_INVALID_LEVEL` -- Invalid risk level string.
- `ERR_CAP_AUDIT_FAILURE` -- Audit trail write failure.

## Acceptance Criteria

1. **Rust module exists** at `crates/franken-node/src/connector/capability_guard.rs`.
2. **Module wired** into `connector/mod.rs` as `pub mod capability_guard`.
3. **Capabilities directory** at `capabilities/` with at least 5 TOML profiles.
4. **Capability taxonomy** covers 12 capabilities with `cap:` prefix naming.
5. **Event codes** CAP-001 through CAP-008 are defined.
6. **Error codes** ERR_CAP_UNDECLARED, ERR_CAP_DENIED, ERR_CAP_PROFILE_MISSING,
   ERR_CAP_INVALID_LEVEL, ERR_CAP_AUDIT_FAILURE are defined.
7. **Invariants** INV-CAP-LEAST-PRIVILEGE, INV-CAP-DENY-DEFAULT, INV-CAP-AUDIT-COMPLETE,
   INV-CAP-PROFILE-VERSIONED, INV-CAP-DETERMINISTIC are defined and tested.
8. **Deny-default enforcement**: undeclared capabilities are rejected.
9. **Audit trail**: every grant/deny decision is recorded.
10. **Profile versioning**: changes between profile versions are detected.
11. **Schema version** is "cap-v1.0".
12. **Unit tests** cover event codes, error codes, invariants, guard pass/fail,
    taxonomy completeness, profile validation, change detection, audit trail,
    serde round-trips, deterministic ordering, and Send+Sync bounds.
13. **Gate script** and **test file** pass the verification triple.

## Verification Artifacts

| Artifact     | Path                                                           |
|--------------|----------------------------------------------------------------|
| Gate script  | `scripts/check_capability_profiles.py`                         |
| Gate tests   | `tests/test_check_capability_profiles.py`                      |
| Evidence     | `artifacts/section_10_11/bd-cvt/verification_evidence.json`    |
| Summary      | `artifacts/section_10_11/bd-cvt/verification_summary.md`       |
| Spec         | `docs/specs/section_10_11/bd-cvt_contract.md`                  |
| Profiles     | `capabilities/*.toml`                                          |
