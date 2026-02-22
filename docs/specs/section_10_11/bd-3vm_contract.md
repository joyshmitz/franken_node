# bd-3vm: Ambient-Authority Audit Gate for Security-Critical Modules

## Purpose

Implement an ambient-authority audit gate that detects and rejects ambient
authority usage in security-critical product modules. This enforces Architecture
Invariant #10: "no ambient authority." Every security-critical operation must
receive its capabilities explicitly through a `CapabilityContext` rather than
relying on global state, ambient environment variables, or implicit file-system
access.

## Invariants

- **INV-AA-NO-AMBIENT**: No security-critical module may use ambient authority;
  all capabilities must be explicitly threaded via `CapabilityContext`.
- **INV-AA-GUARD-ENFORCED**: The `AuthorityAuditGuard` must be consulted before
  any security-critical operation executes.
- **INV-AA-AUDIT-COMPLETE**: Every audit run must produce a complete report
  covering all modules in the security-critical inventory.
- **INV-AA-INVENTORY-CURRENT**: The security-critical module inventory must be
  kept in sync with the actual codebase.
- **INV-AA-DETERMINISTIC**: Audit results are deterministic for the same input;
  BTreeMap is used for ordered output.

## Implementation Surface

- `crates/franken-node/src/runtime/authority_audit.rs`
  - `CapabilityContext` — explicit capability threading for operations.
  - `AuthorityAuditGuard` — central enforcement point for capability checks.
  - `SecurityCriticalInventory` — registry of modules and their required capabilities.
  - `AmbientAuthorityViolation` — structured error for detected violations.
  - `AuditReport` — complete audit output with deterministic ordering.
  - `AmbientAuthorityPattern` — static analysis detection patterns.
  - `Capability` — taxonomy of all system capabilities.
  - `RiskLevel` — module risk classification.
- `config/security_critical_modules.toml`
  - TOML-based inventory of security-critical modules with required capabilities.
- `crates/franken-node/src/runtime/mod.rs`
  - Wires `authority_audit` as a public submodule.

## Event Codes

- `FN-AA-001` — Audit started for a module.
- `FN-AA-002` — Module passed ambient authority check.
- `FN-AA-003` — Ambient authority violation detected.
- `FN-AA-004` — Capability context verified for module.
- `FN-AA-005` — Static analysis pattern matched.
- `FN-AA-006` — Audit report generated.
- `FN-AA-007` — Module inventory loaded.
- `FN-AA-008` — Guard enforcement decision made.

## Error Codes

- `ERR_AA_MISSING_CAPABILITY` — Required capability not present in context.
- `ERR_AA_AMBIENT_DETECTED` — Ambient authority pattern detected in module source.
- `ERR_AA_INVENTORY_STALE` — Module inventory does not match codebase.
- `ERR_AA_AUDIT_INCOMPLETE` — Audit did not cover all inventory modules.
- `ERR_AA_GUARD_BYPASSED` — Security-critical operation executed without guard.

## Capability Taxonomy

| Capability              | Description                             |
|-------------------------|-----------------------------------------|
| key_access              | Access to cryptographic key material    |
| artifact_signing        | Ability to sign artifacts               |
| signature_verification  | Ability to verify signatures            |
| epoch_store_access      | Access to the epoch store               |
| trust_state_mutation    | Ability to modify trust state           |
| network_egress          | Network egress capability               |
| file_system_read        | File system read access                 |
| file_system_write       | File system write access                |
| policy_evaluation       | Access to policy evaluation engine      |
| revocation_access       | Access to revocation list               |

## Acceptance Criteria

1. **Rust module exists** at `crates/franken-node/src/runtime/authority_audit.rs`.
2. **Module wired** into `runtime/mod.rs` as `pub mod authority_audit`.
3. **Config inventory** at `config/security_critical_modules.toml` lists all
   security-critical modules with required capabilities and risk levels.
4. **Event codes** FN-AA-001 through FN-AA-008 are defined.
5. **Error codes** ERR_AA_MISSING_CAPABILITY, ERR_AA_AMBIENT_DETECTED,
   ERR_AA_INVENTORY_STALE, ERR_AA_AUDIT_INCOMPLETE, ERR_AA_GUARD_BYPASSED
   are defined.
6. **Invariants** INV-AA-NO-AMBIENT, INV-AA-GUARD-ENFORCED, INV-AA-AUDIT-COMPLETE,
   INV-AA-INVENTORY-CURRENT, INV-AA-DETERMINISTIC are defined and tested.
7. **Audit report generation** produces deterministic output using BTreeMap.
8. **Schema version** is "aa-v1.0".
9. **Unit tests** cover event codes, error codes, invariants, guard pass/fail,
   advisory vs strict mode, audit_all, deterministic output, serde round-trips,
   and Send+Sync bounds.
10. **Capability taxonomy** covers at least 10 distinct capabilities.
11. **Gate script** and **test file** pass the verification triple.

## Verification Artifacts

| Artifact | Path |
|----------|------|
| Gate script | `scripts/check_ambient_authority.py` |
| Gate tests | `tests/test_check_ambient_authority.py` |
| Evidence | `artifacts/section_10_11/bd-3vm/verification_evidence.json` |
| Summary | `artifacts/section_10_11/bd-3vm/verification_summary.md` |
| Spec | `docs/specs/section_10_11/bd-3vm_contract.md` |
| Config | `config/security_critical_modules.toml` |
