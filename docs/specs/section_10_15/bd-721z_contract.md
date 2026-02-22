# bd-721z: Ambient-Authority Audit Gate for Control-Plane Modules

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-721z |
| Section | 10.15 |
| Title | Add ambient-authority audit gate for control-plane modules |
| Type | task |

## Purpose

Hard Runtime Invariant #10 (Section 8.5) mandates "no ambient authority" —
control-plane modules must not directly access network sockets, spawn OS
processes, read wall-clock time, or perform filesystem I/O without going
through capability-gated APIs provided by the asupersync correctness kernel.

This bead adds a CI gate (`tools/lints/ambient_authority_gate.rs`) that audits
control-plane modules for ambient authority usage and fails the build when
violations are found outside a signed allowlist.

## Deliverables

| Artifact | Path |
|----------|------|
| Lint tool | `tools/lints/ambient_authority_gate.rs` |
| Allowlist | `docs/specs/ambient_authority_allowlist.toml` |
| Policy doc | `docs/specs/ambient_authority_policy.md` |
| Rust module | `crates/franken-node/src/runtime/authority_audit.rs` |
| Config | `config/security_critical_modules.toml` |
| Check script | `scripts/check_ambient_authority.py` |
| Test suite | `tests/test_check_ambient_authority.py` |
| Evidence | `artifacts/section_10_15/bd-721z/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-721z/verification_summary.md` |

## Invariants

- **INV-AA-NO-AMBIENT**: No control-plane module uses ambient authority APIs
  outside the signed allowlist.
- **INV-AA-GUARD-ENFORCED**: The `AuthorityAuditGuard` must be invoked before
  any capability-gated operation.
- **INV-AA-AUDIT-COMPLETE**: Every security-critical module in the inventory
  must be audited.
- **INV-AA-INVENTORY-CURRENT**: The security-critical module inventory must
  include all modules in scope.
- **INV-AA-DETERMINISTIC**: Audit report output uses BTreeMap for deterministic
  ordering.

## Event Codes

| Code | Description |
|------|-------------|
| FN_AA_001 | Audit scan started |
| FN_AA_002 | Module audit passed |
| FN_AA_003 | Module audit found violation |
| FN_AA_004 | Allowlist exception applied |
| FN_AA_005 | Expired allowlist entry detected |
| FN_AA_006 | Audit report generated |
| FN_AA_007 | Guard bypass detected |
| FN_AA_008 | Inventory validation complete |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_AA_MISSING_CAPABILITY | Required capability not declared |
| ERR_AA_AMBIENT_DETECTED | Ambient authority usage found |
| ERR_AA_INVENTORY_STALE | Module inventory out of date |
| ERR_AA_AUDIT_INCOMPLETE | Not all modules audited |
| ERR_AA_GUARD_BYPASSED | Guard was bypassed |

## Gate Contract

The check script (`scripts/check_ambient_authority.py`) must:
- Emit `--json` output with `bead_id`, `verdict`, `checks_passed`, `checks_total`
- Provide a `self_test()` function returning structured results
- Validate >= 11 checks including file existence, event codes, error codes, invariants
- Exit 0 on PASS, 1 on FAIL
