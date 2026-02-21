# Key-Role Separation Policy

**Policy ID:** POL-KRS-001
**Section:** 10.10 (FCP-Inspired Hardening)
**Bead:** bd-364
**Effective:** 2026-02-20
**Owner:** CrimsonCrane

## 1. Purpose

This policy establishes the rules for key-role separation in the
franken_node control plane. It ensures that cryptographic keys are bound
to a single operational role and cannot be reused across roles, limiting
the blast radius of any single key compromise.

## 2. Scope

Applies to all cryptographic key material used in control-plane operations
within the three-kernel architecture (franken_engine, asupersync,
franken_node).

## 3. Definitions

- **Key Role:** A classification that restricts a cryptographic key to a
  single operational domain (Signing, Encryption, Issuance, or Attestation).
- **Key Binding:** The association between a key identifier and exactly one
  role, recorded with authority and timestamp.
- **Role Exclusivity:** The invariant that no key may serve more than one
  role simultaneously.
- **Key Rotation:** The atomic replacement of a role-bound key with a new
  key, revoking the old key in the same operation.

## 4. Mandatory Roles

| Role         | Tag    | Permitted Operations                              |
|-------------|--------|---------------------------------------------------|
| Signing     | 0x0001 | Authenticate control messages, sign attestations   |
| Encryption  | 0x0002 | Encrypt/decrypt confidential payloads              |
| Issuance    | 0x0003 | Mint delegation tokens and authority certificates  |
| Attestation | 0x0004 | Sign operator attestation payloads                 |

## 5. Binding Rules

1. Every key MUST be bound to exactly one role before use.
2. A key MUST NOT be bound to more than one role (INV-KRS-ROLE-EXCLUSIVITY).
3. Each role SHOULD have at most one active key at any time.
4. All bindings MUST record the authority that approved the binding.
5. Bindings MUST include a max_validity_seconds field.

## 6. Usage Enforcement

1. Before any cryptographic operation, the system MUST verify that the key
   is bound to the expected role via `verify_role()`.
2. Any attempt to use a key for a role it is not bound to MUST be rejected
   with error code `KRS_KEY_ROLE_MISMATCH`.
3. Rejected attempts MUST emit a CRITICAL-severity structured log event
   (`KRS_ROLE_VIOLATION_ATTEMPT`).

## 7. Rotation Rules

1. Key rotation MUST be atomic: the old key is revoked and the new key is
   bound in a single operation.
2. After rotation, the old key MUST NOT be usable for any role.
3. Rotation events MUST be logged with both old and new key fingerprints.

## 8. Audit Requirements

All key lifecycle events (bind, revoke, rotate, violation attempt) MUST be
emitted as structured log events with trace_id correlation for audit trail
reconstruction.

## 9. Compliance

Verification is automated via `scripts/check_key_role_separation.py --json`.
Evidence is stored at `artifacts/section_10_10/bd-364/verification_evidence.json`.
