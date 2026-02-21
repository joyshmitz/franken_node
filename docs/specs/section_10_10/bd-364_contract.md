# bd-364 Contract: Key-Role Separation for Control-Plane Signing

**Bead:** bd-364
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Implement key-role separation for control-plane signing, encryption, and
issuance operations. In the three-kernel architecture (franken_engine +
asupersync + franken_node), a single key that handles all cryptographic
operations creates a catastrophic blast radius on compromise. By enforcing
strict key-role separation -- distinct keys for SIGNING (authenticity),
ENCRYPTION (confidentiality), ISSUANCE (authority), and ATTESTATION
(operator attestation) -- the blast radius of any single key compromise is
contained to one operational domain.

This bead establishes the KeyRoleRegistry and enforcement layer that all
downstream trust operations (session auth, revocation, zone segmentation)
depend upon.

## Dependencies

- **Upstream:** bd-1r2 (audience-bound token chains for control actions)
- **Downstream:** bd-oty (session-authenticated control channel)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Structures

### KeyRole

An enum with exactly four variants, each with a fixed 2-byte role tag:

| Variant       | Tag    | Description                                        |
|---------------|--------|----------------------------------------------------|
| Signing       | 0x0001 | Ed25519/ECDSA for authenticating control messages   |
| Encryption    | 0x0002 | X25519/AES for protecting confidential payloads     |
| Issuance      | 0x0003 | Dedicated key for minting tokens/certificates       |
| Attestation   | 0x0004 | Dedicated key for operator attestation signatures   |

### KeyRoleBinding

| Field                | Type               | Description                              |
|---------------------|--------------------|------------------------------------------|
| key_id              | String             | TrustObjectId with KEY domain            |
| role                | KeyRole            | Role this key is bound to                |
| public_key_bytes    | Vec<u8>            | Public key material                      |
| bound_at            | u64                | UTC timestamp when binding was created   |
| bound_by            | String             | TrustObjectId of the approving authority |
| max_validity_seconds| u64                | Maximum validity duration for this key   |

### KeyRoleRegistry

Stores active bindings and supports:

| Operation          | Signature                                                 |
|--------------------|---------------------------------------------------------|
| bind               | (key_id, role, public_key, authority) -> Result           |
| lookup             | (key_id) -> Option<KeyRoleBinding>                        |
| lookup_by_role     | (role) -> Vec<KeyRoleBinding>                             |
| revoke             | (key_id, authority) -> Result                             |
| rotate             | (role, old_key_id, new_key_id, new_pub_key, authority) -> Result |
| verify_role        | (key_id, expected_role) -> Result                         |

## Invariants

- **INV-KRS-ROLE-EXCLUSIVITY:** A single key_id MUST NOT be bound to more
  than one role. Attempting to bind the same key to a second role returns
  RoleSeparationViolation.
- **INV-KRS-ONE-ACTIVE:** Each active role has at most one bound key at any
  time; binding a second key to an already-filled role is rejected.
- **INV-KRS-ROLE-GUARD:** Using a key outside its registered role is
  rejected with KEY_ROLE_MISMATCH at the call site -- zero bypass paths.
- **INV-KRS-ROTATION-ATOMIC:** Key rotation atomically revokes the old key
  and binds the new key; both operations succeed or neither does.

## Event Codes

| Code                         | Severity | Description                            |
|-----------------------------|----------|----------------------------------------|
| KRS_KEY_ROLE_BOUND          | INFO     | Key successfully bound to role          |
| KRS_KEY_ROLE_REVOKED        | WARN     | Key revoked from role                   |
| KRS_KEY_ROLE_ROTATED        | INFO     | Key rotated for a role                  |
| KRS_ROLE_VIOLATION_ATTEMPT  | CRITICAL | Attempted use of key outside its role   |

## Error Codes

| Code                         | Description                                        |
|-----------------------------|----------------------------------------------------|
| KRS_ROLE_SEPARATION_VIOLATION | Key already bound to a different role              |
| KRS_KEY_ROLE_MISMATCH       | Key used for wrong role                             |
| KRS_KEY_NOT_FOUND           | Key not found in registry                           |
| KRS_ROTATION_FAILED         | Rotation failed (old key not found or state error)  |

## Acceptance Criteria

1. `KeyRole` enum defines exactly four variants: `Signing`, `Encryption`,
   `Issuance`, `Attestation` with fixed 2-byte role tags.
2. `KeyRoleBinding` struct with key_id, role, public_key_bytes, bound_at,
   bound_by, max_validity_seconds.
3. `KeyRoleRegistry` enforces role exclusivity: binding a key already bound
   to another role is rejected with `KRS_ROLE_SEPARATION_VIOLATION`.
4. `verify_role(key_id, expected_role)` guard rejects mismatched usage with
   `KRS_KEY_ROLE_MISMATCH`.
5. Key rotation atomically revokes old key and binds new key.
6. Structured log events emitted for bind, revoke, rotation, and violation
   attempt, each with trace correlation ID.
7. Unit tests cover: bind each role type, role exclusivity violation,
   lookup by ID and by role, revoke and re-lookup returns None, rotation
   atomicity, verify_role guard pass/fail.
8. Verification: `scripts/check_key_role_separation.py --json`
9. Evidence: `artifacts/section_10_10/bd-364/verification_evidence.json`

## Verification

- Script: `scripts/check_key_role_separation.py --json`
- Evidence: `artifacts/section_10_10/bd-364/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-364/verification_summary.md`
