# bd-364: Key-Role Separation for Control-Plane Signing

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-02-21

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 94 | 94 |
| Rust unit tests | 50 | 50 |
| Python unit tests | 32 | 32 |

## Implementation

**File:** `crates/franken-node/src/control_plane/key_role_separation.rs`

### Core Types
- `KeyRole` — enum with Signing (0x0001), Encryption (0x0002), Issuance (0x0003), Attestation (0x0004)
- `KeyRoleBinding` — key_id, role, public_key_bytes, bound_at, bound_by, max_validity_seconds
- `KeyRoleRegistry` — in-memory registry enforcing role exclusivity
- `KeyRoleSeparationError` — RoleSeparationViolation, KeyRoleMismatch, KeyNotFound, RotationFailed

### Key API Methods
- `bind()` — bind a key to a role (rejects if key already bound to different role)
- `lookup()` / `lookup_by_role()` — query bindings
- `revoke()` — revoke an active key binding
- `rotate()` — atomically revoke old key + bind new key
- `verify_role()` — guard that rejects mismatched key usage
- `tag()` / `from_tag()` — 2-byte role tag serialization

### Event Codes (4)
| Code | Severity | Description |
|------|----------|-------------|
| KRS_KEY_ROLE_BOUND | INFO | Key successfully bound to role |
| KRS_KEY_ROLE_REVOKED | WARN | Key revoked from role |
| KRS_KEY_ROLE_ROTATED | INFO | Key rotated for a role |
| KRS_ROLE_VIOLATION_ATTEMPT | CRITICAL | Attempted use of key outside its role |

### Error Codes (4)
| Code | Description |
|------|-------------|
| KRS_ROLE_SEPARATION_VIOLATION | Key already bound to a different role |
| KRS_KEY_ROLE_MISMATCH | Key used for wrong role |
| KRS_KEY_NOT_FOUND | Key not found in registry |
| KRS_ROTATION_FAILED | Rotation failed |

### Invariants (4)
- **INV-KRS-ROLE-EXCLUSIVITY**: A key_id binds to at most one role
- **INV-KRS-ONE-ACTIVE**: Each role has at most one active key
- **INV-KRS-ROLE-GUARD**: verify_role rejects mismatched usage with zero bypass paths
- **INV-KRS-ROTATION-ATOMIC**: Rotation atomically revokes old + binds new

## Verification Commands

```bash
python3 scripts/check_key_role_separation.py --json     # 94/94 PASS
python3 -m pytest tests/test_check_key_role_separation.py  # 32 passed
```
