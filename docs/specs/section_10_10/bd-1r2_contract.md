# bd-1r2: Audience-Bound Token Chains for Control Actions

**Section:** 10.10 -- FCP-Inspired Hardening
**Status:** In Progress
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

Enhancement Map 9E.4 mandates capability token delegation chains for migration
and control-plane actions. In the three-kernel architecture, control actions
(policy updates, migration triggers, zone reconfiguration) must carry
cryptographic proof of authorization that is audience-bound -- a token issued
for one service/kernel cannot be replayed against another.

Without audience-bound token chains, the no-ambient-authority invariant (8.5) is
violated: any entity with a valid token could escalate its reach across kernel
boundaries.

## Data Model

### AudienceBoundToken

| Field                | Type                        | Description                                              |
|----------------------|-----------------------------|----------------------------------------------------------|
| `token_id`           | `TokenId(String)`           | Unique identifier (UUID-style) for this token            |
| `issuer`             | `String`                    | Identity of the entity that issued this token            |
| `audience`           | `Vec<String>`               | List of intended recipients / service identifiers        |
| `capabilities`       | `BTreeSet<ActionScope>`     | Granted action scopes (strictly attenuated on delegation)|
| `issued_at`          | `u64`                       | UTC timestamp (ms) when the token was issued             |
| `expires_at`         | `u64`                       | UTC timestamp (ms) after which the token is invalid      |
| `nonce`              | `String`                    | Unique nonce for replay detection                        |
| `parent_token_hash`  | `Option<String>`            | Hash of parent token (None for root tokens)              |
| `signature`          | `String`                    | Signature over canonical preimage                        |
| `max_delegation_depth` | `u8`                      | Maximum number of further delegations (0 = no delegation)|

### ActionScope (enum)

- `Migrate` -- Initiate or manage migrations
- `Rollback` -- Rollback to prior state
- `Promote` -- Promote artifacts / trust levels
- `Revoke` -- Revoke credentials or tokens
- `Configure` -- Modify configuration parameters

### TokenChain

Ordered sequence of `AudienceBoundToken` values where each token's
`parent_token_hash` links to its predecessor's hash. Capabilities are
monotonically narrowing (each delegation only reduces scope, never widens).

### TokenValidator

Stateful validator that tracks seen nonces per epoch and verifies complete
chains.

## Invariants

- **INV-ABT-ATTENUATION**: Delegation never widens capabilities beyond parent scope.
- **INV-ABT-AUDIENCE**: Token audience must match executing service identity.
- **INV-ABT-EXPIRY**: Expired tokens are rejected regardless of chain validity.
- **INV-ABT-REPLAY**: Nonce uniqueness is enforced within an epoch.

## Event Codes

| Code          | Description                                                   |
|---------------|---------------------------------------------------------------|
| `ABT-001`     | Token issued (issuer, audience, capability_count, expiry)     |
| `ABT-002`     | Token delegated (delegator, new_audience, chain_depth)        |
| `ABT-003`     | Token verified (chain_depth, audience_match, duration_us)     |
| `ABT-004`     | Token rejected (reason, attempted_audience, chain_depth)      |

## Error Codes

| Code                           | Description                                    |
|--------------------------------|------------------------------------------------|
| `ERR_ABT_ATTENUATION_VIOLATION`| Delegation attempted to widen capabilities      |
| `ERR_ABT_AUDIENCE_MISMATCH`   | Audience does not match executing service        |
| `ERR_ABT_TOKEN_EXPIRED`       | Token has passed its expiry timestamp            |
| `ERR_ABT_REPLAY_DETECTED`     | Nonce was already used within current epoch      |

## Acceptance Criteria

1. `AudienceBoundToken` includes all required fields (token_id, issuer, audience,
   capabilities, issued_at, expires_at, nonce, parent_token_hash, signature,
   max_delegation_depth) with documented invariants.
2. Token delegation strictly attenuates: any attempt to delegate a wider capability
   set than the parent token grants is rejected with `ERR_ABT_ATTENUATION_VIOLATION`.
3. Audience mismatch is detected and rejected with `ERR_ABT_AUDIENCE_MISMATCH`
   before any control action executes.
4. Token chains of depth 10+ verify correctly with sub-millisecond verification
   time per chain link.
5. Expired tokens (past expiry timestamp) are rejected with `ERR_ABT_TOKEN_EXPIRED`
   regardless of chain validity.
6. Nonce uniqueness is enforced within an epoch -- replaying a token with the same
   nonce is rejected with `ERR_ABT_REPLAY_DETECTED`.
7. Verification evidence JSON includes chain depths tested, attenuation scenarios,
   and audience mismatch rejection counts.
8. Token chain of depth 1, 5, and 20 validated in unit tests.
9. Adversarial tests: forged parent_hash, widened capabilities in chain, cross-audience
   replay, expired intermediate tokens.

## Testing Requirements

- Unit tests for valid root token creation
- Valid single-hop and multi-hop delegation
- Audience escalation rejection
- Scope escalation rejection
- Depth limit exceeded
- Expired intermediate rejection
- Zero-validity rejection (issued_at >= expires_at)
- Audience mismatch rejection
- Nonce replay detection
- Chain integrity (forged parent_hash detection)

## Upstream Dependencies

- bd-2ms: Rollback/fork detection in control-plane state propagation
- bd-jjm: Canonical serializer (referenced for token serialization)

## Downstream Dependents

- bd-364: Key-role separation for control-plane signing/encryption/issuance
- bd-1jjq: Section-wide verification gate

## Artifacts

- `docs/specs/section_10_10/bd-1r2_contract.md` (this document)
- `docs/policy/audience_bound_tokens.md`
- `crates/franken-node/src/control_plane/audience_token.rs`
- `scripts/check_audience_tokens.py`
- `tests/test_check_audience_tokens.py`
- `artifacts/section_10_10/bd-1r2/verification_evidence.json`
- `artifacts/section_10_10/bd-1r2/verification_summary.md`
