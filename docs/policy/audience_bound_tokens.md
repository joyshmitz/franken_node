# Audience-Bound Token Policy

**Bead:** bd-1r2
**Section:** 10.10 -- FCP-Inspired Hardening
**Effective:** 2026-02-20
**Owner:** CrimsonCrane

## Purpose

This policy governs the issuance, delegation, validation, and lifecycle of
audience-bound tokens used in control-plane actions within the franken_node
three-kernel architecture. Every control action must be authorized by a valid
audience-bound token chain that proves delegated authority from an authorized
root issuer.

## Scope

All control-plane operations including but not limited to:

- Migration triggers and migration epoch management
- Rollback operations
- Artifact promotion
- Credential or token revocation
- Zone reconfiguration and configuration parameter changes

## Token Issuance

1. Root tokens are issued by authorized issuers only.
2. Every token MUST specify a non-empty audience list.
3. Every token MUST have `issued_at < expires_at` (positive validity window).
4. Every token MUST include a unique nonce per epoch.
5. Every token MUST include a signature over the canonical preimage.

## Delegation Rules

1. Delegation MUST NOT widen capabilities: the delegated token's `capabilities`
   must be a subset of the parent token's capabilities.
2. Delegation MUST NOT escalate audience: the delegated token's audience must be
   a subset of the parent token's audience.
3. Delegation depth MUST NOT exceed the root token's `max_delegation_depth`.
4. Each delegation step MUST set `parent_token_hash` to the hash of the parent
   token.

## Validation

1. Before any control action executes, the dispatcher MUST verify that the
   token chain's terminal audience matches the executing service identity.
2. Every token in the chain MUST be checked for expiry at evaluation time.
3. Expired intermediate tokens invalidate the entire chain.
4. Nonce replay within the same epoch MUST be rejected.

## Invariants

- **INV-ABT-ATTENUATION**: Delegation never widens capabilities beyond parent scope.
- **INV-ABT-AUDIENCE**: Token audience must match executing service identity.
- **INV-ABT-EXPIRY**: Expired tokens are rejected regardless of chain validity.
- **INV-ABT-REPLAY**: Nonce uniqueness is enforced within an epoch.

## Event Codes

| Code      | Trigger                                   |
|-----------|-------------------------------------------|
| `ABT-001` | Token issued successfully                 |
| `ABT-002` | Token delegated to narrower scope         |
| `ABT-003` | Token chain verified successfully         |
| `ABT-004` | Token or chain rejected                   |

## Error Codes

| Code                            | Meaning                              |
|---------------------------------|--------------------------------------|
| `ERR_ABT_ATTENUATION_VIOLATION` | Attempted to widen capabilities      |
| `ERR_ABT_AUDIENCE_MISMATCH`    | Audience does not match requester    |
| `ERR_ABT_TOKEN_EXPIRED`        | Token past expiry timestamp          |
| `ERR_ABT_REPLAY_DETECTED`      | Nonce reused within epoch            |

## Action Scopes

The following action scopes are defined:

| Scope       | Description                          |
|-------------|--------------------------------------|
| `Migrate`   | Migration operations                 |
| `Rollback`  | Rollback to prior state              |
| `Promote`   | Artifact / trust level promotion     |
| `Revoke`    | Credential / token revocation        |
| `Configure` | Configuration parameter changes      |

## Governance

1. Changes to this policy require approval from the security governance board.
2. All token issuance and delegation events MUST be audit-logged.
3. Token lifetimes should be minimized; prefer short-lived tokens with
   delegation rather than long-lived root tokens.
4. Delegation depth limits should be set to the minimum necessary for the
   operational workflow.

## Appeal Process

If a token validation failure blocks a legitimate control action:

1. The operator MUST NOT bypass the token system.
2. A new root token MUST be issued through the standard issuance flow.
3. The rejected action and new issuance MUST be recorded in the audit log.
4. Persistent validation failures should trigger a security review.

## Upgrade Path

Token format versioning follows the canonical serializer (bd-jjm). When the
token schema evolves:

1. Old tokens remain valid until their expiry.
2. New tokens use the updated schema.
3. Validators MUST support both old and new formats during the transition
   window.

## Downgrade Triggers

The following events trigger token revocation or downgrade:

1. Key compromise detected for the issuer's signing key.
2. Audience service identity rotation.
3. Epoch boundary crossing (all tokens from prior epoch expire).
4. Manual operator revocation via the control plane.
