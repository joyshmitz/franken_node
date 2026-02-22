# bd-1r2: Audience-Bound Token Chains for Control Actions

**Section:** 10.10 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 154 | 154 |
| Rust unit tests | 55 | 55 |
| Python unit tests | 49 | 49 |

## Implementation

**File:** `crates/franken-node/src/control_plane/audience_token.rs`

### Core Types
- `TokenId` -- unique token identifier (newtype String)
- `ActionScope` -- Migrate, Rollback, Promote, Revoke, Configure
- `AudienceBoundToken` -- 10-field token with hash chain, audience binding, capability allowlist
- `TokenError` -- structured error with code and message
- `TokenEvent` -- audit event with event_code, token_id, trace_id, epoch_id
- `TokenChain` -- ordered delegation chain with monotonic attenuation
- `TokenValidator` -- stateful validator with nonce replay detection per epoch

### Key API Methods
- `TokenChain::new()` -- create chain from root token
- `TokenChain::append()` -- add delegated token (enforces attenuation, depth, hash integrity)
- `TokenValidator::verify_chain()` -- full chain verification (expiry, replay, integrity, audience)
- `TokenValidator::advance_epoch()` -- reset nonces for new epoch

### Event Codes (4)
| Code | Description |
|------|-------------|
| ABT-001 | Token issued |
| ABT-002 | Token delegated |
| ABT-003 | Token chain verified |
| ABT-004 | Token rejected |

### Error Codes (4)
| Code | Description |
|------|-------------|
| ERR_ABT_ATTENUATION_VIOLATION | Delegation widened capabilities |
| ERR_ABT_AUDIENCE_MISMATCH | Audience does not match requester |
| ERR_ABT_TOKEN_EXPIRED | Token past expiry |
| ERR_ABT_REPLAY_DETECTED | Nonce reused within epoch |

### Invariants (4)
- **INV-ABT-ATTENUATION**: Delegation never widens capabilities beyond parent scope
- **INV-ABT-AUDIENCE**: Token audience must match executing service identity
- **INV-ABT-EXPIRY**: Expired tokens rejected regardless of chain validity
- **INV-ABT-REPLAY**: Nonce uniqueness enforced within an epoch

### Adversarial Coverage
- Forged parent_hash detection
- Scope escalation rejection
- Audience escalation rejection
- Cross-audience replay rejection
- Expired intermediate token rejection
- Delegation depth limit enforcement
- Chain depths tested: 1, 5, 20+

## Acceptance Criteria

| Criterion | Status |
|-----------|--------|
| AudienceBoundToken includes all 10 required fields | PASS |
| Delegation strictly attenuates capabilities | PASS |
| Audience mismatch detected and rejected | PASS |
| Chain depth 10+ verifies correctly | PASS |
| Expired tokens rejected regardless of chain validity | PASS |
| Nonce replay within epoch rejected | PASS |
| Chain depths 1, 5, 20 validated | PASS |
| Adversarial tests: forged hash, widened caps, cross-audience replay | PASS |

## Additional Quality Checks

- Serde (Serialize/Deserialize) derives present
- SHA-256 hash chain integrity
- Send + Sync trait assertions for thread safety
- `validate_token()` helper validates token object structure
