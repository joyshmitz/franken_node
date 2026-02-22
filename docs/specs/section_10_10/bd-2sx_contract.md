# bd-2sx Contract: Revocation Freshness Gate for Risky Product Actions

**Bead:** bd-2sx
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Integrate canonical revocation freshness semantics that must be satisfied before
any risky product action can execute. Actions are classified into three safety
tiers -- Critical, Standard, and Advisory -- each with epoch-based freshness
thresholds. A signed `FreshnessProof` must accompany every gated action.
Graceful degradation ensures Tier-1 (Critical) actions fail-closed on stale
data, Tier-2 (Standard) actions allow owner-bypass, and Tier-3 (Advisory)
actions proceed with a warning.

This gate prevents the system from executing dangerous mutations (key rotation,
revocation list updates, policy deployments) against stale revocation data,
which could allow revoked credentials to be silently re-accepted.

## Dependencies

- **Upstream:** bd-1m8r (revocation freshness gate per safety tier)
- **Upstream:** bd-3cs3 (epoch-scoped key derivation for proof signatures)
- **Upstream:** bd-174 (policy checkpoint chain)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Structures

### SafetyTier

Classification for risky actions with epoch-based freshness thresholds:

| Variant   | Description                   | Max Staleness    |
|-----------|-------------------------------|------------------|
| Critical  | Fail-closed, no bypass        | 1 epoch          |
| Standard  | Owner-bypass allowed          | 5 epochs         |
| Advisory  | Proceed-with-warning          | 10 epochs        |

### FreshnessProof

Signed proof struct that accompanies every gated action:

| Field                | Type          | Description                                    |
|----------------------|---------------|------------------------------------------------|
| timestamp            | u64           | Unix timestamp when proof was created          |
| credentials_checked  | Vec<String>   | List of credential IDs verified                |
| nonce                | String        | Unique nonce for replay prevention             |
| signature            | String        | Hex-encoded HMAC signature of proof payload    |
| tier                 | SafetyTier    | Safety tier of the gated action                |
| epoch                | u64           | Control epoch when proof was generated         |

### RevocationFreshnessGate

The gate controller that validates freshness before risky actions:

| Method              | Signature                                                         | Description                                  |
|---------------------|-------------------------------------------------------------------|----------------------------------------------|
| check()             | (&self, proof: &FreshnessProof, current_epoch: u64) -> Result     | Validate proof freshness against tier policy |
| classify_action()   | (&self, action_id: &str) -> SafetyTier                           | Map an action to its safety tier             |
| verify_proof()      | (&self, proof: &FreshnessProof) -> Result                        | Verify proof signature and nonce uniqueness  |

### FreshnessError

Error enumeration for gate failures:

| Variant              | Description                                              |
|----------------------|----------------------------------------------------------|
| Stale                | Proof epoch too old for the action's tier                |
| ServiceUnreachable   | Cannot contact revocation service                        |
| ProofTampered        | Signature verification failed                            |
| ReplayDetected       | Nonce was previously consumed                            |
| Unauthenticated      | Session lacks authentication for gated action            |

## Invariants

- **INV-RFG-GATE:** All Tier-1 (Critical) actions must pass the freshness gate
  before execution. No bypass is possible for Critical-tier actions.
- **INV-RFG-PROOF:** FreshnessProof is unforgeable -- signature verification
  must reject any tampered payload.
- **INV-RFG-DEGRADE:** Graceful degradation: Critical actions fail-closed,
  Standard actions allow owner-bypass, Advisory actions proceed-with-warning.
- **INV-RFG-SESSION:** Freshness checks must occur within authenticated sessions.
  Unauthenticated callers receive FreshnessError::Unauthenticated.

## Event Codes

| Code    | Severity | Description                                              |
|---------|----------|----------------------------------------------------------|
| RFG-001 | INFO     | Freshness check passed -- action may proceed             |
| RFG-002 | ERROR    | Freshness check failed -- action blocked                 |
| RFG-003 | WARN     | Freshness degraded -- proceeding with warning or bypass  |
| RFG-004 | CRITICAL | Emergency bypass activated for Critical-tier action      |

## Error Codes

| Code                     | Description                                         |
|--------------------------|-----------------------------------------------------|
| ERR_RFG_STALE            | Proof epoch exceeds maximum staleness for tier      |
| ERR_RFG_SERVICE_DOWN     | Revocation service unreachable                      |
| ERR_RFG_TAMPERED         | Proof signature does not match payload              |
| ERR_RFG_REPLAY           | Nonce already consumed                              |
| ERR_RFG_UNAUTHENTICATED  | Session lacks required authentication               |

## Acceptance Criteria

1. `SafetyTier` enum with `Critical`, `Standard`, and `Advisory` variants, each
   with documented epoch-based freshness thresholds (1, 5, and 10 epochs
   respectively).
2. `FreshnessProof` struct with `timestamp`, `credentials_checked`, `nonce`,
   `signature`, `tier`, and `epoch` fields.
3. `RevocationFreshnessGate` struct implementing `check()`, `classify_action()`,
   and `verify_proof()` methods.
4. `FreshnessError` enum with `Stale`, `ServiceUnreachable`, `ProofTampered`,
   `ReplayDetected`, and `Unauthenticated` variants.
5. Graceful degradation: Critical fail-closed, Standard owner-bypass, Advisory
   proceed-with-warning.
6. Replay detection via consumed nonce set.
7. Signature verification on every FreshnessProof.
8. All four event codes (RFG-001 through RFG-004) emitted at correct severity.
9. All four invariants (INV-RFG-GATE, INV-RFG-PROOF, INV-RFG-DEGRADE,
   INV-RFG-SESSION) enforced.
10. >= 25 unit tests covering tier classification, proof verification, staleness
    rejection, replay detection, graceful degradation, and boundary conditions.

## Test Scenarios

### Scenario 1: Critical Action with Fresh Proof
- Action classified as Critical (tier threshold = 1 epoch)
- FreshnessProof.epoch = current_epoch
- Expected: RFG-001, action proceeds

### Scenario 2: Critical Action with Stale Proof
- Action classified as Critical
- FreshnessProof.epoch = current_epoch - 2
- Expected: RFG-002, FreshnessError::Stale, action blocked

### Scenario 3: Standard Action with Owner Bypass
- Action classified as Standard (tier threshold = 5 epochs)
- FreshnessProof.epoch = current_epoch - 6
- Owner bypass flag set
- Expected: RFG-003, action proceeds with warning

### Scenario 4: Advisory Action with Degraded Freshness
- Action classified as Advisory (tier threshold = 10 epochs)
- FreshnessProof.epoch = current_epoch - 11
- Expected: RFG-003, proceed-with-warning

### Scenario 5: Replay Detection
- Same nonce submitted twice
- Expected: RFG-002, FreshnessError::ReplayDetected

### Scenario 6: Tampered Proof
- Proof signature does not match payload
- Expected: RFG-002, FreshnessError::ProofTampered

### Scenario 7: Unauthenticated Session
- No session credentials provided
- Expected: RFG-002, FreshnessError::Unauthenticated

## Verification

- Script: `scripts/check_revocation_freshness.py --json`
- Evidence: `artifacts/section_10_10/bd-2sx/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-2sx/verification_summary.md`
