# Policy: Revocation Freshness Gate

**Bead:** bd-2sx
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Last Updated:** 2026-02-20

## Risk Description

Risky product actions -- such as key rotation, credential revocation, policy
deployment, and trust graph mutations -- must not execute against stale
revocation data. If the system allows a Critical action to proceed when the
revocation list is outdated, revoked credentials may be silently re-accepted,
violating the no-ambient-authority invariant (8.5).

The Revocation Freshness Gate enforces that every risky action is accompanied by
a signed `FreshnessProof` attesting that revocation data was checked within the
action's tier-specific staleness window.

## Impact

**Critical.** Executing a key rotation with stale revocation data could re-enable
a compromised key. Executing a policy deployment without current revocation
status could grant access to revoked identities. The blast radius encompasses
the entire trust graph.

## Likelihood

**High.** Network partitions, service degradation, and clock skew regularly
cause revocation data to become stale. Without an explicit gate, the system has
no way to distinguish between fresh and stale revocation state.

## Safety Tier Classification

Actions are classified into three tiers with epoch-based freshness thresholds:

| Tier      | Max Staleness | Degradation Behavior     | Examples                                  |
|-----------|---------------|--------------------------|-------------------------------------------|
| Critical  | 1 epoch       | Fail-closed, no bypass   | Key rotation, trust anchor mutation       |
| Standard  | 5 epochs      | Owner-bypass allowed     | Policy deployment, connector activation   |
| Advisory  | 10 epochs     | Proceed-with-warning     | Telemetry config, read-only queries       |

### Tier Thresholds

- **Critical (1 epoch):** The most dangerous actions. If the revocation data is
  more than 1 epoch stale, the action is unconditionally blocked. No bypass is
  available. This ensures that key rotations and trust anchor mutations always
  operate on the freshest available revocation state.

- **Standard (5 epochs):** Important but bypassable actions. If the revocation
  data is more than 5 epochs stale, the action is blocked by default but an
  authenticated owner may issue a bypass with an audit receipt.

- **Advisory (10 epochs):** Low-risk actions that should still be monitored. If
  the revocation data is more than 10 epochs stale, the action proceeds but a
  warning event (RFG-003) is emitted for observability.

## Freshness Proof Requirements

Every gated action must be accompanied by a `FreshnessProof`:

1. **timestamp:** Unix timestamp when the proof was generated.
2. **credentials_checked:** List of credential IDs that were verified against
   the revocation list.
3. **nonce:** Unique value to prevent replay attacks. Each nonce may only be
   consumed once.
4. **signature:** HMAC-SHA256 signature over the concatenation of timestamp,
   credentials_checked, nonce, tier, and epoch fields. Uses epoch-scoped key
   derivation (bd-3cs3).
5. **tier:** The safety tier classification of the action.
6. **epoch:** The control epoch at which the proof was generated.

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

## Countermeasures

### Replay Prevention
Every `FreshnessProof` contains a unique nonce. The gate maintains a set of
consumed nonces. Any attempt to reuse a nonce results in
`FreshnessError::ReplayDetected` and event RFG-002.

### Signature Verification
The proof signature is verified using epoch-scoped key derivation (bd-3cs3).
A tampered proof produces `FreshnessError::ProofTampered` and event RFG-002.

### Staleness Detection
The gate compares `proof.epoch` against `current_epoch` using the tier-specific
threshold. If `current_epoch - proof.epoch > threshold`, the proof is stale.

### Graceful Degradation
- **Critical:** Fail-closed. No action proceeds without fresh proof.
- **Standard:** Owner-bypass. An authenticated owner may force the action
  through, producing event RFG-003 and an audit receipt.
- **Advisory:** Proceed-with-warning. The action proceeds but RFG-003 is
  emitted for observability.

## Escalation

When a Critical-tier action is blocked due to stale revocation data:

1. Event RFG-002 is emitted at ERROR severity.
2. The operator is notified within 60 seconds via the structured observability
   pipeline.
3. If the revocation service is unreachable (`FreshnessError::ServiceUnreachable`),
   the incident bundle retention system (bd-xyz) captures the full context.
4. Emergency bypass (RFG-004) requires two-person authorization and produces an
   immutable audit record.

## Evidence

Evidence for review is maintained in:
- `artifacts/section_10_10/bd-2sx/verification_evidence.json`
- `artifacts/section_10_10/bd-2sx/verification_summary.md`

All freshness decisions are logged with trace_id for audit trail reconstruction.

## Verification

- Script: `scripts/check_revocation_freshness.py --json`
- All checks must pass before the bead can be closed.
