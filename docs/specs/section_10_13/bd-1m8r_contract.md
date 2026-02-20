# bd-1m8r: Revocation Freshness Gate per Safety Tier

## Bead: bd-1m8r | Section: 10.13

## Purpose

Enforces revocation freshness checks per safety tier before risky or
dangerous actions. Actions are classified into safety tiers (Standard,
Risky, Dangerous). Higher tiers require fresher revocation data. Stale
revocation data blocks the action unless an override is provided with
a policy-backed receipt.

## Invariants

| ID | Statement |
|----|-----------|
| INV-RF-TIER-GATE | Actions at Risky/Dangerous tiers are denied if revocation data is staler than the tier's max-age threshold. |
| INV-RF-OVERRIDE-RECEIPT | Override of a stale-frontier denial must produce a signed receipt with reason, actor, and timestamp. |
| INV-RF-STANDARD-PASS | Standard-tier actions always pass the freshness gate (no freshness requirement). |
| INV-RF-AUDIT | Every freshness gate evaluation produces an auditable decision record with trace correlation. |

## Types

### SafetyTier
- Enum: `Standard`, `Risky`, `Dangerous`

### FreshnessPolicy
- `risky_max_age_secs: u64` — max revocation age for Risky actions.
- `dangerous_max_age_secs: u64` — max revocation age for Dangerous actions.

### FreshnessCheck
- `action_id: String`
- `tier: SafetyTier`
- `revocation_age_secs: u64`
- `trace_id: String`
- `timestamp: String`

### OverrideReceipt
- `action_id: String`
- `actor: String`
- `reason: String`
- `timestamp: String`
- `trace_id: String`

### FreshnessDecision
- `action_id: String`
- `tier: SafetyTier`
- `allowed: bool`
- `revocation_age_secs: u64`
- `max_age_secs: Option<u64>`
- `override_receipt: Option<OverrideReceipt>`
- `reason: String`
- `trace_id: String`
- `timestamp: String`

### FreshnessError
- `StaleFrontier { tier, age_secs, max_age_secs }`
- `OverrideRequired { tier, age_secs }`
- `PolicyInvalid { reason }`

## Error Codes

| Code | Trigger |
|------|---------|
| `RF_STALE_FRONTIER` | Revocation data is staler than the tier's max-age threshold. |
| `RF_OVERRIDE_REQUIRED` | Action denied; override with receipt required to proceed. |
| `RF_POLICY_INVALID` | Freshness policy configuration is invalid. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-1m8r_contract.md` |
| Implementation | `crates/franken-node/src/security/revocation_freshness.rs` |
| Security tests | `tests/security/revocation_freshness_gate.rs` |
| Freshness decisions | `artifacts/section_10_13/bd-1m8r/revocation_freshness_decisions.json` |
| Verification evidence | `artifacts/section_10_13/bd-1m8r/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-1m8r/verification_summary.md` |
