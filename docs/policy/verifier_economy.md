# Verifier Economy Policy

**Bead:** bd-m8p | **Section:** 10.9

## Purpose

This policy governs the verifier economy portal and external attestation
publishing flow. It defines who can participate as a verifier, how attestations
are submitted and published, how reputation is scored, and how disputes are
resolved.

## Verifier Registration Policy

### Eligibility

Any organization or individual may register as a verifier. Registration is
self-service for the `basic` tier; the `advanced` tier requires manual vetting
by the trust plane operator.

### Required Credentials

- Unique organization or individual identity
- Contact information (email, organization URL)
- Ed25519 public key for attestation signing
- Declaration of verification capabilities (which dimensions the verifier
  can assess)

### Key Management

- Verifiers are responsible for their private key security.
- Key rotation is supported: a new public key can be registered with a
  transition period during which both old and new keys are accepted.
- Compromised keys must be reported immediately; all attestations signed
  with the compromised key are flagged for re-verification.

## Attestation Format

### JSON-LD Structure

All attestations use the `https://frankennode.dev/attestation/v1` context.
Required fields:

- `attestation_id`: Unique identifier (format: `att-<uuid>`)
- `verifier_id`: Registered verifier identifier
- `claim`: Object containing `dimension`, `statement`, and `score`
- `evidence`: Object containing `suite_id`, `measurements`, `execution_trace_hash`, and `environment`
- `signature`: Object containing `algorithm`, `public_key`, and `value`
- `timestamp`: ISO 8601 timestamp
- `immutable`: Boolean, always `true` for published attestations

### Signature Requirements

- Algorithm: Ed25519
- Payload: Canonical JSON serialization of the attestation (excluding the signature field)
- Verification: Signature must be valid against the verifier's registered public key

## Publishing Flow

### Stages

1. **Submission**: Verifier submits signed attestation via API
2. **Review**: Automated validation of structure, signature, and consistency
3. **Publish**: Attestation is published and becomes immutable
4. **Consume**: Public access via scoreboard and API

No stage may be skipped. A submission that fails review emits VEP-008 and is
not published.

### Immutability

Once published, attestations cannot be modified or deleted. Disputed
attestations are annotated with dispute metadata but the original attestation
remains intact.

## Reputation Scoring

### Dimensions and Weights

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Consistency | 0.35 | Agreement with other verifiers on overlapping claims |
| Coverage | 0.25 | Breadth of verification dimensions covered |
| Accuracy | 0.30 | Agreement with reference results and replay capsule verification |
| Longevity | 0.10 | Duration of active participation |

Weights sum to 1.00. Weight changes require governance RFC.

### Reputation Tiers

| Tier | Score Range | Privileges |
|------|------------|------------|
| Novice | 0-24 | Basic submission, limited visibility on scoreboard |
| Active | 25-49 | Standard submission, visible on scoreboard |
| Established | 50-74 | Priority in dispute resolution, advanced toolkit access |
| Trusted | 75-100 | Attestations carry higher weight in aggregate scores |

### Determinism

Reputation scoring is deterministic: the same set of inputs (attestation
history, cross-verifier agreement, reference results) always produces the
same reputation score. This is enforced by INV-VEP-REPUTATION.

## Incentive Model

### Verifier Rewards

- Reputation points accumulate with each valid attestation.
- Higher reputation tiers unlock access to advanced verification toolkits
  and priority in dispute resolution.
- Consistent, accurate verifiers are highlighted on the public scoreboard.

### Penalties

- Attestations that fail consistency checks reduce reputation.
- Anti-gaming triggers result in reputation penalties.
- Severe violations (fabrication, sybil attacks) result in verifier suspension.

## Dispute Resolution

### Filing a Dispute

Any registered verifier or the trust plane operator may file a dispute
against a published attestation. Disputes must include:

- The disputed attestation ID
- A written justification
- Supporting evidence (e.g., independent verification results)

### Resolution Process

1. Dispute filed (VEP-003 emitted)
2. Both parties notified
3. Independent re-verification using replay capsule (if available)
4. Trust plane operator makes final determination
5. Outcome recorded; reputation updated for both parties (VEP-004 emitted)

### Dispute Outcomes

| Outcome | Effect |
|---------|--------|
| Upheld | Attestation annotated as disputed; verifier reputation decreased |
| Rejected | Dispute dismissed; disputing party reputation unaffected |
| Inconclusive | No reputation change; attestation annotated for future review |

## Anti-Gaming Measures

### Sybil Resistance

- Rate limiting on verifier registration (max 5 registrations per IP per day)
- Identity verification for advanced tier
- Cross-verifier correlation analysis to detect coordinated submissions

### Selective Reporting Detection

- Verifiers must submit results for complete verification suites
- Statistical completeness checks flag verifiers who consistently omit
  unfavorable results
- Incomplete submissions are rejected with ERR-VEP-INCOMPLETE-PAYLOAD

### Anomaly Detection

- Statistical outlier detection across verifier submissions
- Submissions that deviate significantly from reference results or peer
  verifiers are flagged for review
- VEP-006 emitted when anti-gaming measure is triggered

## Event Codes

| Code | Trigger |
|------|---------|
| VEP-001 | Attestation submitted by verifier |
| VEP-002 | Attestation published (passed review) |
| VEP-003 | Dispute filed against an attestation |
| VEP-004 | Verifier reputation updated |
| VEP-005 | Verifier registered |
| VEP-006 | Anti-gaming measure triggered |
| VEP-007 | Replay capsule accessed |
| VEP-008 | Attestation rejected (failed review) |

## Invariants

| ID | Statement |
|----|-----------|
| INV-VEP-ATTESTATION | Every published attestation is immutable and includes full provenance metadata |
| INV-VEP-SIGNATURE | Every attestation payload is cryptographically signed and signature is verified before publishing |
| INV-VEP-REPUTATION | Verifier reputation is deterministic: same inputs always produce the same score |
| INV-VEP-PUBLISH | Attestation publishing flow is: submit -> review -> publish; no stage can be skipped |

## Governance

- This policy is owned by the trust plane (PP-03) operator.
- Changes to reputation weights require governance RFC and a 7-day review period.
- Changes to anti-gaming thresholds require trust plane operator approval.
- Verifier suspension decisions require documented justification and are
  subject to appeal.

### Appeal Process

Suspended verifiers may appeal by submitting a written justification to the
trust plane operator. Appeals are reviewed within 14 calendar days. The
operator's decision is final but must be documented with rationale.

## Upgrade Path

Verifiers advance tiers automatically when their reputation score crosses
the tier threshold. Tier upgrades are immediate and emit VEP-004.

## Downgrade Triggers

Verifier reputation decreases and tier downgrades occur when:
- Attestations fail consistency cross-checks
- Anti-gaming measures are triggered
- Disputes are upheld against the verifier's attestations
- Verifier is inactive for more than 90 days (longevity decay)

Tier downgrades emit VEP-004 with the previous and new tier in the event
payload.
