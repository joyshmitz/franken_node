# Policy: Ecosystem Network-Effect APIs

**Bead:** bd-2aj | **Section:** 10.12 (Ecosystem Fabric + Network Effects)

## Purpose

This policy governs the operation of ecosystem network-effect APIs that serve
extension registry, reputation scoring, and compliance evidence publishing.
These APIs form the programmatic foundation for trust-verified ecosystem
participation.

## Publishing Flow

1. Extension publisher registers via RegistryAPI with signed metadata.
2. Registry validates publisher identity (Sybil resistance check).
3. On successful registration, an immutable audit log entry is created (ENE-001).
4. Publisher submits extensions with version lineage and compatibility metadata.
5. ReputationAPI computes initial reputation score from available evidence.
6. ComplianceEvidenceAPI accepts verification artifacts for content-addressed storage.

## Event Codes

| Code    | When Emitted                                              |
|---------|-----------------------------------------------------------|
| ENE-001 | REGISTRY_MUTATION -- extension registered or updated      |
| ENE-002 | REGISTRY_QUERY -- extension metadata queried              |
| ENE-003 | REPUTATION_COMPUTED -- reputation score computed          |
| ENE-004 | REPUTATION_ANOMALY -- anomaly detected in score change    |
| ENE-005 | COMPLIANCE_EVIDENCE_STORED -- evidence artifact stored    |
| ENE-006 | COMPLIANCE_EVIDENCE_RETRIEVED -- evidence artifact read   |
| ENE-007 | COMPLIANCE_TAMPER_CHECK_PASS -- tamper check passed       |
| ENE-008 | COMPLIANCE_TAMPER_CHECK_FAIL -- tamper check failed       |
| ENE-009 | API_AUTH_REJECT -- authentication rejected                |
| ENE-010 | API_RATE_LIMIT -- rate limit exceeded                     |
| ENE-011 | SYBIL_REJECT -- Sybil duplicate identity rejected         |

## Invariants

| ID               | Rule                                                       |
|------------------|------------------------------------------------------------|
| INV-ENE-REGISTRY | All registry mutations produce immutable audit log entries  |
| INV-ENE-DETERM   | Reputation scores are byte-identical given identical inputs |
| INV-ENE-TAMPER   | Content-addressed storage ensures tamper-evident retrieval  |
| INV-ENE-SYBIL    | Sybil resistance rejects duplicate publisher identities    |
| INV-ENE-ANOMALY  | Anomaly detection flags deltas > 2 standard deviations     |

## Reputation Tiers

| Tier          | Score Range | Privileges                                     |
|---------------|-------------|-------------------------------------------------|
| Untrusted     | 0 -- 19     | Read-only access; cannot publish extensions     |
| Provisional   | 20 -- 49    | Can publish with mandatory review               |
| Established   | 50 -- 79    | Standard publish; subject to spot checks        |
| Trusted       | 80 -- 100   | Full publish; eligible for fast-track review    |

## Governance

The ecosystem network-effect APIs are governed by the franken_node governance
board. Changes to scoring weights, tier thresholds, or anti-gaming parameters
require governance approval via the structured proposal process.

## Anti-Gaming Measures

Anti-Gaming protections safeguard reputation integrity:

1. **Sybil Resistance**: Publisher identity binding via cryptographic keys.
   Duplicate publisher identities are rejected at registration time.
2. **Rate-Limited Score Updates**: Score recomputation throttled to prevent
   burst gaming through rapid signal injection.
3. **Anomaly Detection**: Score changes exceeding 2 standard deviations from
   the rolling mean trigger REPUTATION_ANOMALY events and may freeze the score.
4. **Evidence Freshness**: Stale evidence (older than 90 days) receives
   diminishing weight in score calculations.

## Dispute Resolution

Publishers may file disputes against reputation score changes they believe
are erroneous. The dispute process follows these stages:

1. **Filing**: Publisher submits dispute with evidence references.
2. **Review**: Governance team reviews within 48 hours.
3. **Resolution**: Score adjusted or dispute rejected with explanation.
4. **Audit**: All dispute outcomes recorded in immutable audit trail.

## Appeal Process

If a dispute is rejected, the publisher may file an appeal:

1. Appeal must include new evidence not present in the original dispute.
2. Appeal is reviewed by a different governance panel member.
3. Appeal decisions are final and recorded in the audit trail.

## Upgrade Path

Publishers can improve their reputation tier by:
- Submitting verified provenance attestations
- Maintaining high compatibility pass rates
- Completing certification renewals on time
- Responding promptly to reported vulnerabilities

## Downgrade Triggers

Reputation may be downgraded when:
- Revocation events are issued against published artifacts
- Certification lapses are detected
- Quarantine events are triggered
- Anomaly detection identifies suspicious score manipulation
- Community reports accumulate negative signals

## Compliance Evidence Storage

Evidence artifacts are stored using content-addressed storage:
- Storage key = `sha256(canonical_json(artifact))`
- On retrieval, hash is recomputed and verified against the storage key
- Tamper-evident: any modification invalidates the content address
- All store/retrieve operations produce structured log events

## Cross-Program Integration

At least two frontier programs integrate with the ComplianceEvidenceAPI:
1. **Migration Singularity** (10.3/10.12): Publishes migration success evidence
2. **Trust Fabric** (10.4/10.13): Publishes trust artifact validity evidence
