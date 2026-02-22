# bd-2aj: Ecosystem Network-Effect APIs

**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane

## Overview

This contract defines the API surface for ecosystem-level network effects:
extension registry, reputation scoring, and compliance evidence publishing.
These three pillars create programmatic foundations that external ecosystem
participants consume, compounding adoption through trust-verified participation.

## Scope

1. **RegistryAPI** -- extension registration with signed metadata, version lineage
   queries, compatibility matrix lookups, and deprecation/revocation notifications.
   All mutations produce immutable audit log entries.

2. **ReputationAPI** -- deterministic reputation scores for extension publishers
   computed from four input dimensions:
   - Compatibility pass rate (from 10.2)
   - Migration success rate (from 10.3/10.12)
   - Trust artifact validity (from 10.4/10.13)
   - Verifier audit frequency (from 10.7/10.12)

3. **ComplianceEvidenceAPI** -- accepts, stores, indexes, and serves compliance
   evidence artifacts (verification_evidence.json blobs, signed attestations,
   audit reports) with content-addressed storage (SHA-256) and tamper-evident
   retrieval.

## Event Codes

| Code    | Description                                           |
|---------|-------------------------------------------------------|
| ENE-001 | REGISTRY_MUTATION -- extension registered/updated     |
| ENE-002 | REGISTRY_QUERY -- extension queried                   |
| ENE-003 | REPUTATION_COMPUTED -- reputation score computed      |
| ENE-004 | REPUTATION_ANOMALY -- anomaly detected in score delta |
| ENE-005 | COMPLIANCE_EVIDENCE_STORED -- evidence artifact stored|
| ENE-006 | COMPLIANCE_EVIDENCE_RETRIEVED -- evidence retrieved   |
| ENE-007 | COMPLIANCE_TAMPER_CHECK_PASS -- tamper check passed   |
| ENE-008 | COMPLIANCE_TAMPER_CHECK_FAIL -- tamper check failed   |
| ENE-009 | API_AUTH_REJECT -- authentication rejected            |
| ENE-010 | API_RATE_LIMIT -- rate limit exceeded                 |
| ENE-011 | SYBIL_REJECT -- Sybil resistance rejected duplicate   |

## Invariants

| ID               | Description                                                   |
|------------------|---------------------------------------------------------------|
| INV-ENE-REGISTRY | All registry mutations produce immutable audit log entries     |
| INV-ENE-DETERM   | Reputation scores are byte-identical given identical inputs    |
| INV-ENE-TAMPER   | Content-addressed storage ensures tamper-evident retrieval     |
| INV-ENE-SYBIL    | Sybil resistance rejects duplicate publisher identities        |
| INV-ENE-ANOMALY  | Anomaly detection flags score changes > 2 std deviations       |

## Error Codes

| Code                       | Description                                         |
|----------------------------|-----------------------------------------------------|
| ERR-ENE-DUPLICATE-REG      | Duplicate extension registration attempt             |
| ERR-ENE-NOT-FOUND          | Extension or publisher not found                     |
| ERR-ENE-REVOKED            | Extension has been revoked                           |
| ERR-ENE-SYBIL              | Sybil resistance rejected duplicate publisher        |
| ERR-ENE-TAMPER             | Tamper evidence check failed on retrieval            |
| ERR-ENE-RATE-LIMIT         | Rate limit exceeded                                  |
| ERR-ENE-AUTH               | Authentication/authorization failure                 |

## Anti-Gaming Protections

Anti-Gaming measures protect reputation integrity:
- **Sybil Resistance**: Publisher identity binding via signed keys; duplicate
  publisher identities are rejected at registration time.
- **Rate-Limited Score Updates**: Score recomputation is throttled to prevent
  burst gaming of signal injection.
- **Anomaly Detection**: Score changes exceeding 2 standard deviations from
  the rolling mean are flagged and may trigger investigation.
- **Dispute/Appeal Mechanism**: Publishers can dispute anomalous score changes
  through a structured appeal process.

## Compliance Evidence Format

Evidence artifacts use content-addressed storage with SHA-256 keying:
- Store: compute `sha256(canonical_content)`, use as storage key.
- Retrieve: recompute hash on read and verify against stored key.
- Format: JSON-LD signed attestation envelopes containing
  verification_evidence.json blobs.

## Reputation Scoring

Reputation Scoring uses four weighted dimensions:

| Dimension                 | Weight | Source           |
|---------------------------|--------|------------------|
| Compatibility pass rate   | 0.30   | Section 10.2     |
| Migration success rate    | 0.25   | Section 10.3     |
| Trust artifact validity   | 0.25   | Section 10.4/13  |
| Verifier audit frequency  | 0.20   | Section 10.7/12  |

Final score = weighted sum, clamped to [0.0, 100.0].
Determinism: `deterministic_reputation_score(inputs)` is a pure function.

## API Schema

### RegistryAPI Endpoints

- `POST /api/v1/registry/extensions` -- Register extension
- `GET  /api/v1/registry/extensions/{id}` -- Get extension
- `GET  /api/v1/registry/extensions/{id}/lineage` -- Version lineage
- `GET  /api/v1/registry/extensions/{id}/compat` -- Compatibility matrix
- `POST /api/v1/registry/extensions/{id}/deprecate` -- Deprecate
- `POST /api/v1/registry/extensions/{id}/revoke` -- Revoke
- `GET  /api/v1/registry/audit` -- Audit log

### ReputationAPI Endpoints

- `GET  /api/v1/reputation/{publisher_id}` -- Get reputation
- `POST /api/v1/reputation/{publisher_id}/compute` -- Recompute score
- `GET  /api/v1/reputation/{publisher_id}/history` -- Score history
- `POST /api/v1/reputation/dispute` -- File dispute

### ComplianceEvidenceAPI Endpoints

- `POST /api/v1/compliance/evidence` -- Submit evidence
- `GET  /api/v1/compliance/evidence/{hash}` -- Retrieve evidence
- `GET  /api/v1/compliance/evidence/{hash}/verify` -- Verify tamper evidence
- `GET  /api/v1/compliance/index` -- Search evidence index

### Authentication

All endpoints require mTLS + API key authentication.

### Rate Limiting

Read operations: 1000 req/min per client.
Write operations: 100 req/min per client.

### Pagination

All list endpoints support `?page=N&per_page=M` (default: page=1, per_page=50).

## Replay Capsule

Replay Capsule support enables external reproducibility: an independent verifier
can query the RegistryAPI and ComplianceEvidenceAPI to independently verify any
reputation score by re-computing from the same evidence inputs.

## Dispute Resolution

Publishers may file a Dispute against anomalous reputation score changes.
Disputes are reviewed within 48 hours, and outcomes are recorded in the
audit trail. Appeal Process is available for rejected disputes, escalating
to the governance board.

## Acceptance Criteria

1. RegistryAPI supports extension registration, version lineage queries,
   compatibility matrix lookups, and deprecation notifications, with all
   mutations producing immutable audit log entries.
2. ReputationAPI computes deterministic reputation scores from at least four
   input dimensions; given identical inputs, the score is byte-identical.
3. ComplianceEvidenceAPI stores and retrieves evidence artifacts using
   content-addressed storage (SHA-256 keyed); retrieval includes
   tamper-evidence verification.
4. Anti-gaming protections active: Sybil resistance rejects duplicates;
   anomaly detection flags score changes exceeding 2 std deviations.
5. Python SDK wrapper exercises all three API surfaces with >= 95% coverage.
6. At least two frontier programs emit compliance evidence through the API.
7. API latency for read operations < 50ms p99 for 1,000 extensions.
8. Verification evidence records endpoint coverage, determinism check,
   tamper-evidence check, and anti-gaming test results.
