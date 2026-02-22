# bd-2aj API Schema: Ecosystem Network-Effect APIs

**Section:** 10.12  
**Bead:** bd-2aj  
**Version:** v1

## Purpose

This document defines the wire-level API contract for the three ecosystem
network-effect pillars:

1. Registry API
2. Reputation API
3. Compliance Evidence API

The schema is versioned and supports deterministic, auditable integrations for
frontier programs and external ecosystem clients.

## Common Protocol Rules

### Versioning

- Base path: `/api/v1`
- Backwards-incompatible changes require `/api/v2` (or higher).
- New optional response fields are allowed in minor revisions.

### Authentication

- Mutation endpoints require mTLS client auth plus `X-API-Key`.
- Read endpoints require at least `X-API-Key`.
- Unauthorized requests must emit `ENE-009 (API_AUTH_REJECT)`.

### Rate Limiting

- Read endpoints: 1000 requests/min/client.
- Mutation endpoints: 100 requests/min/client.
- Rejections emit `ENE-010 (API_RATE_LIMIT)` and HTTP `429`.

### Pagination

List/index endpoints support:

- `page` (default `1`, minimum `1`)
- `per_page` (default `50`, maximum `200`)

Response envelope:

```json
{
  "items": [],
  "page": 1,
  "per_page": 50,
  "total_items": 0,
  "total_pages": 0
}
```

### Trace Correlation

All mutation endpoints accept `X-Trace-Id` and include it in event logs.

## Registry API

### POST `/api/v1/registry/extensions`

Register extension metadata.

Request body:

```json
{
  "extension_id": "ext-auth-guard",
  "publisher_id": "pub-acme",
  "publisher_key": "pubkey-acme-001",
  "name": "Auth Guard",
  "description": "Credential hardening extension",
  "version": "1.0.0",
  "signature": "sig-base64",
  "tags": ["auth", "security"]
}
```

Response: `201` with registered record.

### GET `/api/v1/registry/extensions/{extension_id}`

Read extension metadata and status.

### GET `/api/v1/registry/extensions/{extension_id}/lineage`

Return deterministic version lineage entries.

### GET `/api/v1/registry/extensions/{extension_id}/compat`

Return compatibility matrix entries.

### POST `/api/v1/registry/extensions/{extension_id}/deprecate`

Deprecate extension and emit immutable audit log entry (`ENE-001`).

### POST `/api/v1/registry/extensions/{extension_id}/revoke`

Revoke extension with reason and emit immutable audit log entry (`ENE-001`).

Request body:

```json
{
  "reason": "supply-chain compromise suspected"
}
```

### GET `/api/v1/registry/audit`

Read append-only audit trail with hash-chain fields:

- `sequence`
- `prev_hash`
- `entry_hash`

## Reputation API

### GET `/api/v1/reputation/{publisher_id}`

Return publisher reputation snapshot.

### POST `/api/v1/reputation/{publisher_id}/compute`

Compute deterministic score from four dimensions:

- `compatibility_pass_rate`
- `migration_success_rate`
- `trust_artifact_validity`
- `verifier_audit_frequency`

Request body:

```json
{
  "compatibility_pass_rate": 0.95,
  "migration_success_rate": 0.92,
  "trust_artifact_validity": 0.98,
  "verifier_audit_frequency": 0.74
}
```

Response: `200` with computed score and deltas.

### GET `/api/v1/reputation/{publisher_id}/history`

Return score history for reproducibility and anomaly analysis.

### POST `/api/v1/reputation/dispute`

File dispute/appeal record for anomalous score changes.

Request body:

```json
{
  "dispute_id": "disp-001",
  "publisher_id": "pub-acme",
  "reason": "unexpected migration signal spike",
  "old_score": 61.2,
  "new_score": 49.7
}
```

## Compliance Evidence API

### POST `/api/v1/compliance/evidence`

Submit evidence artifact for content-addressed storage.

Request body:

```json
{
  "publisher_id": "pub-acme",
  "source": "migration_singularity",
  "title": "Migration Verification Evidence",
  "content": "{\"verification\": \"pass\"}",
  "attestation": "signed-attestation",
  "tags": ["migration", "10.12"]
}
```

Response fields include computed `content_hash`.

### GET `/api/v1/compliance/evidence/{content_hash}`

Retrieve evidence and perform tamper-evident verification.

### GET `/api/v1/compliance/evidence/{content_hash}/verify`

Run explicit tamper-evidence check and return pass/fail.

### GET `/api/v1/compliance/index`

Search index by optional filters:

- `source`
- `publisher_id`
- `tag`

Supports pagination envelope.

## Error Contract

Stable error codes include:

- `ERR-ENE-DUPLICATE-REG`
- `ERR-ENE-NOT-FOUND`
- `ERR-ENE-REVOKED`
- `ERR-ENE-SYBIL`
- `ERR-ENE-TAMPER`
- `ERR-ENE-RATE-LIMIT`
- `ERR-ENE-AUTH`

## Determinism and Auditability

- Registry mutations are append-only and hash-linked.
- Reputation scoring is pure/deterministic for identical inputs.
- Compliance evidence retrieval verifies hash integrity on every read.
- API events map to `ENE-001` through `ENE-011`.
