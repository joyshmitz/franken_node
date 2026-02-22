# ATC Verifier Contract (bd-2zip)

**Section:** 10.19 (Adversarial Trust Commons)  
**Bead:** bd-2zip  
**Version:** v1

## Objective

Expose verifier-facing APIs and proof artifacts so an external verifier can confirm:

1. federation computation integrity,
2. published metric provenance,
3. determinism of verifier output,
4. validation without private raw participant data.

## Verifier API Surface

### ATC-VERIFIER-ENDPOINT-001

`GET /api/v1/atc/verifier/metrics/{metric_id}`

Returns published aggregate metric snapshot plus provenance metadata.

### ATC-VERIFIER-ENDPOINT-002

`POST /api/v1/atc/verifier/computations/{computation_id}/verify`

Accepts proof references and verifier parameters. Returns deterministic verification result digest.

### ATC-VERIFIER-ENDPOINT-003

`GET /api/v1/atc/verifier/computations/{computation_id}/proof-chain`

Returns hash-chained proof artifact metadata (artifact hash + parent hash + signature metadata).

### ATC-VERIFIER-ENDPOINT-004

`GET /api/v1/atc/verifier/reports/{computation_id}`

Returns canonical report payload used for third-party reproducibility checks.

## Determinism Contract

- Repeating verification against the same `(computation_id, proof_chain, metric_snapshot)` must produce byte-identical verifier digests.
- Canonical serialization uses sorted keys and UTF-8 JSON with compact separators.
- Any divergence emits `ATC-VERIFIER-ERR-DETERMINISM`.

## Privacy Contract

- Verifier APIs expose aggregated values and commitments only.
- Raw participant records are never required for external verification.
- Payloads include explicit `data_visibility = aggregate_only` markers.
- Any response that includes raw participant data must fail validation with `ATC-VERIFIER-ERR-PRIVACY`.

## Provenance Contract

Each metric report must include:

- metric identifier,
- computation identifier,
- dataset commitment hash,
- proof-chain root hash,
- verifier output digest,
- signing key identifier,
- signature over canonical payload.

## Event Codes

- `ATC-VERIFIER-001` verifier API evaluation started.
- `ATC-VERIFIER-002` metric provenance validated.
- `ATC-VERIFIER-003` proof-chain continuity validated.
- `ATC-VERIFIER-004` determinism check passed.
- `ATC-VERIFIER-005` privacy envelope validated.
- `ATC-VERIFIER-006` external verifier report emitted.
- `ATC-VERIFIER-ERR-SIGNATURE` signature mismatch.
- `ATC-VERIFIER-ERR-CHAIN` invalid proof-chain parent linkage.
- `ATC-VERIFIER-ERR-DETERMINISM` repeated run digest mismatch.
- `ATC-VERIFIER-ERR-PRIVACY` raw participant exposure detected.

## Minimum Security Requirements

- Signing key IDs are pinned to verifier policy.
- Hash algorithm is SHA-256 with `sha256:<hex>` prefix.
- Proof chain must be append-only; revocation uses a new terminal artifact (no history rewrite).

## External Verification Workflow

1. Retrieve canonical report from endpoint 004.
2. Validate report signature and canonical payload hash.
3. Validate proof chain continuity via endpoint 003.
4. Re-run verification via endpoint 002 and compare result digest.
5. Confirm no raw participant data fields are present.
6. Emit deterministic verifier decision (`pass` / `fail`) with trace ID.

## Compatibility and Versioning

- Base path is `/api/v1/atc/verifier/*`.
- Additive fields are allowed in minor revisions.
- Any semantic change to canonical payload or digest derivation requires `/api/v2`.
