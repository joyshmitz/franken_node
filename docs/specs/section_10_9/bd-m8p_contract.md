# bd-m8p: Verifier Economy Portal and External Attestation Publishing Flow

## Scope

Build the verifier economy portal and external attestation publishing flow for
franken_node. This creates a marketplace where external verifiers register,
submit verification results, and publish cryptographic attestations that form a
trust network extending beyond the core team.

## Components

### Verifier Portal

| Component | Description |
|-----------|-------------|
| Registration | External verifiers register with identity, capabilities, and public key |
| Toolkit Access | Download verification SDK, replay capsules, benchmark datasets |
| Result Submission | Structured API for submitting verification results |
| Trust Scoreboard | Public-facing aggregate trust scores and attestation details |

### Attestation Publishing Flow

| Stage | Description |
|-------|-------------|
| Submission | Verifier submits signed verification result via API |
| Review | System validates payload structure, signature, and consistency |
| Publish | Verified claims are published as immutable attestations |
| Consume | Public consumers query attestations via scoreboard API |

### Attestation Format

Attestations use JSON-LD with cryptographic signatures:

```json
{
  "@context": "https://frankennode.dev/attestation/v1",
  "@type": "VerificationAttestation",
  "attestation_id": "att-<uuid>",
  "verifier_id": "ver-<uuid>",
  "claim": {
    "dimension": "compatibility",
    "statement": "...",
    "score": 0.95
  },
  "evidence": {
    "suite_id": "suite-compat-v1",
    "measurements": [],
    "execution_trace_hash": "sha256:...",
    "environment": {}
  },
  "signature": {
    "algorithm": "ed25519",
    "public_key": "...",
    "value": "..."
  },
  "timestamp": "2026-02-20T12:00:00Z",
  "immutable": true
}
```

### Verifier Registration

Verifier registration requires:
- **Identity**: Organization name, contact, unique verifier ID
- **Capabilities**: List of verification dimensions (e.g., compatibility, security, performance)
- **Public Key**: Ed25519 public key for attestation signing
- **Tier**: `basic` (no approval gate) or `advanced` (requires vetting)

### Incentive Model

| Mechanism | Description |
|-----------|-------------|
| Verifier Rewards | Reputation points for consistent, accurate attestations |
| Reputation Scoring | Weighted score based on consistency, coverage, and accuracy |
| Dispute Resolution | Process for challenging attestations with evidence |

### Reputation Scoring

Verifier reputation is computed from:
- **Consistency**: Cross-check agreement with other verifiers (weight: 0.35)
- **Coverage**: Breadth of verification dimensions covered (weight: 0.25)
- **Accuracy**: Agreement with reference results (weight: 0.30)
- **Longevity**: Duration of active participation (weight: 0.10)

Score range: 0-100 basis points. Tiers: Novice (0-24), Active (25-49),
Established (50-74), Trusted (75-100).

### Anti-Gaming Measures

| Measure | Description |
|---------|-------------|
| Sybil Resistance | Rate limiting, identity verification, cross-verifier correlation |
| Selective Reporting | Statistical completeness checks, mandatory suite coverage |
| Result Fabrication | Execution environment attestation, replay capsule verification |
| Anomaly Detection | Statistical outlier detection across verifier submissions |

### Replay Capsule Access

Replay capsules are deterministic execution recordings:
- Input state snapshot
- Execution trace
- Output state
- Expected result
- Cryptographic integrity hash (SHA-256)

Capsules allow anyone to independently verify a specific claim.

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

## Error Codes

| Code | Condition |
|------|-----------|
| ERR-VEP-INVALID-SIGNATURE | Attestation signature verification failed |
| ERR-VEP-DUPLICATE-SUBMISSION | Duplicate attestation submission detected |
| ERR-VEP-UNREGISTERED-VERIFIER | Submission from unregistered verifier |
| ERR-VEP-INCOMPLETE-PAYLOAD | Required attestation fields missing |
| ERR-VEP-ANTI-GAMING | Anti-gaming measure triggered, submission rejected |

## Acceptance Criteria

1. Verifier registration flow works end-to-end: register, receive credentials,
   download toolkit, submit results, see attestation published.
2. Verification toolkit download includes SDK reference, replay capsules,
   benchmark datasets, and reference results with integrity hashes.
3. Result submission API validates payload structure, cryptographic signature,
   and basic consistency before accepting submissions.
4. Published attestations are immutable, cryptographically signed, and include
   full provenance metadata.
5. Public trust scoreboard displays aggregate scores, individual attestations,
   and historical trends; data is queryable via API.
6. Replay capsules can be independently executed and produce results matching
   the published attestation.
7. At least two anti-gaming measures are implemented and tested (sybil
   resistance and selective reporting detection).
8. Portal API has structured JSON responses throughout; a verification script
   validates all API endpoints.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_9/bd-m8p_contract.md` |
| Policy document | `docs/policy/verifier_economy.md` |
| Rust implementation | `crates/franken-node/src/verifier_economy/mod.rs` |
| Verification script | `scripts/check_verifier_economy.py` |
| Python unit tests | `tests/test_check_verifier_economy.py` |
| Verification evidence | `artifacts/section_10_9/bd-m8p/verification_evidence.json` |
| Verification summary | `artifacts/section_10_9/bd-m8p/verification_summary.md` |
