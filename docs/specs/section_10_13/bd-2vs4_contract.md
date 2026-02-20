# bd-2vs4: Deterministic Lease Coordinator Selection and Quorum Verification

## Bead: bd-2vs4 | Section: 10.13

## Purpose

Implements deterministic lease coordinator selection (same inputs always
select the same coordinator) and quorum signature verification with
safety-tier-dependent thresholds. Verification failures are classified
by type.

## Invariants

| ID | Statement |
|----|-----------|
| INV-LC-DETERMINISTIC | Coordinator selection is deterministic: identical inputs produce the same coordinator. |
| INV-LC-QUORUM-TIER | Quorum requirements vary by safety tier; higher tiers require more signers. |
| INV-LC-VERIFY-CLASSIFIED | Verification failures are classified (BelowQuorum, InvalidSignature, UnknownSigner). |
| INV-LC-REPLAY | Selection and verification produce identical results on replay with same inputs. |

## Types

### CoordinatorCandidate
- `node_id: String`
- `weight: u64` — selection weight/priority.

### CoordinatorSelection
- `candidates: Vec<CoordinatorCandidate>`
- `lease_id: String`
- `selected: String` — deterministically chosen node_id.
- `trace_id: String`

### QuorumConfig
- `standard_threshold: u32`
- `risky_threshold: u32`
- `dangerous_threshold: u32`

### QuorumSignature
- `signer_id: String`
- `signature: String`

### QuorumVerification
- `lease_id: String`
- `tier: String`
- `required: u32`
- `received: u32`
- `passed: bool`
- `failures: Vec<VerificationFailure>`
- `trace_id: String`
- `timestamp: String`

### VerificationFailure
- `BelowQuorum { required, received }`
- `InvalidSignature { signer_id }`
- `UnknownSigner { signer_id }`

### LeaseCoordinatorService
- Methods: `select_coordinator`, `verify_quorum`.
- Deterministic selection via weighted hash.

## Error Codes

| Code | Trigger |
|------|---------|
| `LC_BELOW_QUORUM` | Not enough valid signatures to meet tier threshold. |
| `LC_INVALID_SIGNATURE` | A signature failed verification. |
| `LC_UNKNOWN_SIGNER` | Signer is not in the known signer set. |
| `LC_NO_CANDIDATES` | No coordinator candidates available. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-2vs4_contract.md` |
| Implementation | `crates/franken-node/src/connector/lease_coordinator.rs` |
| Conformance tests | `tests/conformance/lease_coordinator_selection.rs` |
| Quorum vectors | `artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json` |
| Verification evidence | `artifacts/section_10_13/bd-2vs4/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-2vs4/verification_summary.md` |
