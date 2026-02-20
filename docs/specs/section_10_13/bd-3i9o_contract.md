# bd-3i9o: Provenance/Attestation Policy Gates

## Bead: bd-3i9o | Section: 10.13

## Purpose

Implements provenance and attestation policy gates for connector activation.
The policy engine enforces required attestation types, minimum build
assurance levels, and trusted builder constraints. Non-compliant artifacts
are blocked pre-activation.

## Invariants

| ID | Statement |
|----|-----------|
| INV-PROV-REQUIRED-ATTEST | All required attestation types must be present; missing types block activation. |
| INV-PROV-BUILD-ASSURANCE | Artifact build assurance level must meet or exceed the policy minimum. |
| INV-PROV-TRUSTED-BUILDER | Builder identity must be in the trusted builders set. |
| INV-PROV-GATE-LOGGED | Every gate decision (pass or block) is recorded with trace_id. |

## Types

### AttestationType
- Enum: `Slsa`, `Sigstore`, `InToto`, `Custom(String)`

### BuildAssurance
- Enum: `None(0)`, `Basic(1)`, `Verified(2)`, `Hardened(3)`
- Numeric levels for ordered comparison.

### ProvenancePolicy
- `required_attestations: Vec<AttestationType>`
- `min_build_assurance: BuildAssurance`
- `trusted_builders: Vec<String>`

### ArtifactProvenance
- `artifact_id: String`
- `connector_id: String`
- `attestations: Vec<AttestationType>`
- `build_assurance: BuildAssurance`
- `builder_id: String`

### GateDecision
- `artifact_id: String`
- `passed: bool`
- `missing_attestations: Vec<AttestationType>`
- `assurance_ok: bool`
- `builder_trusted: bool`
- `failure_reason: Option<GateFailure>`
- `trace_id: String`
- `timestamp: String`

### GateFailure
- `MissingAttestation { types: Vec<AttestationType> }`
- `InsufficientAssurance { have: BuildAssurance, need: BuildAssurance }`
- `UntrustedBuilder { builder_id: String }`
- `PolicyInvalid { reason: String }`

## Error Codes

| Code | Trigger |
|------|---------|
| `PROV_ATTEST_MISSING` | Required attestation type not present. |
| `PROV_ASSURANCE_LOW` | Build assurance below policy minimum. |
| `PROV_BUILDER_UNTRUSTED` | Builder not in trusted set. |
| `PROV_POLICY_INVALID` | Policy configuration is malformed. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-3i9o_contract.md` |
| Implementation | `crates/franken-node/src/supply_chain/provenance_gate.rs` |
| Security tests | `tests/security/attestation_gate.rs` |
| Gate decisions | `artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json` |
| Verification evidence | `artifacts/section_10_13/bd-3i9o/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-3i9o/verification_summary.md` |
