# bd-3n58: Domain-Separated Interface-Hash Verification

## Bead: bd-3n58 | Section: 10.13

## Purpose

Adds domain-separated interface-hash verification for connector admission.
Domain separation ensures hash values derived in one context cannot collide
with those from another. Invalid hashes block admission (fail-closed).
Admission telemetry tracks rejection code distribution for diagnostics.

## Invariants

| ID | Statement |
|----|-----------|
| INV-HASH-DOMAIN-SEP | Hash derivation prepends domain tag to input before hashing, preventing cross-domain collisions. |
| INV-HASH-ADMISSION | Invalid hashes block admission; no partial or degraded admission is permitted. |
| INV-HASH-TELEMETRY | Every admission check (pass or fail) is recorded in telemetry with rejection code. |
| INV-HASH-DETERMINISTIC | Same domain + data always produces the same hash. |

## Types

### DomainTag
- `domain: String` — e.g. `"connector.v1"`, `"provider.v1"`

### InterfaceHash
- `domain: String` — domain tag used in derivation
- `hash_hex: String` — hex-encoded hash value
- `data_len: usize` — length of input data (for diagnostics)

### AdmissionCheck
- `connector_id: String`
- `domain: String`
- `admitted: bool`
- `rejection_code: Option<RejectionCode>`
- `trace_id: String`
- `timestamp: String`

### RejectionCode
- `HashMismatch` — computed hash does not match expected
- `DomainMismatch` — domain tag does not match expected
- `ExpiredHash` — hash has expired (TTL exceeded)
- `MalformedHash` — hash string cannot be parsed

### AdmissionTelemetry
- `total_checks: u64`
- `total_admitted: u64`
- `total_rejected: u64`
- `rejection_distribution: HashMap<RejectionCode, u64>`
- `checks: Vec<AdmissionCheck>`

## Functions

| Function | Signature | Behaviour |
|----------|-----------|-----------|
| `compute_hash` | `(domain, data) -> InterfaceHash` | Derives hash as `H(domain \|\| ":" \|\| data)`. |
| `verify_hash` | `(expected, domain, data) -> Result<(), RejectionCode>` | Recomputes and compares; returns rejection code on mismatch. |
| `admit` | `(telemetry, connector_id, expected_hash, domain, data, trace_id, ts) -> bool` | Full admission check; records telemetry. |

## Error Codes

| Code | Trigger |
|------|---------|
| `IFACE_HASH_MISMATCH` | Computed hash does not match expected value. |
| `IFACE_DOMAIN_MISMATCH` | Domain tag on hash does not match admission context. |
| `IFACE_HASH_EXPIRED` | Hash TTL has been exceeded. |
| `IFACE_HASH_MALFORMED` | Hash string is not valid hex or wrong length. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-3n58_contract.md` |
| Implementation | `crates/franken-node/src/security/interface_hash.rs` |
| Conformance tests | `tests/conformance/interface_hash_verification.rs` |
| Rejection metrics | `artifacts/section_10_13/bd-3n58/interface_hash_rejection_metrics.csv` |
| Verification evidence | `artifacts/section_10_13/bd-3n58/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-3n58/verification_summary.md` |
