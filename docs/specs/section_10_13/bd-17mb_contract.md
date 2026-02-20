# bd-17mb: Fail-Closed Manifest Negotiation

## Bead: bd-17mb | Section: 10.13

## Purpose

Implements fail-closed manifest negotiation for connector activation.
A connector's manifest declares its SemVer version, required features,
and transport capabilities. The negotiation engine checks compatibility
against the host's supported version range, available features, and
transport caps. Any mismatch hard-fails activation (fail-closed).

## Invariants

| ID | Statement |
|----|-----------|
| INV-MANIFEST-SEMVER | Version checks use semantic comparison, never lexical string comparison. |
| INV-MANIFEST-FAIL-CLOSED | Any negotiation failure results in activation denial; partial matches are not accepted. |
| INV-MANIFEST-FEATURES | All required features must be available; a single missing feature fails negotiation. |
| INV-MANIFEST-TRANSPORT | Transport capability mismatch between connector and host fails negotiation. |

## Types

### ConnectorManifest
- `connector_id: String`
- `version: SemVer` — connector's declared version
- `required_features: Vec<String>` — features the connector needs
- `transport_caps: Vec<TransportCap>` — transport capabilities required

### SemVer
- `major: u32`, `minor: u32`, `patch: u32`
- Parsing from `"1.2.3"` strings
- Semantic ordering (major > minor > patch)

### HostCapabilities
- `supported_range: (SemVer, SemVer)` — min/max supported versions
- `available_features: Vec<String>` — features the host provides
- `transport_caps: Vec<TransportCap>` — transport capabilities available

### TransportCap
- Enum: `Http1`, `Http2`, `Http3`, `WebSocket`, `Grpc`

### NegotiationResult
- `connector_id: String`
- `outcome: Outcome` — `Accepted | Rejected`
- `version_ok: bool`
- `features_ok: bool`
- `transport_ok: bool`
- `missing_features: Vec<String>`
- `missing_transports: Vec<TransportCap>`
- `trace_id: String`
- `timestamp: String`

### Outcome
- `Accepted` — all checks pass
- `Rejected { reason: String }` — at least one check failed

## Functions

| Function | Signature | Behaviour |
|----------|-----------|-----------|
| `negotiate` | `(manifest, host_caps, trace_id, timestamp) -> NegotiationResult` | Runs all three checks; fail-closed on any mismatch. |
| `check_version` | `(version, range) -> bool` | Returns true if version is within the supported SemVer range (inclusive). |
| `check_features` | `(required, available) -> Vec<String>` | Returns list of missing features (empty = pass). |
| `check_transport` | `(required, available) -> Vec<TransportCap>` | Returns list of missing transport caps (empty = pass). |

## Error Codes

| Code | Trigger |
|------|---------|
| `MANIFEST_VERSION_UNSUPPORTED` | Connector version outside host's supported range. |
| `MANIFEST_FEATURE_MISSING` | One or more required features not available. |
| `MANIFEST_TRANSPORT_MISMATCH` | Required transport capability not supported. |
| `MANIFEST_INVALID` | Manifest cannot be parsed or is malformed. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-17mb_contract.md` |
| Conformance tests | `tests/conformance/manifest_negotiation_fail_closed.rs` |
| Negotiation trace | `artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json` |
| Verification evidence | `artifacts/section_10_13/bd-17mb/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-17mb/verification_summary.md` |
