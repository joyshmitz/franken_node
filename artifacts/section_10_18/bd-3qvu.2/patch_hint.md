Suggested patch location: `tests/perf/vef_proof_service_support_perf.rs` lines ~133-146.

Current pattern:
- `entry.detail.contains(ProofBackendId::HashAttestationV1.as_str())`
- `entry.detail.contains(ProofBackendId::DoubleHashAttestationV1.as_str())`

Recommended replacement:

```rust
entry.event_code == event_codes::VEF_PROOF_002_BACKEND_SELECTED
    && entry.detail
        == format!("backend={}", ProofBackendId::HashAttestationV1.as_str())
```

```rust
entry.event_code == event_codes::VEF_PROOF_002_BACKEND_SELECTED
    && entry.detail
        == format!("backend={}", ProofBackendId::DoubleHashAttestationV1.as_str())
```
