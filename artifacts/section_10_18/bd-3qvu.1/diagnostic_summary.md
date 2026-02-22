# bd-3qvu.1 Diagnostics (Support Lane)

## Command

- `rch exec -- cargo check -p frankenengine-node --test vef_proof_service_support`
- Exit: `101`

## Failure groups

1. **Compile-context imports inside `proof_generator.rs` do not resolve in support harness context**
- `super::proof_scheduler`, `super::receipt_chain`
- `super::super::connector::vef_execution_receipt`
- `super::super::proof_scheduler`, `super::super::receipt_chain`

2. **Support harness expects symbols not exported by wrapper-visible proof_generator module**
- Conformance harness missing: `BackendDescriptor`, `GeneratedProof`, `JobId`, `JobStatus`, `PROOF_GEN_BACKEND_SELECTED`, `PROOF_GEN_JOB_FAILED`, `ProofGenError`, `ProofGenerationService`, `ReceiptWindow`
- Perf harness missing: `BackendDescriptor`, `GeneratedProof`, `JobId`, `JobStatus`, `PROOF_GEN_JOB_COMPLETED`, `ProofGenerationService`, `ReceiptWindow`

## Practical fix direction (non-overlapping with other lanes)

- Build wrapper-local module graph that mirrors expected `super`/`super::super` structure.
- Add wrapper-local aliases/exports only if tests intentionally target legacy names.
- Keep edits limited to `bd-3qvu` scope files.

## Machine-readable matrix

- `artifacts/section_10_18/bd-3qvu.1/diagnostic_matrix.json`
