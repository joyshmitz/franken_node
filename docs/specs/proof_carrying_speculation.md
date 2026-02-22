# Proof-Carrying Speculation Contract (bd-1nl1)

## Scope

This contract governs speculative execution for extension-host hot paths in
`franken_node`. Speculation may only activate when a valid proof receipt exists,
all guard predicates pass, and the requested activation surface is explicitly
approved.

## Core Invariants

- `INV-SPEC-PROOF-REQUIRED`: speculative transforms cannot activate without a proof receipt.
- `INV-SPEC-APPROVED-INTERFACE-ONLY`: activation is limited to approved `franken_engine` interfaces.
- `INV-SPEC-FAIL-CLOSED-TO-BASELINE`: any proof/guard failure degrades to deterministic safe baseline.
- `INV-SPEC-DETERMINISTIC-BASELINE`: baseline output is deterministic for a fixed input.

## Activation Rules

1. Interface allowlist must contain the requested interface id.
2. Receipt must be present and must match requested transform.
3. Receipt expiry must be in the future.
4. Receipt signer must be trusted and signature must verify.
5. Runtime guard predicate must pass.

If any rule fails, activation is denied and execution continues in safe baseline mode.

## Proof Receipt Schema

Required fields:

- `receipt_id`
- `transform`
- `interface_id`
- `proof_hash`
- `signer_id`
- `signature`
- `expires_epoch_ms`
- `trace_id`

## Event Codes

- `SPECULATION_GUARD_START`
- `SPECULATION_PROOF_ACCEPTED`
- `SPECULATION_ACTIVATED`
- `SPECULATION_DEGRADED`
- `SPECULATION_SAFE_BASELINE_USED`

## Error Codes

- `ERR_SPEC_MISSING_PROOF`
- `ERR_SPEC_EXPIRED_PROOF`
- `ERR_SPEC_SIGNATURE_INVALID`
- `ERR_SPEC_INTERFACE_UNAPPROVED`
- `ERR_SPEC_GUARD_REJECTED`
- `ERR_SPEC_TRANSFORM_MISMATCH`

## Required Artifacts

- `crates/franken-node/src/runtime/speculation/proof_executor.rs`
- `tests/conformance/proof_speculation_guards.rs`
- `artifacts/10.17/speculation_proof_report.json`
- `artifacts/section_10_17/bd-1nl1/verification_evidence.json`
- `artifacts/section_10_17/bd-1nl1/verification_summary.md`
