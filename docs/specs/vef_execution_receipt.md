# VEF ExecutionReceipt Schema (v1)

**Bead:** bd-p73r  
**Section:** 10.18 — Verifiable Execution Fabric (VEF)  
**Schema Version:** `vef-execution-receipt-v1`

## Purpose

Define the canonical `ExecutionReceipt` emitted for high-risk runtime actions.
Receipts are the atomic evidence unit used by downstream hash-chain, proof, and
verification-gate stages.

## Required Fields

- `schema_version` (`vef-execution-receipt-v1`)
- `action_type` (`network_access | filesystem_operation | process_spawn | secret_access | policy_transition | artifact_promotion`)
- `capability_context` (map<string,string>, non-empty)
- `actor_identity` (string, non-empty)
- `artifact_identity` (string, non-empty)
- `policy_snapshot_hash` (`sha256:<64-hex>`)
- `timestamp_millis` (u64)
- `sequence_number` (u64)
- `witness_references` (string[], entries non-empty)
- `trace_id` (string, non-empty)

## Deterministic Serialization Contract

Canonical serialization (`serialize_canonical`) follows these rules:

1. Validate schema version and required field constraints.
2. Normalize witness references by sorting + deduplicating.
3. Serialize canonical receipt object to UTF-8 JSON.
4. Use canonical bytes as the sole hashing substrate.

Determinism guarantee:

- Identical logical receipts produce identical canonical byte sequences.
- Canonical hashing is deterministic across repeated runs.

## Hashing Contract

- Algorithm: SHA-256
- Output format: `sha256:<64-lowercase-hex>`
- Function: `receipt_hash_sha256(receipt)`
- Mismatch verification: `verify_hash(receipt, expected_hash)`

## Validation + Error Model

Stable event codes:

- `VEF-RECEIPT-001` receipt created
- `VEF-RECEIPT-002` receipt serialized

Stable error codes:

- `VEF-RECEIPT-ERR-001` missing required field
- `VEF-RECEIPT-ERR-002` invalid field shape/value
- `VEF-RECEIPT-ERR-003` schema version mismatch
- `VEF-RECEIPT-ERR-004` hash mismatch
- `VEF-RECEIPT-ERR-005` internal serialization failure

## Invariants

- `INV-VEF-RECEIPT-DETERMINISTIC`
- `INV-VEF-RECEIPT-HASH-STABLE`
- `INV-VEF-RECEIPT-VERSIONED`
- `INV-VEF-RECEIPT-TRACEABLE`

## Golden Vectors

Golden vectors live at:

- `artifacts/10.18/vef_receipt_schema_vectors.json`

Vectors include canonical examples for:

- baseline network access receipt
- unicode actor identity handling
- high sequence/timestamp boundary

## Implementation Surfaces

- `crates/franken-node/src/connector/vef_execution_receipt.rs`
- `spec/vef_execution_receipt_v1.json`
- `scripts/check_vef_execution_receipt.py`
- `tests/test_check_vef_execution_receipt.py`
- `artifacts/section_10_18/bd-p73r/verification_evidence.json`
- `artifacts/section_10_18/bd-p73r/verification_summary.md`
