# bd-p73r: Canonical ExecutionReceipt Schema + Deterministic Serialization

**Section:** 10.18 — Verifiable Execution Fabric (VEF)  
**Track:** C/E — Trust-Native + Frontier Industrialization  
**Status:** Active

## Purpose

Define the canonical `ExecutionReceipt` schema and deterministic serialization
rules for VEF. This receipt is the foundational evidence object consumed by
hash-chain, proof-generation, and verification-gate stages.

## Required Action Classes

1. `network_access`
2. `filesystem_operation`
3. `process_spawn`
4. `secret_access`
5. `policy_transition`
6. `artifact_promotion`

## Receipt Contract

Each receipt must include:

- action type
- capability context
- actor identity
- artifact identity
- policy snapshot hash
- monotonic timestamp + sequence number
- witness references
- trace correlation ID
- schema version

## Determinism Rules

- Canonical serialization must normalize witness order and deduplicate entries.
- Canonical bytes must be hash-stable for identical logical receipts.
- Round-trip serialization (`serialize -> deserialize -> serialize`) must
  produce identical canonical bytes.

## Event Codes

- `VEF-RECEIPT-001` receipt created
- `VEF-RECEIPT-002` receipt serialized

## Error Codes

- `VEF-RECEIPT-ERR-001` missing required field
- `VEF-RECEIPT-ERR-002` invalid field value/shape
- `VEF-RECEIPT-ERR-003` schema version mismatch
- `VEF-RECEIPT-ERR-004` hash mismatch
- `VEF-RECEIPT-ERR-005` internal serialization failure

## Invariants

- `INV-VEF-RECEIPT-DETERMINISTIC`
- `INV-VEF-RECEIPT-HASH-STABLE`
- `INV-VEF-RECEIPT-VERSIONED`
- `INV-VEF-RECEIPT-TRACEABLE`

## Acceptance Criteria

1. Receipt schema includes all required identity/context/policy/time fields.
2. Canonical serialization is deterministic and hash-stable.
3. Schema version is explicit and validated.
4. Golden vectors include expected hashes and canonical outputs.
5. Validation rejects malformed receipts with stable error codes.
6. Verification checker + unit tests pass with machine-readable evidence.

## Artifacts

- `docs/specs/vef_execution_receipt.md`
- `spec/vef_execution_receipt_v1.json`
- `artifacts/10.18/vef_receipt_schema_vectors.json`
- `scripts/check_vef_execution_receipt.py`
- `tests/test_check_vef_execution_receipt.py`
- `artifacts/section_10_18/bd-p73r/verification_evidence.json`
- `artifacts/section_10_18/bd-p73r/verification_summary.md`
