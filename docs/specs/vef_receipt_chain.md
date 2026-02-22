# VEF Receipt Chain Specification (v1)

**Bead:** bd-3g4k  
**Section:** 10.18 — Verifiable Execution Fabric (VEF)  
**Schema Version:** `vef-receipt-chain-v1`

## Purpose

Define the append-only, tamper-evident chain for `ExecutionReceipt` objects.
The chain converts isolated receipts into cryptographically linked execution
history suitable for proof-window selection and independent verification.

## Data Model

### Chain Entry

Each entry includes:

- `index` (u64, contiguous from `0`)
- `prev_chain_hash` (`sha256:<64-hex>`, genesis uses all-zero hash)
- `receipt_hash` (`sha256:<64-hex>`)
- `chain_hash` (`sha256:<64-hex>`)
- `receipt` (canonical `ExecutionReceipt`)
- `appended_at_millis` (u64)
- `trace_id` (string, non-empty)

### Checkpoint Commitment

Each checkpoint includes:

- `checkpoint_id` (u64, contiguous from `0`)
- `start_index` (u64)
- `end_index` (u64)
- `entry_count` (u64)
- `chain_head_hash` (`sha256:<64-hex>`)
- `commitment_hash` (`sha256:<64-hex>`)
- `created_at_millis` (u64)
- `trace_id` (string, non-empty)

## Deterministic Chain-Link Rule

For each entry `i`:

1. Compute `receipt_hash` from canonical `ExecutionReceipt` bytes.
2. Set `prev_chain_hash`:
   - `GENESIS_PREV_HASH` for `i == 0`
   - previous entry `chain_hash` for `i > 0`
3. Compute `chain_hash = sha256(json({schema_version, index, prev_chain_hash, receipt_hash}))`.

Identical receipt sequences always yield identical chain hashes.

## Checkpoint Commitment Rule

For checkpoint range `start_index..end_index`:

1. Collect entry `chain_hash` values in index order.
2. Compute `commitment_hash = sha256(json({schema_version, start_index, end_index, entry_count, chain_head_hash, entry_chain_hashes}))`.
3. Persist checkpoint as append-only commitment log entry.

Recomputing the same range must yield the same commitment hash.

## Tamper Detection (Fail-Closed)

Verification fails closed on:

- receipt content mutation
- receipt insertion/deletion/reordering
- broken `prev_chain_hash` linkage
- forged `chain_hash`
- forged checkpoint commitment
- invalid checkpoint ranges/overlap

## Concurrency and Recovery

- `ConcurrentReceiptChain` enforces linearizable append ordering via mutex
  serialization.
- `resume_from_snapshot` verifies full chain + checkpoint integrity before
  accepting recovered state.

## Event Codes

- `VEF-CHAIN-001` receipt appended
- `VEF-CHAIN-002` checkpoint created
- `VEF-CHAIN-003` chain verified
- `VEF-CHAIN-ERR-001` tamper/integrity failure
- `VEF-CHAIN-ERR-002` checkpoint integrity failure
- `VEF-CHAIN-ERR-003` sequence/linkage failure
- `VEF-CHAIN-ERR-004` internal serialization/hashing failure

## Invariants

- `INV-VEF-CHAIN-APPEND-ONLY`
- `INV-VEF-CHAIN-DETERMINISTIC`
- `INV-VEF-CHAIN-CHECKPOINT-REPRODUCIBLE`
- `INV-VEF-CHAIN-FAIL-CLOSED`

## Implementation Surfaces

- `crates/franken-node/src/vef/receipt_chain.rs`
- `crates/franken-node/src/vef/mod.rs`
- `tests/conformance/vef_receipt_chain_integrity.rs`
- `crates/franken-node/tests/vef_receipt_chain_integrity.rs`
- `artifacts/10.18/vef_receipt_commitment_log.jsonl`
- `scripts/check_vef_receipt_chain.py`
- `tests/test_check_vef_receipt_chain.py`
- `artifacts/section_10_18/bd-3g4k/verification_evidence.json`
- `artifacts/section_10_18/bd-3g4k/verification_summary.md`
