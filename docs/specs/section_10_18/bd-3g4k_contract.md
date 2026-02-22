# bd-3g4k: VEF Hash-Chained Receipt Stream + Checkpoint Commitments

**Section:** 10.18 — Verifiable Execution Fabric (VEF)  
**Track:** C/E — Trust-Native + Frontier Industrialization  
**Status:** Active

## Purpose

Implement an append-only receipt stream where each entry is hash-linked to the
previous entry, producing a deterministic tamper-evident execution history.
Define checkpoint commitments over deterministic windows for proof and verifier
subsystems.

## Required Behaviors

1. Append-only deterministic chain linkage (`prev_chain_hash` + `receipt_hash` -> `chain_hash`).
2. Configurable periodic checkpoint creation.
3. Independent integrity verification from entries + checkpoints alone.
4. Fail-closed tamper detection and stable error classification.
5. Recovery from persisted snapshot with full re-verification.
6. Linearizable concurrent append semantics.

## Tamper Classes

- receipt content mutation
- insertion
- deletion
- reordering
- forged link hash
- forged checkpoint commitment

## Event Codes

- `VEF-CHAIN-001`
- `VEF-CHAIN-002`
- `VEF-CHAIN-003`
- `VEF-CHAIN-ERR-001`
- `VEF-CHAIN-ERR-002`
- `VEF-CHAIN-ERR-003`
- `VEF-CHAIN-ERR-004`

## Invariants

- `INV-VEF-CHAIN-APPEND-ONLY`
- `INV-VEF-CHAIN-DETERMINISTIC`
- `INV-VEF-CHAIN-CHECKPOINT-REPRODUCIBLE`
- `INV-VEF-CHAIN-FAIL-CLOSED`

## Acceptance Criteria

1. Deterministic chain hash reproduction for identical receipt sequences.
2. Deterministic checkpoint commitment reproduction for identical windows.
3. Verification fails closed on tamper scenarios and forged checkpoints.
4. Snapshot recovery validates and restores a consistent chain state.
5. Concurrency path preserves valid chain linkage.
6. Checker + tests pass with machine-readable evidence artifacts.

## Artifacts

- `crates/franken-node/src/vef/receipt_chain.rs`
- `crates/franken-node/src/vef/mod.rs`
- `tests/conformance/vef_receipt_chain_integrity.rs`
- `crates/franken-node/tests/vef_receipt_chain_integrity.rs`
- `docs/specs/vef_receipt_chain.md`
- `artifacts/10.18/vef_receipt_commitment_log.jsonl`
- `scripts/check_vef_receipt_chain.py`
- `tests/test_check_vef_receipt_chain.py`
- `artifacts/section_10_18/bd-3g4k/verification_evidence.json`
- `artifacts/section_10_18/bd-3g4k/verification_summary.md`
