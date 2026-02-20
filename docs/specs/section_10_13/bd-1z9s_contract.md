# bd-1z9s: Transparency-Log Inclusion Proof Checks

## Bead: bd-1z9s | Section: 10.13

## Purpose

Implements transparency-log inclusion proof verification for connector
install/update pipelines. Install or update fails if the required
inclusion proof is missing or invalid. Log roots are pinned per policy
and the verification path is deterministically replayable.

## Invariants

| ID | Statement |
|----|-----------|
| INV-TLOG-REQUIRED | Install/update fails if inclusion proof is missing. |
| INV-TLOG-VERIFY | Inclusion proof must recompute to the pinned log root via Merkle path. |
| INV-TLOG-PINNED-ROOT | Log roots are pinned per policy; unpinned roots are rejected. |
| INV-TLOG-REPLAYABLE | Verification is deterministic: same proof + root always yields same result. |

## Types

### LogRoot
- `tree_size: u64` — number of entries in the log
- `root_hash: String` — hex-encoded Merkle root

### InclusionProof
- `leaf_index: u64` — position of the entry in the log
- `tree_size: u64` — log size at time of proof
- `leaf_hash: String` — hash of the entry being proved
- `audit_path: Vec<String>` — sibling hashes along the Merkle path

### TransparencyPolicy
- `required: bool` — whether inclusion proof is mandatory
- `pinned_roots: Vec<LogRoot>` — accepted root checkpoints

### ProofReceipt
- `connector_id: String`
- `artifact_id: String`
- `verified: bool`
- `log_root_matched: bool`
- `proof_valid: bool`
- `failure_reason: Option<ProofFailure>`
- `trace_id: String`
- `timestamp: String`

### ProofFailure
- `ProofMissing` — no inclusion proof provided
- `RootNotPinned` — log root not in pinned set
- `PathInvalid` — Merkle audit path doesn't recompute to root
- `LeafMismatch` — leaf hash doesn't match artifact hash

## Error Codes

| Code | Trigger |
|------|---------|
| `TLOG_PROOF_MISSING` | No inclusion proof provided for install/update. |
| `TLOG_ROOT_NOT_PINNED` | Log root hash not found in pinned roots set. |
| `TLOG_PATH_INVALID` | Merkle audit path fails to recompute expected root. |
| `TLOG_LEAF_MISMATCH` | Leaf hash in proof doesn't match artifact content hash. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-1z9s_contract.md` |
| Implementation | `crates/franken-node/src/supply_chain/transparency_verifier.rs` |
| Security tests | `tests/security/transparency_inclusion.rs` |
| Proof receipts | `artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json` |
| Verification evidence | `artifacts/section_10_13/bd-1z9s/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-1z9s/verification_summary.md` |
