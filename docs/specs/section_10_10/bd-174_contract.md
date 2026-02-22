# bd-174 Contract: Policy Checkpoint Chain for Product Release Channels

**Bead:** bd-174
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

Enhancement Map 9E.3 requires a checkpointed policy frontier for release channels
and rollback resistance. Without an immutable, hash-chained sequence of policy
checkpoints, product release channels (stable, beta, canary) lack a verifiable
audit trail -- operators cannot prove which policy was active at any point in time,
and rollback attacks can silently revert security-critical policy changes.

This bead implements the product-level policy checkpoint chain that anchors every
release channel transition to a signed, sequenced, tamper-evident record. Combined
with the rollback/fork detection in bd-2ms, this forms the foundation of the
epoch-scoped trust model where no policy state can be rewound without detection.

## Dependencies

- **Upstream:** bd-jjm (canonical deterministic serialization and signature preimage rules)
- **Upstream:** bd-1l5 (canonical trust object IDs with domain separation -- provides `DomainPrefix::PolicyCheckpoint`)
- **Downstream:** bd-2ms (rollback/fork detection consumes the policy frontier)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Model

### ReleaseChannel (enum)

Predefined release channels plus a custom variant:

| Variant  | Description                             |
|----------|-----------------------------------------|
| Stable   | Production-ready general availability   |
| Beta     | Pre-release testing channel             |
| Canary   | Early-adopter experimental channel      |
| Custom   | Operator-defined channel (string label) |

Canonical labels: `"stable"`, `"beta"`, `"canary"`, `"custom:<name>"`.
Implements `Display`, `Eq`, `Hash`, `Clone`, `Serialize`, `Deserialize`.

### PolicyCheckpoint (struct)

Each checkpoint captures a snapshot of policy state for a specific release channel:

| Field           | Type              | Description                                                  |
|-----------------|-------------------|--------------------------------------------------------------|
| sequence        | u64               | Monotonically increasing sequence number (per chain)         |
| epoch_id        | u64               | Epoch identifier for grouping checkpoints                    |
| channel         | ReleaseChannel    | Which release channel this checkpoint covers                 |
| policy_hash     | String            | SHA-256 hash over canonically-serialized policy document     |
| parent_hash     | Option\<String\>  | Hash of previous checkpoint (None for genesis)               |
| timestamp       | u64               | Unix timestamp (seconds) when checkpoint was created         |
| signer          | String            | Identity of the entity that signed/created this checkpoint   |
| checkpoint_hash | String            | Content-addressed hash of this checkpoint's canonical form   |

#### Methods

- **`verify_hash(&self) -> bool`**
  Recomputes the checkpoint hash from all fields and compares it to the stored
  `checkpoint_hash`. Returns `true` if they match. This is the per-checkpoint
  integrity check used by `verify_chain()`.

- **`short_hash(&self) -> &str`**
  Returns the first 16 hex characters of `checkpoint_hash` for log output.

#### Hash computation (INV-PCK-CANONICAL-SER)

The canonical hash is computed via SHA-256 over deterministically ordered fields
using domain-separated byte encoding:

```
SHA-256("pchk:canonical:v1" || 0x00
        || sequence.to_be_bytes() || 0x00
        || epoch_id.to_be_bytes() || 0x00
        || channel.label().as_bytes() || 0x00
        || policy_hash.as_bytes() || 0x00
        || parent_hash_or("GENESIS").as_bytes() || 0x00
        || timestamp.to_be_bytes() || 0x00
        || signer.as_bytes())
```

The domain separation tag `"pchk:canonical:v1"` prevents cross-type hash
collisions with other trust objects.

### PolicyCheckpointChain (struct)

Append-only chain that enforces integrity invariants:

| Field       | Type                           | Description                               |
|-------------|--------------------------------|-------------------------------------------|
| checkpoints | Vec\<PolicyCheckpoint\>        | Ordered sequence of checkpoints           |
| head_hash   | Option\<String\>               | Hash of the latest checkpoint             |
| next_seq    | u64                            | Next expected sequence number             |
| events      | Vec\<CheckpointChainEvent\>    | Audit event log                           |

### CheckpointChainEvent (struct)

Structured audit events emitted during chain operations:

| Field        | Type   | Description                              |
|--------------|--------|------------------------------------------|
| event_code   | String | Event code (PCK-001 through PCK-004)     |
| event_name   | String | Human-readable event name                |
| trace_id     | String | Correlation trace identifier             |
| epoch_id     | u64    | Epoch in which this event occurred       |
| sequence     | u64    | Sequence number involved                 |
| channel      | String | Release channel label                    |
| detail       | String | Additional detail or error reason        |

### CheckpointChainError (enum)

| Variant                  | Error Code                     | Description                                             |
|--------------------------|--------------------------------|---------------------------------------------------------|
| SequenceViolation        | CHECKPOINT_SEQ_VIOLATION       | Non-monotonic or duplicate sequence number              |
| ParentMismatch           | CHECKPOINT_PARENT_MISMATCH     | parent_hash does not match current chain head           |
| HashChainBreak           | CHECKPOINT_HASH_CHAIN_BREAK    | Verification found hash inconsistency                   |
| EmptyChain               | CHECKPOINT_EMPTY_CHAIN         | Operation requires non-empty chain but chain is empty   |
| SerializationFailure     | CHECKPOINT_SERIALIZATION_ERROR | Canonical serialization of checkpoint failed            |

Each variant exposes a `code() -> &'static str` method returning the machine-readable
error code, and implements `Display` with a human-readable message including relevant
context (expected vs. actual values, violation index, etc.).

## Key Methods

### PolicyCheckpointChain

- **`PolicyCheckpointChain::new() -> Self`**
  Creates an empty chain with sequence starting at 0, no head hash, and an empty
  event log. Also available via `Default`.

- **`create_checkpoint(&mut self, epoch_id: u64, channel: ReleaseChannel, policy_hash: &str, signer: &str, trace_id: &str) -> Result<&PolicyCheckpoint, CheckpointChainError>`**
  High-level checkpoint creation. Automatically assigns the next monotonic sequence
  number, sets `parent_hash` to the current chain head, computes `checkpoint_hash`
  via canonical serialization, and records the Unix timestamp. Enforces:
  - INV-PCK-MONOTONIC: sequence = `self.next_seq`
  - INV-PCK-PARENT-CHAIN: parent_hash = `self.head_hash`
  - INV-PCK-CANONICAL-SER: hash via deterministic encoding
  Emits `PCK-001 CHECKPOINT_CREATED` event. Returns reference to newly appended checkpoint.

- **`append_checkpoint(&mut self, checkpoint: PolicyCheckpoint, trace_id: &str) -> Result<&PolicyCheckpoint, CheckpointChainError>`**
  Low-level append of a pre-built checkpoint. The caller is responsible for
  constructing the checkpoint with the correct fields. The chain enforces:
  - INV-PCK-MONOTONIC: `checkpoint.sequence` must equal `self.next_seq`
  - INV-PCK-PARENT-CHAIN: `checkpoint.parent_hash` must equal `self.head_hash`
  Returns `SequenceViolation` or `ParentMismatch` on invariant violations. On
  rejection, emits `PCK-003 CHECKPOINT_REJECTED` event before returning the error.
  On success, emits `PCK-001 CHECKPOINT_CREATED` event.

- **`verify_chain(&self) -> Result<usize, (usize, CheckpointChainError)>`**
  Validates the entire chain in O(n) time. For each checkpoint, verifies:
  - Sequence number equals its index (INV-PCK-MONOTONIC)
  - parent_hash matches predecessor's checkpoint_hash (INV-PCK-PARENT-CHAIN)
  - Recomputed hash matches stored checkpoint_hash (INV-PCK-HASH-INTEGRITY)
  Returns `Ok(chain_length)` on success or `Err((violation_index, error))` on the
  first detected violation. An empty chain returns `Ok(0)`.

- **`latest_for_channel(&self, channel: &ReleaseChannel) -> Option<&PolicyCheckpoint>`**
  Scans the chain in reverse to find the most recent checkpoint for the given
  release channel. Returns `None` if no checkpoint exists for that channel.

- **`policy_frontier(&self) -> Vec<(ReleaseChannel, &PolicyCheckpoint)>`**
  Returns the latest checkpoint per channel (the policy frontier). At most one
  checkpoint per distinct channel. Results are sorted by sequence number. Used by
  downstream bd-2ms for divergence detection.

- **`len(&self) -> usize`**
  Returns the number of checkpoints in the chain.

- **`is_empty(&self) -> bool`**
  Returns `true` if the chain has no checkpoints.

- **`checkpoints(&self) -> &[PolicyCheckpoint]`**
  Read-only access to the checkpoint list.

- **`events(&self) -> &[CheckpointChainEvent]`**
  Read-only access to the audit event log.

- **`head_hash(&self) -> Option<&str>`**
  The hash of the current chain head (latest checkpoint).

- **`next_seq(&self) -> u64`**
  The next expected sequence number.

- **`channels(&self) -> Vec<ReleaseChannel>`**
  Returns distinct channels that have at least one checkpoint, sorted by label.

## Invariants

| Invariant ID             | Statement                                                                                              |
|--------------------------|--------------------------------------------------------------------------------------------------------|
| INV-PCK-MONOTONIC        | Sequence numbers are strictly monotonically increasing with no gaps. Appending sequence N requires the chain head to be at sequence N-1 (or chain to be empty for N=0). Enforced at `append_checkpoint()` and verified by `verify_chain()`. |
| INV-PCK-PARENT-CHAIN     | Every checkpoint's parent_hash matches the checkpoint_hash of its predecessor. The genesis checkpoint has parent_hash = None. Enforced at `append_checkpoint()` and verified by `verify_chain()`. |
| INV-PCK-HASH-INTEGRITY   | checkpoint_hash is deterministically derived from the canonical serialization of (sequence, epoch_id, channel, policy_hash, parent_hash, timestamp, signer) using SHA-256 with domain separation tag `"pchk:canonical:v1"`. Any modification to any field invalidates the hash. Verified by `PolicyCheckpoint::verify_hash()` and `verify_chain()`. |
| INV-PCK-APPEND-ONLY      | The chain is strictly append-only. No checkpoint may be removed, replaced, or reordered after insertion. The `PolicyCheckpointChain` API exposes no mutation methods for existing checkpoints (test-only tamper methods are gated behind `#[cfg(test)]`). |
| INV-PCK-CANONICAL-SER    | All checkpoint hashing uses canonical deterministic serialization (per bd-jjm). The hash function uses fixed field ordering with `0x00` byte separators, big-endian integer encoding, and a domain separation prefix. No ad-hoc encoding paths exist. |
| INV-PCK-MULTI-CHANNEL    | A single chain may contain checkpoints for multiple release channels. `policy_frontier()` returns at most one checkpoint per distinct channel. `latest_for_channel()` returns the most recent for a specific channel. |

## Event Codes

| Code    | Event Name            | Severity | Description                                                   |
|---------|-----------------------|----------|---------------------------------------------------------------|
| PCK-001 | CHECKPOINT_CREATED    | INFO     | New checkpoint appended (sequence, epoch, channel, hash prefix, signer) |
| PCK-002 | CHECKPOINT_VERIFIED   | INFO     | Chain verification completed (chain_length, channels, duration_ms)      |
| PCK-003 | CHECKPOINT_REJECTED   | ERROR    | Checkpoint append rejected (reason, attempted_seq, expected_seq)        |
| PCK-004 | CHECKPOINT_FRONTIER   | INFO     | Policy frontier queried (channel_count, checkpoint_count)               |

## Error Codes

| Code                             | Description                                                   |
|----------------------------------|---------------------------------------------------------------|
| CHECKPOINT_SEQ_VIOLATION         | Appending with non-monotonic or duplicate sequence number     |
| CHECKPOINT_PARENT_MISMATCH       | parent_hash does not match current chain head                 |
| CHECKPOINT_HASH_CHAIN_BREAK      | Hash chain integrity verification failed at some index        |
| CHECKPOINT_EMPTY_CHAIN           | Operation requires non-empty chain                            |
| CHECKPOINT_SERIALIZATION_ERROR   | Canonical serialization failed                                |

## Acceptance Criteria

1. **PolicyCheckpoint struct includes all required fields** (sequence, epoch_id,
   channel, policy_hash, parent_hash, timestamp, signer, checkpoint_hash) with
   documented invariants for each. All fields are public and serializable via serde.

2. **Non-monotonic sequence rejection:** Appending a checkpoint with a non-monotonic
   sequence number is rejected with error code `CHECKPOINT_SEQ_VIOLATION`. Both
   forward-skip (seq=5 when expecting seq=1) and duplicate (seq=0 when expecting
   seq=1) cases are covered.

3. **Parent hash mismatch rejection:** Appending a checkpoint whose parent_hash
   does not match the current chain head is rejected with `CHECKPOINT_PARENT_MISMATCH`.
   The error includes both expected and actual hash values.

4. **verify_chain() detects violations:** Detects any gap, reorder, or hash-chain
   break in O(n) time and returns the first violation index. Specifically detects:
   sequence gaps, parent_hash mismatches, and checkpoint_hash recomputation failures.

5. **latest_for_channel() correctness:** Returns the correct checkpoint for each
   of at least 3 channels (stable, beta, canary) in a multi-channel interleaved
   scenario. Returns `None` for channels with no checkpoints.

6. **Crash-recovery persistence:** The `PolicyCheckpointChain` struct derives
   `Serialize` and `Deserialize`. A chain serialized to JSON and deserialized back
   produces a chain that passes `verify_chain()` with identical length, head hash,
   and next sequence number.

7. **Canonical serialization:** All checkpoint hashing routes through the
   deterministic canonical encoding with domain separation tag `"pchk:canonical:v1"`,
   fixed field ordering, and `0x00` byte separators. No ad-hoc encoding paths exist.
   Hash computation is delegated to `PolicyCheckpoint::compute_hash()` which is the
   single code path for all checkpoint hash derivation.

8. **Verification evidence:** The evidence artifact JSON at
   `artifacts/section_10_10/bd-174/verification_evidence.json` conforms to the
   project evidence schema and includes chain length, channels covered, sample
   checkpoint hashes, and passing results for all acceptance criteria.

9. **100+ checkpoint chain test:** Unit tests create chains of 150 checkpoints
   across 3 channels and 3 epochs, verify full chain integrity, and confirm the
   policy frontier returns exactly one checkpoint per channel with the correct
   latest sequence number.

10. **Adversarial tests:** Unit tests attempt to skip sequence numbers, duplicate
    sequences, forge parent hashes, tamper checkpoint hashes, tamper policy hashes,
    tamper sequence numbers, and detect single-bit flips in policy_hash fields.
    All tampering is detected by `verify_chain()`.

## Test Scenarios

| Scenario                          | Description                                                                     |
|-----------------------------------|---------------------------------------------------------------------------------|
| Genesis checkpoint                | Creating the first checkpoint on an empty chain succeeds with sequence=0        |
| Sequential append                 | Appending checkpoints 0..N succeeds with correct parent chaining                |
| Out-of-order sequence rejection   | Attempting to append seq=5 when head is at seq=0 fails with SEQ_VIOLATION       |
| Duplicate sequence rejection      | Attempting to append seq=0 when head is at seq=0 fails with SEQ_VIOLATION       |
| Wrong parent hash rejection       | Appending with incorrect parent_hash fails with PARENT_MISMATCH                 |
| Empty chain edge case             | latest_for_channel returns None, verify_chain returns Ok(0)                     |
| Multi-channel interleaving        | Interleaving stable/beta/canary checkpoints, frontier returns one per channel   |
| Custom channel support            | Custom("nightly") channel coexists with standard channels in frontier           |
| Chain of 150 checkpoints          | Build and verify a 150-element chain across 3 channels and 3 epochs             |
| Tampered checkpoint_hash          | Modify a checkpoint_hash mid-chain and verify_chain detects it at correct index |
| Tampered policy_hash              | Modify a policy_hash mid-chain and verify_chain detects it at correct index     |
| Tampered parent_hash              | Forge a parent_hash mid-chain and verify_chain detects it at correct index      |
| Tampered sequence number          | Alter a sequence number mid-chain and verify_chain detects it at correct index  |
| Single bit-flip detection         | Flip one character in a policy_hash and verify detection                         |
| Epoch boundary continuity         | Chain maintains parent-hash continuity across epoch boundaries                  |
| Serde round-trip (checkpoint)     | Single checkpoint survives JSON serialize/deserialize with equality              |
| Serde round-trip (chain)          | Full chain survives JSON round-trip and passes verify_chain                     |
| ReleaseChannel serde              | All 4 channel variants survive JSON round-trip                                  |
| Event emission on create          | PCK-001 event emitted with correct fields on successful create                  |
| Event emission on rejection       | PCK-003 event emitted with correct fields on rejected append                    |
| Send + Sync                       | All public types are Send + Sync for safe concurrent access                     |

## Verification

- Script: `scripts/check_policy_checkpoint.py --json`
- Tests: `tests/test_check_policy_checkpoint.py`
- Evidence: `artifacts/section_10_10/bd-174/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-174/verification_summary.md`

## Artifacts

| Artifact                                                          | Purpose                        |
|-------------------------------------------------------------------|--------------------------------|
| `docs/specs/section_10_10/bd-174_contract.md`                     | This specification document    |
| `docs/policy/policy_checkpoint_chain.md`                          | Policy document                |
| `crates/franken-node/src/connector/policy_checkpoint.rs`          | Rust implementation            |
| `scripts/check_policy_checkpoint.py`                              | Verification script (--json)   |
| `tests/test_check_policy_checkpoint.py`                           | Unit tests for verifier        |
| `artifacts/section_10_10/bd-174/verification_evidence.json`       | Machine-readable evidence      |
| `artifacts/section_10_10/bd-174/verification_summary.md`          | Human-readable summary         |
