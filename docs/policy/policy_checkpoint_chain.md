# Policy: Policy Checkpoint Chain for Release Channels

**Bead:** bd-174
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active

## Purpose

This policy defines the requirements for maintaining a cryptographically-linked
policy checkpoint chain across product release channels (stable, beta, canary,
and operator-defined custom channels). The chain provides a tamper-evident audit
trail that ensures policy integrity and prevents undetected rollback attacks.

## Scope

This policy applies to all policy state transitions within the franken_node
system. Every release channel must have at least one policy checkpoint before
any release artifact can be published for that channel.

## Requirements

### Checkpoint Chain Integrity

1. **Append-Only Semantics:** The policy checkpoint chain is strictly append-only.
   No checkpoint may be deleted, modified, or reordered after insertion.

2. **Monotonic Sequencing:** Every checkpoint carries a monotonically increasing
   sequence number. Gaps are not permitted. Attempting to append a checkpoint
   with sequence number N requires the chain head to be at N-1.

3. **Parent Hash Linking:** Each checkpoint references the hash of its immediate
   predecessor via the `parent_hash` field. The genesis checkpoint has
   `parent_hash = None`. This forms an unbroken hash chain from genesis to head.

4. **Canonical Serialization:** All checkpoint hashing MUST use the canonical
   deterministic serializer (per bd-jjm). No ad-hoc or alternative encoding
   paths are permitted. This ensures signature preimage stability and
   cross-kernel verifiability.

5. **Domain-Separated IDs:** Checkpoint identifiers use the `pchk:` domain
   prefix from the trust object ID system (bd-1l5), ensuring no cross-domain
   collisions with other trust objects.

### Release Channel Coverage

1. **Multi-Channel Support:** A single chain supports checkpoints for multiple
   release channels (stable, beta, canary, custom). The `policy_frontier()`
   query returns the latest checkpoint per channel.

2. **Minimum Channels:** At least three channels (stable, beta, canary) must
   be supported. Operators may define additional custom channels.

3. **Channel-Scoped Queries:** `latest_for_channel()` provides O(n)
   retrieval of the most recent checkpoint for a specific channel.

### Rollback Resistance

1. **Fork Detection:** The policy frontier produced by this chain is consumed
   by bd-2ms for divergence and rollback detection. Any attempt to rewind
   the chain is detectable via the hash chain break.

2. **Epoch Boundaries:** Epoch transitions are explicitly marked via the
   `epoch_id` field. Policy checkpoints across epoch boundaries maintain
   chain continuity.

### Verification Requirements

1. **O(n) Chain Verification:** `verify_chain()` must traverse the entire
   chain in linear time and return the first violation index upon detecting
   any integrity issue.

2. **Tamper Detection:** A single bit-flip in any checkpoint field (sequence,
   epoch_id, channel, policy_hash, parent_hash, timestamp, signer) must be
   detectable by `verify_chain()`.

3. **Adversarial Resilience:** The chain must reject:
   - Out-of-order sequence numbers
   - Duplicate sequence numbers
   - Forged parent hashes
   - Skipped sequence numbers

### Audit Trail

All checkpoint operations emit structured events:

| Event               | When Emitted                                  |
|---------------------|-----------------------------------------------|
| CHECKPOINT_CREATED  | New checkpoint successfully appended           |
| CHECKPOINT_VERIFIED | Chain verification completed                   |
| CHECKPOINT_REJECTED | Checkpoint append rejected due to violation    |
| CHECKPOINT_FRONTIER | Policy frontier queried                        |

Each event includes `trace_id` and `epoch_id` for correlation.

## Invariants

- **INV-PCK-MONOTONIC:** Sequence numbers strictly increase with no gaps.
- **INV-PCK-PARENT-CHAIN:** Every parent_hash matches the predecessor's checkpoint_hash.
- **INV-PCK-HASH-INTEGRITY:** checkpoint_hash is deterministic over canonical fields.
- **INV-PCK-APPEND-ONLY:** Chain is immutable after insertion.
- **INV-PCK-CANONICAL-SER:** All hashing uses canonical serialization (bd-jjm).
- **INV-PCK-MULTI-CHANNEL:** Multiple channels coexist; frontier returns one per channel.

## Event Codes

| Code    | Description                                      |
|---------|--------------------------------------------------|
| PCK-001 | Checkpoint created                               |
| PCK-002 | Chain verification completed                     |
| PCK-003 | Checkpoint rejected                              |
| PCK-004 | Policy frontier queried                          |

## Error Codes

| Code                             | Description                                   |
|----------------------------------|-----------------------------------------------|
| CHECKPOINT_SEQ_VIOLATION         | Non-monotonic sequence number                 |
| CHECKPOINT_PARENT_MISMATCH       | Parent hash does not match chain head         |
| CHECKPOINT_HASH_CHAIN_BREAK      | Hash chain integrity failure                  |
| CHECKPOINT_EMPTY_CHAIN           | Operation on empty chain                      |
| CHECKPOINT_SERIALIZATION_ERROR   | Canonical serialization failure               |

## Review and Updates

This policy is reviewed as part of the section 10.10 verification gate (bd-1jjq).
Any changes to the checkpoint chain format or invariants require updating both
this policy document and the specification contract (bd-174_contract.md).
