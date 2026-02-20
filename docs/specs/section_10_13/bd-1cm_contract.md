# bd-1cm: Singleton-Writer Fencing Validation

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Connector state writes are guarded by a singleton-writer fencing mechanism.
Each writer holds a lease with a monotonically increasing sequence number
(`lease_seq`). Writes without a valid fence token or with a stale `lease_seq`
are deterministically rejected.

## Dependencies

- bd-18o: Canonical connector state root/object model

## Fencing Mechanism

A writer acquires a lease before writing state. The lease contains:
- `lease_seq`: monotonically increasing u64 sequence number
- `object_id`: the state root object this lease governs
- `holder_id`: identity of the writer
- `acquired_at`: ISO 8601 timestamp
- `expires_at`: ISO 8601 timestamp

## Fencing Rules

1. A write is **fenced** if it carries a lease_seq matching the current fence.
2. A write is **unfenced** if it carries no lease_seq.
3. A write is **stale-fenced** if its lease_seq < current fence value.
4. Only the holder of the current lease can advance the fence.

## Invariants

1. **INV-FENCE-MONOTONIC**: `lease_seq` values are strictly monotonically increasing.
   A new lease_seq must be greater than the current fence value.
2. **INV-FENCE-REJECT-UNFENCED**: Writes without a fence token are rejected with
   `WRITE_UNFENCED`.
3. **INV-FENCE-REJECT-STALE**: Writes with lease_seq < current fence are rejected
   with `WRITE_STALE_FENCE`.
4. **INV-FENCE-LINKED**: Each lease is linked to exactly one object_id. A lease
   cannot be used to write to a different object.

## Error Codes

| Code                 | Meaning                                         |
|----------------------|-------------------------------------------------|
| `WRITE_UNFENCED`     | Write has no fence token                         |
| `WRITE_STALE_FENCE`  | Write fence seq < current fence seq              |
| `LEASE_EXPIRED`      | Lease has passed its expiry timestamp            |
| `LEASE_OBJECT_MISMATCH`| Lease object_id does not match target object   |

## Artifacts

- `crates/franken-node/src/connector/fencing.rs` — Fencing implementation
- `tests/conformance/singleton_writer_fencing.rs` — Conformance tests
- `docs/specs/section_10_13/bd-1cm_contract.md` — This specification
- `artifacts/section_10_13/bd-1cm/fencing_rejection_receipts.json` — Evidence
