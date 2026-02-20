# bd-19u: CRDT State Mode Scaffolding

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Provide four CRDT (Conflict-free Replicated Data Type) implementations for
connector state management in multi-replica environments. Each type has
deterministic merge semantics verified by conformance fixtures.

## Dependencies

- bd-1cm: Singleton-writer fencing (provides state write context)

## CRDT Types

| Type        | Description                                   | Merge Law              |
|-------------|-----------------------------------------------|------------------------|
| `lww_map`   | Last-Writer-Wins Map — per-key timestamp wins | max(timestamp) per key |
| `or_set`    | Observed-Remove Set — add wins over remove    | union(adds) - removes  |
| `gcounter`  | Grow-only Counter — monotonically increasing  | max(per-replica)       |
| `pncounter` | Positive-Negative Counter — inc and dec       | sum(pos) - sum(neg)    |

## Merge Laws

1. **Commutativity**: merge(A, B) == merge(B, A)
2. **Associativity**: merge(merge(A, B), C) == merge(A, merge(B, C))
3. **Idempotency**: merge(A, A) == A

## Invariants

1. **INV-CRDT-TAGGED**: Each CRDT value carries a schema tag identifying its type.
   Merging values with different tags is an error.
2. **INV-CRDT-DETERMINISTIC**: merge(A, B) produces the same output regardless of
   which replica performs the merge.
3. **INV-CRDT-COMMUTATIVE**: merge(A, B) == merge(B, A) for all values.
4. **INV-CRDT-IDEMPOTENT**: merge(A, A) == A for all values.

## Error Codes

| Code               | Meaning                                 |
|--------------------|-----------------------------------------|
| `CRDT_TYPE_MISMATCH` | Attempted to merge different CRDT types |

## Artifacts

- `crates/franken-node/src/connector/crdt.rs` — CRDT implementations
- `tests/conformance/crdt_merge_fixtures.rs` — Merge law conformance tests
- `fixtures/crdt/*.json` — Merge test fixtures
- `docs/specs/section_10_13/bd-19u_contract.md` — This specification
