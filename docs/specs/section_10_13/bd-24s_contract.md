# bd-24s: Snapshot Policy and Bounded Replay Targets

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Implement snapshot policies (`every_updates`, `every_bytes`) that bound replay
cost for connector state recovery. Snapshots are validated against chain heads
and policy changes are audited.

## Dependencies

- bd-19u: CRDT state mode scaffolding (provides state merge foundation)

## Snapshot Policy

| Trigger        | Description                                          | Default |
|----------------|------------------------------------------------------|---------|
| `every_updates`| Take snapshot after N state updates since last snap  | 100     |
| `every_bytes`  | Take snapshot after N bytes of accumulated mutations | 65536   |

Either trigger firing causes a snapshot. Both must be configured.

## Replay Target

A replay target bounds the maximum number of operations that must be
replayed from the last snapshot to reach the current state.

| Field              | Type   | Description                                   |
|--------------------|--------|-----------------------------------------------|
| `max_replay_ops`   | u64    | Upper bound on replay operations              |
| `max_replay_bytes` | u64    | Upper bound on replay bytes                   |
| `snapshot_version` | u64    | Version at which the last snapshot was taken   |
| `current_version`  | u64    | Current head version                          |

## Snapshot Record

| Field              | Type   | Description                              |
|--------------------|--------|------------------------------------------|
| `connector_id`     | String | Connector this snapshot belongs to       |
| `snapshot_version`  | u64    | Version captured in this snapshot        |
| `root_hash`        | String | Hash of state at snapshot time           |
| `taken_at`         | String | ISO-8601 timestamp                       |
| `policy`           | Policy | The policy that triggered this snapshot  |
| `ops_since_last`   | u64    | Operations since previous snapshot       |
| `bytes_since_last` | u64    | Bytes since previous snapshot            |

## Invariants

1. **INV-SNAP-BOUNDED**: replay_ops <= max(every_updates, max_replay_ops).
   After a snapshot, the replay distance resets to zero.
2. **INV-SNAP-HASH**: Snapshot root_hash must match the state root hash at
   snapshot_version.
3. **INV-SNAP-MONOTONIC**: snapshot_version is strictly monotonically increasing
   within a connector's snapshot chain.
4. **INV-SNAP-AUDIT**: Policy changes produce an audit record with old/new values
   and a timestamp.

## Error Codes

| Code                    | Meaning                                       |
|-------------------------|-----------------------------------------------|
| `SNAPSHOT_HASH_MISMATCH`| Snapshot hash does not match chain head        |
| `SNAPSHOT_STALE`        | Snapshot version is behind current by too much |
| `REPLAY_BOUND_EXCEEDED` | Replay cost exceeds configured threshold       |
| `POLICY_INVALID`        | Policy has zero or negative thresholds         |

## Artifacts

- `crates/franken-node/src/connector/snapshot_policy.rs` — Snapshot policy impl
- `tests/conformance/snapshot_policy_conformance.rs` — Conformance tests
- `fixtures/snapshot_policy/*.json` — Policy test fixtures
- `docs/specs/section_10_13/bd-24s_contract.md` — This specification
