# Migration to Frankensqlite

This document now separates the section 10.16 end-state from the live operator
surface in `crates/franken-node/src/migration/`. The end-state remains a single
durable `frankensqlite` source of truth, but the current CLI only exposes
project-level `migrate audit`, `migrate rewrite`, and `migrate validate`
workflows over package manifests and JS/TS source files. It does not yet expose
connector-store cutover, dual-write execution, or a
`migrate to-frankensqlite --rollback --run-id ...` command.

## Current live surface

- `franken-node migrate audit <project>` inventories migration risk and emits
  audit findings.
- `franken-node migrate rewrite <project> --apply --emit-rollback <path>`
  rewrites manifests and JS/TS modules, writes original file snapshots under
  `.migrate-backup/`, and emits a file-scoped `MigrationRollbackPlan`.
- `franken-node migrate validate <project>` reruns the static migration checks
  and executes transformed-runtime smoke validation; it does not orchestrate a
  live connector-state cutover into `frankensqlite`.

## Migration inventory (target state)

| Domain | Source module | Current source type | Migration status target | Primary persistence after cutover |
|---|---|---|---|---|
| `state_model` | `crates/franken-node/src/connector/state_model.rs` | In-memory `StateRoot` objects with JSON head/hash/version fields | `frankensqlite` table set with canonical root rows | `frankensqlite` |
| `fencing_token_state` | `crates/franken-node/src/connector/fencing.rs` | In-memory `FenceState` + `Lease` sequence and holder metadata | `frankensqlite` fencing token rows keyed by object + sequence | `frankensqlite` |
| `lease_coordination_state` | `crates/franken-node/src/connector/lease_coordinator.rs` | In-memory candidate/signature sets and deterministic selection output | `frankensqlite` coordination snapshots keyed by lease id | `frankensqlite` |
| `lease_service_state` | `crates/franken-node/src/connector/lease_service.rs` | In-memory lease map + decision log vector | `frankensqlite` lease and lease_decision tables | `frankensqlite` |
| `lease_conflict_state` | `crates/franken-node/src/connector/lease_conflict.rs` | In-memory active lease inputs and fork-resolution log entries | `frankensqlite` conflict + fork-log tables | `frankensqlite` |
| `snapshot_policy_state` | `crates/franken-node/src/connector/snapshot_policy.rs` | In-memory `SnapshotTracker` counters + policy audit vector | `frankensqlite` snapshot policy and snapshot record tables | `frankensqlite` |
| `quarantine_store_state` | `crates/franken-node/src/connector/quarantine_store.rs` | In-memory quarantine entry map + eviction counters | `frankensqlite` quarantine entry and eviction audit tables | `frankensqlite` |
| `retention_policy_state` | `crates/franken-node/src/connector/retention_policy.rs` | In-memory policy registry map + retention store map | `frankensqlite` retention policy/message/decision tables | `frankensqlite` |
| `artifact_persistence_state` | `crates/franken-node/src/connector/artifact_persistence.rs` | In-memory artifact map + per-type sequence vectors | `frankensqlite` artifact and replay-hook tables | `frankensqlite` |

## Migration strategy per domain

Each domain follows the same deterministic pipeline:

1. Export current state from interim store.
2. Transform to the `frankensqlite` schema using canonical keys.
3. Import with idempotent upsert semantics.
4. Verify row counts and domain invariants.
5. Cut over primary reads/writes to `frankensqlite`.

### Domain-specific details

- `state_model`
  - Export `connector_id`, `root_hash`, `version`, `state_model`, and canonical JSON head.
  - Verify `root_hash` integrity and monotonic version ordering.
- `fencing_token_state`
  - Export `object_id`, `current_seq`, and holder metadata.
  - Verify uniqueness of `(object_id, current_seq)` and stale-fence rejection parity.
- `lease_coordination_state`
  - Export coordinator selection inputs, selected coordinator, and quorum result material.
  - Verify deterministic coordinator selection for the same lease inputs.
- `lease_service_state`
  - Export lease lifecycle records and decision log entries.
  - Verify no active lease violates TTL/revocation rules.
- `lease_conflict_state`
  - Export overlap windows, conflict classification, and deterministic winner metadata.
  - Verify non-overlap policy and deterministic winner/tiebreak replay.
- `snapshot_policy_state`
  - Export snapshot policy thresholds, tracker counters, and audit records.
  - Verify replay distance bounds and policy validation behavior are preserved.
- `quarantine_store_state`
  - Export quarantine objects, ingest timestamps, and eviction history.
  - Verify TTL/quota eviction decisions remain deterministic.
- `retention_policy_state`
  - Export message class policies and stored message metadata.
  - Verify required-vs-ephemeral behavior and TTL cleanup semantics.
- `artifact_persistence_state`
  - Export persisted artifacts, per-type sequence numbers, and replay hooks.
  - Verify sequence monotonicity and replay hash checks.

## Rollback path

Rollback is file-scoped today, not connector-store dual-write.

1. `migrate rewrite --apply` writes the original file contents to
   `.migrate-backup/<relative-path>` before mutating the source file.
2. The rewrite report records `rollback_entries` with both original and
   rewritten content.
3. `--emit-rollback <path>` serializes those entries into a
   `MigrationRollbackPlan`.
4. Operator rollback today means restoring from the emitted rollback plan and/or
   `.migrate-backup` snapshots; there is no live `run_id` rollback command in
   this module.
5. `validate_rollback_plan()` hardens rollback artifacts against absolute paths,
   traversal, unsafe separators, oversized entries, and entry-count mismatch.

## Idempotency guarantee

The durable-cutover guarantees below remain the target design. The current live
module only guarantees deterministic rewrite planning/report serialization and
runtime-smoke receipt round-trips for the file-oriented migration surface.

- Target cutover import should use upsert keys derived from canonical source
  identifiers.
- Target cutover should make repeated runs over the same source data converge on
  identical row values and row counts.
- Target cutover should not introduce duplicate rows on rerun.
- Target invariants (fencing uniqueness, lease non-overlap, replay ordering)
  should pass on both first and second runs.

## Current evidence surface

The live migration module currently emits/produces:

- `MigrationAuditReport`
- `MigrationRewriteReport`
- `MigrationRollbackPlan`
- transformed-runtime smoke receipts with stdout/stderr digests during
  `migrate validate`

Per-domain `run_id` migration events remain future work for the eventual
connector-store cutover path.
