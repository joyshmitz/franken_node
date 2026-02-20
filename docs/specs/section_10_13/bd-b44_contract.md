# bd-b44: State Schema Version Contracts and Migration Hints

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

State schema version transitions require declared migration paths.
Migrations are idempotent, replay-stable, and failed migrations
roll back cleanly. Migration hints provide deterministic execution
contracts for version transitions.

## Dependencies

- bd-24s: Snapshot policy and bounded replay targets

## Schema Version Contract

Each connector declares a schema version. Version transitions must
follow a declared migration path.

| Field             | Type      | Description                              |
|-------------------|-----------|------------------------------------------|
| `connector_id`    | String    | Connector owning this schema             |
| `current_version` | SemVer    | Current schema version (major.minor.patch) |
| `supported_range` | Range     | Range of versions this connector supports |

## Migration Hint

A migration hint describes a single version transition step.

| Field           | Type       | Description                              |
|-----------------|------------|------------------------------------------|
| `from_version`  | SemVer     | Source version                            |
| `to_version`    | SemVer     | Target version                            |
| `hint_type`     | HintType   | Type of migration operation               |
| `idempotent`    | bool       | Whether the migration is safe to re-run   |
| `rollback_safe` | bool       | Whether the migration can be rolled back  |

### Hint Types

| Type            | Description                                      |
|-----------------|--------------------------------------------------|
| `add_field`     | Add a new field with a default value              |
| `remove_field`  | Remove a deprecated field                         |
| `rename_field`  | Rename a field (preserving data)                  |
| `transform`     | Apply a data transformation                       |

## Migration Plan

A migration plan is an ordered sequence of hints from source to target
version. The plan must form a valid path in the version graph.

## Invariants

1. **INV-MIGRATE-PATH**: Every version transition must have a declared
   migration path (no implicit schema jumps).
2. **INV-MIGRATE-IDEMPOTENT**: Re-applying a migration to an already-migrated
   state produces the same result.
3. **INV-MIGRATE-ROLLBACK**: Failed migrations leave state unchanged
   (clean rollback).
4. **INV-MIGRATE-MONOTONIC**: Schema versions advance forward; downgrades
   require explicit rollback hints.

## Error Codes

| Code                        | Meaning                                     |
|-----------------------------|---------------------------------------------|
| `MIGRATION_PATH_MISSING`    | No path from source to target version        |
| `MIGRATION_ALREADY_APPLIED` | Migration was already applied (idempotent OK) |
| `MIGRATION_ROLLBACK_FAILED` | Rollback of a failed migration did not succeed |
| `SCHEMA_VERSION_INVALID`    | Version string does not parse as semver       |

## Artifacts

- `crates/franken-node/src/connector/schema_migration.rs` — Migration impl
- `tests/integration/state_migration_contract.rs` — Integration tests
- `fixtures/schema_migration/*.json` — Migration test fixtures
- `artifacts/section_10_13/bd-b44/state_migration_receipts.json` — Receipts
- `docs/specs/section_10_13/bd-b44_contract.md` — This specification
