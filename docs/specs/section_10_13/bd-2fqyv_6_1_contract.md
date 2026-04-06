# bd-2fqyv.6.1 Contract: Executable Schema-Migration Step Semantics and Receipt Contract

## Scope

This contract defines how `crates/franken-node/src/connector/schema_migration.rs`
must evolve from a version-path validator into a real state-transforming
executor.

The goal is not to widen the live `franken-node migrate *` CLI surface beyond
its current truthful audit/rewrite/validate behavior. The goal is to make the
future connector-level schema-migration executor precise enough that
implementation bead `bd-2fqyv.6.2` becomes mechanical rather than interpretive.

This contract answers four questions explicitly:

- what state shape the executor is allowed to mutate
- how an ordered hint path becomes executable steps
- what idempotency and rollback mean for live execution
- which receipt fields are required to prove actual work happened

This document refines, but does not replace:

- `docs/specs/section_10_13/bd-b44_contract.md`
- `docs/specs/section_10_12/bd-3j4_contract.md`
- `docs/specs/section_10_12/bd-3hm_contract.md`
- `docs/specs/frankensqlite_persistence_contract.md`

## Relationship to Existing Modules

- `connector/schema_migration.rs` owns schema versions, migration hints, path
  discovery, and the future step executor for connector state.
- `connector/migration_pipeline.rs` owns cohort-level orchestration and the
  higher-level migration pipeline receipt.
- `connector/migration_artifact.rs` owns verifier-facing artifact packaging.
- `storage/models.rs::SchemaMigrationRecord` is the persistence anchor for
  applied schema-migration journal rows.

The schema-migration executor receipt is the low-level proof of connector state
mutation. Pipeline and artifact receipts may aggregate it, but they must not
invent lower-level execution facts that the executor did not record.

## Authoritative Execution State

An executable schema migration operates on a connector-owned deterministic state
capsule with these logical fields:

- `connector_id: String`
- `schema_version: SchemaVersion`
- `canonical_state: BTreeMap<String, serde_json::Value>` or an equivalent
  deterministic representation
- `state_hash: String` derived from canonical serialization of the mutable
  connector state
- `migration_journal: Vec<SchemaMigrationRecord>` or an equivalent persisted
  history

Implementation detail is flexible, but the executor must be able to derive
those logical fields before and after each step. Any state that depends on wall
clock time, random bytes, hash map iteration order, or non-canonical floating
point encoding is non-conformant for live execution.

## Plan Normalization

`MigrationHint` remains the path-discovery primitive. A `MigrationPlan` becomes
executable only after every hint is normalized into an `ExecutableMigrationStep`
with at least:

- `step_id`: stable digest of connector id + from/to version + hint type +
  description
- `from_version`
- `to_version`
- `hint_type`
- `idempotent`
- `rollback_safe`
- `mutation_summary`: explicit statement of what state keys/fields change
- `precondition_summary`: checks required before mutation
- `rollback_descriptor`: either an inverse operation or a checkpoint restore
  reference

Normalization MUST fail closed if any step lacks enough information to describe
the mutation boundary or rollback boundary deterministically.

## Step Application Semantics

Live execution of a normalized plan MUST follow this state machine for each
step:

1. Validate plan invariants before mutation begins:
   - plan connector id matches the target state owner
   - `plan.from_version` matches the current state version
   - ordered steps form a contiguous version chain
   - every step has deterministic mutation and rollback descriptors
2. Capture a deterministic checkpoint for the current state.
3. Evaluate step idempotency using journal state plus state hashes.
4. Apply the step mutation atomically.
5. Verify postconditions and the new state hash.
6. Persist the journal/receipt facts for the successful step.
7. Advance the in-memory state version to the step target version.

The executor MUST NOT mark a step as applied merely because the target version
number matches. Version equality without matching journal and hash evidence is a
hard conflict, not success.

## Hint-Type Mutation Rules

### `add_field`

- If the target field is absent, the executor inserts the deterministic default
  or computed value described by the step.
- If the target field already exists with the exact expected post-state value,
  the step may resolve as `already_applied` only when the step is idempotent.
- If the target field exists with any other value, execution fails.

### `remove_field`

- The executor removes the target field and stores the removed value in the
  rollback checkpoint or inverse descriptor.
- If the field is already absent, only an idempotent step may resolve as
  `already_applied`.

### `rename_field`

- The source field must exist unless the step is being recognized as an
  idempotent re-run.
- The destination field must be absent, or must already contain the exact moved
  value for an idempotent re-run.
- Rename is atomic: the executor must not persist an intermediate state where
  both fields are absent or both contain diverging values.

### `transform`

- The transformation function must be pure and deterministic for the canonical
  input state.
- It must not depend on external I/O, wall-clock reads, randomness, or ambient
  process state.
- The post-state hash must be verified after transformation and before the step
  is committed.

## Rollback Semantics

Rollback is not optional for live execution.

Rules:

- Every executable step must have a rollback descriptor.
- `rollback_safe = false` means the step is planable metadata only and MUST NOT
  enter the live executor until an explicit rollback path exists.
- On the first mutation failure or postcondition failure, the executor rolls
  back the current step from its checkpoint.
- If a plan has already committed earlier steps, rollback proceeds in reverse
  step order until the pre-plan state hash is restored.
- If any rollback action fails, the outcome is `failed` with
  `MIGRATION_ROLLBACK_FAILED`, and the receipt must identify the exact step
  where rollback broke down.

The live path must prefer fail-closed refusal over partially migrated state that
cannot be explained or reversed.

## Idempotency Contract

Two idempotency keys are required:

- `plan_idempotency_key`: digest of connector id + source version + target
  version + ordered step digests
- `step_idempotency_key`: digest of `plan_idempotency_key` + `step_id` +
  `pre_state_hash`

Replaying a fully applied plan returns `already_applied` only when:

- the migration journal proves each step committed previously
- the current state hash matches the recorded final hash
- the current schema version matches the plan target version

If the target version matches but the journal or hashes do not, the executor
must fail with a divergence error rather than silently accepting the state.

## Receipt Contract

The current `MigrationReceipt` in `schema_migration.rs` is a scaffold. The live
executor receipt required by `bd-2fqyv.6.2` must expand to include at least:

- `receipt_schema_version`
- `receipt_id`
- `connector_id`
- `plan_id`
- `plan_idempotency_key`
- `from_version`
- `to_version`
- `started_at`
- `completed_at`
- `outcome`
- `initial_state_hash`
- `final_state_hash`
- `steps_total`
- `steps_applied`
- `steps_already_applied`
- `steps_rolled_back`
- `journal_record_ids`
- `rollback_result`
- `error_code`
- `error_detail`
- `step_results: Vec<MigrationStepResult>`

Each `MigrationStepResult` must carry:

- `step_id`
- `from_version`
- `to_version`
- `status` (`applied`, `already_applied`, `rolled_back`, `failed`)
- `step_idempotency_key`
- `pre_state_hash`
- `post_state_hash`
- `checkpoint_ref` or equivalent rollback provenance
- `journal_record_id`
- `error_detail` when status is `failed`

These fields are the minimum needed to:

- prove real connector mutations occurred
- reconstruct partial-application/rollback history
- bridge cleanly into `MigrationArtifact` and pipeline-level receipts
- support deterministic replay and conformance testing

## Persistence Requirements

Every successfully applied step must emit a persisted journal row consistent
with `SchemaMigrationRecord` ownership under
`storage/models.rs::SchemaMigrationRecord`.

At minimum, persisted execution evidence must record:

- a stable migration or step identifier
- source and target versions
- commit timestamp
- deterministic checksum or state hash
- whether the step remained reversible at commit time

The executor must not emit an `Applied` plan receipt unless the journal and the
final state hash agree.

## Required Verification For `bd-2fqyv.6.2`

Minimum coverage for the implementation bead:

- chain validation rejects disconnected step sequences before any mutation
- idempotent re-run succeeds only when journal + hashes match
- version-only matches without journal/hash evidence fail closed
- `rollback_safe = false` steps are refused by the live executor
- mid-plan failure rolls back already-applied earlier steps in reverse order
- rollback failure yields explicit `MIGRATION_ROLLBACK_FAILED` evidence
- successful execution emits complete per-step receipt data and persisted journal
  rows
- identical input state + identical plan produce byte-identical receipt payloads

## Non-Goals

- This contract does not widen the current operator-facing `migrate audit`,
  `migrate rewrite`, or `migrate validate` CLI behavior into a general data
  migration engine yet.
- This contract does not require the low-level schema executor to own final
  signature policy; it requires enough evidence-bearing fields that higher-level
  signed receipts cannot fabricate missing execution facts.
