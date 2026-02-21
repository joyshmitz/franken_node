# bd-3agp Contract: >=3x Migration Velocity Gate

## Goal

Enforce a concrete release gate requiring migration velocity improvement of
`>= 3x` versus baseline/manual migration across a representative cohort.

## Quantified Invariants

- `INV-MVG-RATIO`: Aggregate velocity ratio is `>= 3.0x`, computed as
  `sum(manual_migration_minutes) / sum(tooled_migration_minutes)`.
- `INV-MVG-COHORT-SIZE`: Cohort includes at least `10` projects.
- `INV-MVG-ARCHETYPES`: Cohort contains all required archetypes:
  - `express_app`
  - `fastify_app`
  - `nextjs_app`
  - `cli_tool`
  - `library_package`
  - `worker_service`
  - `websocket_server`
  - `monorepo`
  - `native_addons_partial`
  - `custom_build_pipeline`
- `INV-MVG-E2E`: Every project record includes start/end timestamps and a
  first-passing-test timestamp for end-to-end measurement.
- `INV-MVG-DOC`: Every project record includes manual intervention points and
  blockers encountered.
- `INV-MVG-CI-SAMPLE`: At least `3` cohort projects are flagged for release CI
  sampling.
- `INV-MVG-DETERMINISM`: Reordering cohort entries does not change aggregate
  ratio or verdict.

## Required Data Contract

`artifacts/13/migration_velocity_report.json` must include:

- Metadata:
  - `bead_id`
  - `generated_at_utc`
  - `measurement_unit` (`minutes`)
  - `trace_id`
- Cohort summary:
  - `required_velocity_ratio`
  - `overall_velocity_ratio`
  - `total_manual_minutes`
  - `total_tooled_minutes`
  - `cohort_size`
- Project entries (`projects[]`) with required fields:
  - `project_id`
  - `archetype`
  - `start_time_utc`
  - `end_time_utc`
  - `first_passing_test_time_utc`
  - `manual_migration_minutes`
  - `tooled_migration_minutes`
  - `manual_intervention_points` (list)
  - `blockers_encountered` (list)
  - `ci_release_sample` (boolean)

## Required Scenarios

1. **Pass scenario**: representative cohort meets `>= 3.0x` aggregate ratio.
2. **Threshold-fail scenario**: aggregate ratio drops below `3.0x` and gate
   blocks.
3. **Coverage-fail scenario**: missing required archetype blocks gate.
4. **Sampling-fail scenario**: fewer than 3 CI sample projects blocks gate.
5. **Determinism scenario**: shuffled cohort yields identical ratio/verdict.

## Structured Event Codes

- `MVG-001`: Velocity metrics computed.
- `MVG-002`: Velocity gate passed (`>= 3x`).
- `MVG-003`: Velocity gate failed (`< 3x`).
- `MVG-004`: Cohort coverage violation (size/archetypes/docs).
- `MVG-005`: CI sampling violation.
- `MVG-006`: Determinism validation executed.

All events include a stable `trace_id`.

## Gate Decision Flow

1. Load and validate `migration_velocity_report.json`.
2. Verify cohort size and archetype coverage.
3. Validate end-to-end timing and documentation fields per project.
4. Compute aggregate velocity ratio.
5. Verify release CI sample coverage (`>= 3` projects).
6. Verify determinism under reordered project lists.
7. Emit structured events and pass/fail verdict.
