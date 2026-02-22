# bd-3j4 Contract: End-to-End Migration Singularity Pipeline for Pilot Cohorts

**Bead:** bd-3j4
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane
**Schema:** gate-v1.0

## Overview

Implement a MigrationSingularityPipeline module that orchestrates the full
migration lifecycle as a deterministic, restartable state machine with stages:

INTAKE -> ANALYSIS -> PLAN_GENERATION -> PLAN_REVIEW -> EXECUTION ->
VERIFICATION -> RECEIPT_ISSUANCE -> COMPLETE

ROLLBACK is reachable from any post-INTAKE stage.

## Data Model

### PipelineStage

Enum representing each stage of the migration pipeline.

| Variant          | Label             | Terminal | Rollback-able |
|------------------|-------------------|----------|---------------|
| Intake           | INTAKE            | No       | No            |
| Analysis         | ANALYSIS          | No       | Yes           |
| PlanGeneration   | PLAN_GENERATION   | No       | Yes           |
| PlanReview       | PLAN_REVIEW       | No       | Yes           |
| Execution        | EXECUTION         | No       | Yes           |
| Verification     | VERIFICATION      | No       | Yes           |
| ReceiptIssuance  | RECEIPT_ISSUANCE  | No       | Yes           |
| Complete         | COMPLETE          | Yes      | No            |
| Rollback         | ROLLBACK          | Yes      | No            |

### PipelineState

| Field                  | Type                            | Description                        |
|------------------------|---------------------------------|------------------------------------|
| `current_stage`        | `PipelineStage`                 | Current pipeline stage             |
| `cohort_id`            | `String`                        | Cohort identifier                  |
| `extensions`           | `BTreeMap<String, String>`      | Extension state map                |
| `stage_history`        | `Vec<StageTransition>`          | Transition records                 |
| `started_at`           | `String`                        | RFC 3339 start timestamp           |
| `idempotency_key`      | `String`                        | Deterministic idempotency key      |
| `schema_version`       | `String`                        | Schema version (pipe-v1.0)         |
| `compatibility_report` | `Option<CompatibilityReport>`   | Analysis results                   |
| `migration_plan`       | `Option<MigrationPlan>`         | Generated migration plan           |
| `execution_traces`     | `Vec<ExecutionTrace>`           | Execution records                  |
| `verification_report`  | `Option<VerificationReport>`    | Verification results               |
| `migration_receipt`    | `Option<MigrationReceipt>`      | Signed migration receipt           |

### CohortDefinition

| Field                | Type                  | Description                          |
|----------------------|-----------------------|--------------------------------------|
| `cohort_id`          | `String`              | Unique cohort identifier             |
| `extensions`         | `Vec<ExtensionSpec>`  | Extensions in the cohort             |
| `selection_criteria`  | `String`              | Cohort selection criteria            |

### ExtensionSpec

| Field                  | Type     | Description                          |
|------------------------|----------|--------------------------------------|
| `name`                 | `String` | Extension name                       |
| `source_version`       | `String` | Source version (pre-migration)       |
| `target_version`       | `String` | Target version (post-migration)      |
| `dependency_complexity` | `u32`    | Dependency complexity score          |
| `risk_tier`            | `u32`    | Risk tier (1=low, 2=medium, 3=high)  |

### CompatibilityReport

| Field                    | Type                       | Description                     |
|--------------------------|----------------------------|---------------------------------|
| `per_extension_results`  | `BTreeMap<String, bool>`   | Per-extension pass/fail         |
| `blockers`               | `Vec<String>`              | Blocking issues                 |
| `overall_pass_rate`      | `f64`                      | Overall pass rate [0,1]         |

### MigrationPlan

| Field           | Type                       | Description                        |
|-----------------|----------------------------|------------------------------------|
| `plan_id`       | `String`                   | Deterministic plan identifier      |
| `steps`         | `Vec<TransformationStep>`  | Ordered transformation steps       |
| `risk_score`    | `f64`                      | Aggregate risk score               |
| `rollback_spec` | `String`                   | Rollback specification             |

### TransformationStep

| Field             | Type              | Description                        |
|-------------------|-------------------|------------------------------------|
| `action`          | `TransformAction` | ApiShim, PolyfillInjection, or DependencyRewire |
| `target`          | `String`          | Target resource or extension       |
| `pre_state_hash`  | `String`          | Pre-transformation state hash      |
| `post_state_hash` | `String`          | Post-transformation state hash     |

### ExecutionTrace

| Field               | Type           | Description                        |
|---------------------|----------------|------------------------------------|
| `extension_name`    | `String`       | Extension being migrated           |
| `state_transitions` | `Vec<String>`  | State transition records           |
| `mutations`         | `Vec<String>`  | Mutations applied                  |
| `duration_ms`       | `u64`          | Execution duration in ms           |

### VerificationReport

| Field                    | Type                       | Description                     |
|--------------------------|----------------------------|---------------------------------|
| `pass_rate`              | `f64`                      | Overall pass rate [0,1]         |
| `per_extension_results`  | `BTreeMap<String, bool>`   | Per-extension results           |
| `meets_threshold`        | `bool`                     | Whether 95% threshold is met    |

### MigrationReceipt

| Field                  | Type     | Description                          |
|------------------------|----------|--------------------------------------|
| `pre_migration_hash`   | `String` | SHA-256 hash of pre-migration state  |
| `plan_fingerprint`     | `String` | Migration plan fingerprint           |
| `post_migration_hash`  | `String` | SHA-256 hash of post-migration state |
| `verification_summary` | `String` | Verification results summary         |
| `rollback_proof`       | `String` | Proof of rollback availability       |
| `signature`            | `String` | Cryptographic signature              |
| `timestamp`            | `String` | RFC 3339 timestamp                   |

### CohortSummary

| Field                    | Type   | Description                           |
|--------------------------|--------|---------------------------------------|
| `throughput`             | `f64`  | Extensions per second                 |
| `success_rate`           | `f64`  | Success fraction [0,1]                |
| `mean_time_to_migrate_ms`| `u64`  | Mean migration time in ms             |
| `rollback_rate`          | `f64`  | Rollback fraction [0,1]               |

## Pipeline Operations

- `new(cohort) -> Result<PipelineState, PipelineError>`: Create new pipeline.
- `advance(state) -> Result<PipelineState, PipelineError>`: Advance to next stage.
- `rollback(state) -> Result<PipelineState, PipelineError>`: Trigger rollback.
- `is_idempotent(state, state) -> bool`: Verify idempotency.
- `run_full_pipeline(cohort) -> Result<PipelineState, PipelineError>`: Run all stages.
- `compute_cohort_summary(state) -> CohortSummary`: Compute cohort metrics.

## Invariants

- **INV-PIPE-DETERMINISTIC** -- Same cohort input produces identical pipeline traces.
- **INV-PIPE-IDEMPOTENT** -- Re-advancing from a given state yields the same result.
- **INV-PIPE-THRESHOLD-ENFORCED** -- Verification must reach 95% pass rate to proceed.
- **INV-PIPE-ROLLBACK-ANY-STAGE** -- Rollback is reachable from any post-INTAKE stage.
- **INV-PIPE-RECEIPT-SIGNED** -- Every migration receipt carries a non-empty signature.
- **INV-PIPE-STAGE-MONOTONIC** -- Stage transitions are strictly forward (except rollback).

## Event Codes

| Code     | Severity | Description                                |
|----------|----------|--------------------------------------------|
| PIPE-001 | INFO     | Pipeline stage entered                     |
| PIPE-002 | INFO     | Pipeline stage exited                      |
| PIPE-003 | WARN     | Analysis blocker found                     |
| PIPE-004 | INFO     | Plan generated                             |
| PIPE-005 | INFO     | Execution step completed                   |
| PIPE-006 | INFO     | Execution idempotency check                |
| PIPE-007 | INFO     | Verification passed                        |
| PIPE-008 | ERROR    | Verification failed                        |
| PIPE-009 | INFO     | Receipt issued                             |
| PIPE-010 | INFO     | Receipt verified                           |
| PIPE-011 | WARN     | Rollback initiated                         |
| PIPE-012 | INFO     | Rollback complete                          |
| PIPE-013 | INFO     | Cohort summary generated                   |

## Error Codes

| Code                         | Description                              |
|------------------------------|------------------------------------------|
| ERR_PIPE_INVALID_TRANSITION  | Invalid stage transition attempted       |
| ERR_PIPE_VERIFICATION_FAILED | Verification stage failed                |
| ERR_PIPE_IDEMPOTENCY_VIOLATED| Idempotency invariant violated           |
| ERR_PIPE_ROLLBACK_FAILED     | Rollback operation failed                |
| ERR_PIPE_THRESHOLD_NOT_MET   | 95% verification threshold not met       |
| ERR_PIPE_DUPLICATE_EXTENSION | Duplicate extension in cohort            |

## Acceptance Criteria

1. PipelineStage enum with all 9 variants in `crates/franken-node/src/connector/migration_pipeline.rs`.
2. PipelineState struct with deterministic BTreeMap-based extensions.
3. CohortDefinition, ExtensionSpec, CompatibilityReport, MigrationPlan, TransformationStep,
   ExecutionTrace, VerificationReport, MigrationReceipt, CohortSummary structs defined.
4. Pipeline operations: new, advance, rollback, is_idempotent.
5. 95% verification threshold enforcement.
6. Event codes PIPE-001 through PIPE-013 defined in event_codes module.
7. Error codes ERR_PIPE_* defined in error_codes module.
8. Invariants INV-PIPE-* defined in invariants module.
9. Schema version "pipe-v1.0" constant.
10. Serde round-trip for all types.
11. >= 25 unit tests covering all invariants and pipeline paths.
12. Module wired into connector/mod.rs.

## Dependencies

- **10.12** (ecosystem fabric) -- pipeline operates within the ecosystem.
- **bd-3hm** (migration artifact) -- receipts follow artifact contract conventions.

## Artifacts

| Artifact                    | Path                                                              |
|-----------------------------|-------------------------------------------------------------------|
| Rust implementation         | `crates/franken-node/src/connector/migration_pipeline.rs`         |
| Spec contract               | `docs/specs/section_10_12/bd-3j4_contract.md`                    |
| Gate script                 | `scripts/check_migration_pipeline.py`                             |
| Test file                   | `tests/test_check_migration_pipeline.py`                          |
| Verification evidence       | `artifacts/section_10_12/bd-3j4/verification_evidence.json`       |
| Verification summary        | `artifacts/section_10_12/bd-3j4/verification_summary.md`          |
