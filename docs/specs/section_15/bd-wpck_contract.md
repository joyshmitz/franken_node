# bd-wpck — Migration Kit Ecosystem for Major Node/Bun Archetypes

**Section:** 15 — Supply-chain integrity
**Bead:** bd-wpck
**Status:** Implementation
**Depends on:** bd-209w (Signed extension registry)

## Overview

Provides structured migration kits for five major Node.js and Bun application
archetypes (Express, Fastify, Koa, Next.js, Bun Native), enabling deterministic
migration from established runtimes to franken_node. Each kit includes compatibility
mappings, step-by-step procedures with dependency tracking, rollback procedures,
progress tracking, and report generation.

## Archetypes

| Archetype   | Label        | Complexity range |
|-------------|-------------|-----------------|
| Express     | `express`    | Low–Critical     |
| Fastify     | `fastify`    | Low–Critical     |
| Koa         | `koa`        | Low–Critical     |
| Next.js     | `nextjs`     | Low–Critical     |
| Bun Native  | `bun_native` | Low–Critical     |

## Migration Phases

1. **Assessment** — Evaluate application compatibility
2. **DependencyAudit** — Audit all dependencies for franken_node compatibility
3. **CodeAdaptation** — Adapt imports and API calls
4. **TestValidation** — Run test suites against franken_node runtime
5. **Deployment** — Deploy adapted application

## Capabilities

- **Kit loading**: `load_kit` with compatibility gate (minimum API coverage enforced)
- **Plan generation**: `generate_plan` with deterministic content hashing
- **Step management**: `start_step`, `complete_step` with progress tracking
- **Rollback**: `rollback_step` with safety check (procedure must exist)
- **Report generation**: `generate_report` with status/progress computation
- **Audit logging**: All operations logged; JSONL export via `export_audit_log_jsonl`

## Event Codes

| Code         | Description                         |
|-------------|-------------------------------------|
| MKE-001     | Kit loaded for archetype            |
| MKE-002     | Compatibility check passed          |
| MKE-003     | Migration plan generated            |
| MKE-004     | Migration step started              |
| MKE-005     | Migration step completed            |
| MKE-006     | Full migration completed            |
| MKE-007     | Rollback initiated                  |
| MKE-008     | Rollback completed                  |
| MKE-009     | Completion gate passed              |
| MKE-010     | Progress report generated           |
| MKE-ERR-001 | Compatibility check failed          |
| MKE-ERR-002 | Step execution failed               |
| MKE-ERR-003 | Rollback failed (no procedure)      |

## Invariants

| ID                    | Rule                                                  |
|-----------------------|-------------------------------------------------------|
| INV-MKE-COMPLETE      | Every kit covers all required migration phases         |
| INV-MKE-REVERSIBLE    | Every migration step has a rollback procedure          |
| INV-MKE-GATED         | Migration blocked if compatibility check fails         |
| INV-MKE-DETERMINISTIC | Same archetype + steps produces same content hash      |
| INV-MKE-AUDITABLE     | Every migration operation logged with event code       |
| INV-MKE-VERSIONED     | Kit version embedded in every migration plan           |

## Types

- `Archetype` — 5-variant enum
- `MigrationPhase` — 5-variant enum
- `StepStatus` — 5-variant enum (Pending, InProgress, Completed, Failed, RolledBack)
- `MigrationComplexity` — 4-variant enum (Low, Medium, High, Critical)
- `MigrationStatus` — 5-variant enum
- `MigrationStep` — Step with phase, deps, rollback procedure
- `CompatibilityMapping` — Per-archetype compatibility data
- `MigrationKit` — Complete kit with steps and content hash
- `MigrationReport` — Progress report with status computation
- `MkeAuditRecord` — Audit record with event code
- `MkeConfig` — Configuration (version, coverage threshold)
- `MigrationKitEcosystem` — Engine managing kits, reports, audit log

## Verification

- Gate script: `scripts/check_migration_kit.py`
- Tests: `tests/test_check_migration_kit.py`
- Min inline tests: 26
