# Migration Cohort Definition (bd-sxt5)

## Purpose

This document defines the deterministic migration-validation cohort used by
`bd-sxt5` (Section 15 adoption target). The cohort is designed to prove that
`franken-node` migration audit/rewrite/lockstep flows can be run repeatedly with
stable outcomes across diverse real-world Node.js/Bun archetypes.

The canonical machine-readable results for this cohort are stored at:

- `artifacts/15/migration_cohort_results.json`

The deterministic E2E verifier for this cohort is:

- `tests/e2e/migration_cohort_validation.sh`

## Cohort Composition

The cohort contains 10 projects (minimum required: 10), covering all required
archetypes from the bead acceptance contract.

| Project ID | Runtime | Archetype | Notes |
|---|---|---|---|
| `cohort-express-api-001` | Node.js | web server (Express) | API-heavy service surface |
| `cohort-nextjs-ssr-001` | Node.js | SSR app (Next.js) | SSR + route handlers |
| `cohort-cli-tooling-001` | Node.js | CLI tool | Packaging and argument handling |
| `cohort-lib-utils-001` | Node.js | library | Published reusable package |
| `cohort-bun-worker-001` | Bun | worker | Queue/background worker |
| `cohort-monorepo-turbo-001` | Node.js | monorepo | Multi-package workspace |
| `cohort-native-addon-001` | Node.js | native addon | Rust/C++ bridge surface |
| `cohort-ts-heavy-001` | Node.js | TypeScript-heavy | Strict TS + advanced types |
| `cohort-test-heavy-001` | Node.js | test-heavy | Large test suite focus |
| `cohort-minimal-001` | Bun | minimal | Small baseline project |

Each project is version-pinned (`repo` + `commit`) in
`artifacts/15/migration_cohort_results.json`.

## Deterministic Validation Workflow

For each cohort project:

1. Capture **pre-migration baseline** test result snapshot.
2. Run migration **audit**.
3. Run migration **rewrite** with rollback artifact generation.
4. Run post-rewrite **lockstep validation**.
5. Capture **post-migration** test results.
6. Repeat post-migration validation runs to confirm flaky rate `< 1%`.

All stages emit stable artifacts (audit/rewrite/rollback/lockstep paths) in the
results JSON so CI/release gates can consume evidence without manual lookup.

## Success Thresholds

The cohort must satisfy all of the following:

- `cohort_size >= 10`
- `per_project`: `pass_rate >= 95%` OR failures are documented as known incompatibilities
- `cohort_success_rate >= 80%`
- `max_flaky_rate_pct < 1.0`
- Deterministic replay flags: `determinism_verified == true`, `ci_reproducible == true`

These thresholds are enforced by `tests/e2e/migration_cohort_validation.sh`.

## Refresh Policy

The cohort is refreshed at least once per major release:

- Add/rotate projects if ecosystem mix changes materially.
- Update pinned refs and rerun the deterministic validation pipeline.
- Recompute aggregate metrics and refresh artifacts under `artifacts/15/`.

## Structured Logging

The validation script emits JSONL logs at:

- `artifacts/15/migration_cohort_validation_log.jsonl`

Event codes:

- `MCV-001`: validation started
- `MCV-002`: check passed
- `MCV-003`: check failed
- `MCV-004`: validation completed

