# bd-1ul: Fuzz and Adversarial Tests for Migration and Shim Logic

**Bead:** bd-1ul
**Section:** 10.7 -- Conformance and Verification
**Last updated:** 2026-02-20

## 1. Purpose

Migration scanning and compatibility shim logic are security-critical attack
surfaces. The migration scanner processes untrusted project structures (arbitrary
directory trees, malformed `package.json` files, adversarial dependency graphs),
and the compatibility shim translates between runtime APIs where type confusion
or unexpected inputs could bypass policy enforcement.

This contract defines the fuzz testing strategy, structured corpus management,
regression seed preservation, CI gate integration, and coverage tracking for
both the migration scanner and compatibility shim layers.

## 2. Scope

| Target Domain       | Entry Points                                                |
|----------------------|-------------------------------------------------------------|
| Migration scanner    | Directory scan, `package.json` parse, dependency resolution |
| Compatibility shim   | API translation, type coercion                              |

## 3. Event Codes

| Code    | Meaning                                  | Emitted When                                        |
|---------|------------------------------------------|-----------------------------------------------------|
| FZT-001 | Fuzz session started                     | A fuzz target begins execution                      |
| FZT-002 | Fuzz corpus seed executed                | A corpus seed completes without crash               |
| FZT-003 | Fuzz crash discovered                    | An input triggers panic, OOM, or hang               |
| FZT-004 | Fuzz coverage checkpoint                 | Coverage metrics captured at end of fuzz session     |

## 4. Invariants

| Invariant         | Statement                                                                    |
|-------------------|------------------------------------------------------------------------------|
| INV-FZT-CORPUS    | Structured corpus directories exist with >= 50 seed inputs each              |
| INV-FZT-REGRESS   | Regression seeds in `fuzz/regression/` are permanent and run on every build  |
| INV-FZT-BUDGET    | CI fuzz health gate enforces minimum time budget (default 60s per target)    |
| INV-FZT-COVERAGE  | Fuzz coverage monotonically increases as corpus grows; regressions warn      |
| INV-FZT-TRIAGE    | New crash-triggering inputs are auto-added to the regression seed set        |

## 5. Fuzz Target Definitions

### 5.1 Migration Scanner Targets

**fuzz_migration_directory_scan** -- Feeds adversarial directory structures to the
migration scanner. Covers deeply nested paths, path traversal attempts,
symlink loops, and pathological filenames (null bytes, unicode edge cases,
oversized names).

**fuzz_migration_package_parse** -- Feeds malformed `package.json` data to the
migration scanner's package parser. Covers invalid JSON, unexpected types in
dependency fields, circular references, oversized files (memory exhaustion),
and encoding edge cases (BOM, mixed encodings).

**fuzz_migration_dependency_resolve** -- Feeds adversarial dependency trees to the
dependency resolver. Covers diamond dependencies, version conflicts, impossible
constraint sets, and pathologically deep dependency chains.

### 5.2 Compatibility Shim Targets

**fuzz_shim_api_translation** -- Feeds adversarial API call inputs to the shim
translation layer. Covers type confusion (objects where primitives expected),
boundary values (`MAX_SAFE_INTEGER + 1`, empty strings, null), and encoding
edge cases (surrogate pairs, overlong UTF-8).

**fuzz_shim_type_coercion** -- Feeds adversarial type coercion inputs to the shim
type coercion logic. Covers policy bypass attempts (crafted inputs that skip
validation), mixed-type arrays, and nested object depth attacks.

## 6. Corpus Management

### 6.1 Directory Structure

```
fuzz/
  corpus/
    migration/       # >= 50 seed inputs for migration fuzz targets
    shim/            # >= 50 seed inputs for shim fuzz targets
  regression/
    migration/       # Permanent regression seeds for migration
    shim/            # Permanent regression seeds for shim
  targets/
    migration_directory_scan.rs
    migration_package_parse.rs
    migration_dependency_resolve.rs
    shim_api_translation.rs
    shim_type_coercion.rs
  config/
    fuzz_budget.toml
  coverage/
    latest_migration.json
    latest_shim.json
```

### 6.2 Seed Requirements

Each corpus directory must contain at least 50 seed inputs covering:

- **Valid baseline inputs** (10%): Known-good inputs to establish baseline behavior
- **Boundary values** (20%): Edge cases for integer overflow, empty collections, max lengths
- **Malformed structure** (30%): Broken JSON, missing fields, wrong types
- **Adversarial payloads** (40%): Path traversal, injection attempts, resource exhaustion

### 6.3 Regression Seed Lifecycle

1. New crash-triggering input discovered during fuzz run
2. Input is minimized to smallest reproducer
3. Minimized input is copied to `fuzz/regression/{domain}/`
4. Input is committed to version control
5. Regression input runs on every CI build as a deterministic test
6. Regression input is NEVER removed unless the associated code path is deleted

## 7. CI Fuzz Health Gate

### 7.1 Budget Configuration

Budget is configured in `fuzz/config/fuzz_budget.toml`:

```toml
[migration]
min_seconds_per_target = 60
targets = ["directory_scan", "package_parse", "dependency_resolve"]

[shim]
min_seconds_per_target = 60
targets = ["api_translation", "type_coercion"]
```

### 7.2 Gate Pass/Fail Criteria

The CI gate **passes** when:
- All fuzz targets ran for at least the budgeted minimum time
- No new crashes were discovered (zero new entries in crash log)
- All regression seeds executed without crash

The CI gate **fails** when:
- Any fuzz target ran for less than the budgeted time
- A new crash was discovered (crashing input is preserved in regression set)
- Any regression seed triggered a crash

## 8. Coverage Tracking

### 8.1 Coverage Report Structure

```json
{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "migration_directory_scan",
  "corpus_size": 52,
  "lines_covered": 342,
  "lines_total": 400,
  "coverage_pct": 85.5,
  "new_paths_found": 3,
  "event_code": "FZT-004"
}
```

### 8.2 Coverage Regression Detection

Coverage percentage is tracked per target. If coverage decreases between
consecutive runs (new code added without corresponding corpus expansion), a
warning event (FZT-004 with `regression: true`) is emitted.

## 9. Structured Log Format

Each fuzz session emits structured JSON logs:

```json
{
  "event_code": "FZT-001",
  "target": "migration_package_parse",
  "session_id": "fuzz-20260220-abc123",
  "seeds_executed": 52,
  "new_paths_found": 7,
  "crashes_found": 0,
  "coverage_pct": 82.3,
  "wall_clock_seconds": 62.4,
  "trace_id": "trace-fuzz-001"
}
```

## 10. Acceptance Criteria Traceability

| AC# | Requirement                                                | Invariant       |
|-----|------------------------------------------------------------|-----------------|
| AC1 | Fuzz targets for migration (>= 3) and shim (>= 2)        | INV-FZT-CORPUS  |
| AC2 | Corpus dirs with >= 50 seeds each                          | INV-FZT-CORPUS  |
| AC3 | Regression seeds permanent and run on every build          | INV-FZT-REGRESS |
| AC4 | CI fuzz health gate with configurable budget               | INV-FZT-BUDGET  |
| AC5 | Auto-add crash inputs to regression set                    | INV-FZT-TRIAGE  |
| AC6 | Coverage reports per fuzz run                              | INV-FZT-COVERAGE|
| AC7 | Verification script with --json flag                       | --              |
| AC8 | Unit tests for verification script                         | --              |

## 11. Dependencies

| Dependency                     | Bead   | Section |
|-------------------------------|--------|---------|
| Migration scanner             | 10.3   | 10.3    |
| Compatibility shims           | 10.2   | 10.2    |
| Fuzz corpus infrastructure    | bd-3n2u| 10.13   |
