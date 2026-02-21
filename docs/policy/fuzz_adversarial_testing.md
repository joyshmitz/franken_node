# Fuzz and Adversarial Testing Policy

**Bead:** bd-1ul
**Section:** 10.7 -- Conformance and Verification
**Last updated:** 2026-02-20

## 1. Overview

This policy governs fuzz and adversarial testing for security-critical attack
surfaces in the franken_node project, specifically the migration scanner and
compatibility shim layers. All fuzz testing must follow the structured corpus
management, regression preservation, and CI gate integration defined here.

## 2. Fuzz Target Requirements

### 2.1 Mandatory Targets

Every security-critical input parser must have at least one fuzz target. The
following are mandatory:

| Domain               | Target                         | Minimum Budget |
|----------------------|--------------------------------|----------------|
| Migration scanner    | `fuzz_migration_directory_scan` | 60 seconds     |
| Migration scanner    | `fuzz_migration_package_parse`  | 60 seconds     |
| Migration scanner    | `fuzz_migration_dependency_resolve` | 60 seconds |
| Compatibility shim   | `fuzz_shim_api_translation`     | 60 seconds     |
| Compatibility shim   | `fuzz_shim_type_coercion`       | 60 seconds     |

### 2.2 Target Registration

New fuzz targets must be registered in `fuzz/config/fuzz_budget.toml` before
they are considered active. Unregistered targets do not count toward CI gate
compliance.

### 2.3 Target Implementation

Fuzz targets may be implemented using:

- `cargo-fuzz` / `libFuzzer` for Rust code paths
- Structured Python fuzzers (e.g., `hypothesis`) for Python verification code
- Property-based test generators for deterministic adversarial input creation

## 3. Corpus Management Policy

### 3.1 Seed Quality

Corpus seeds must be categorized by adversarial intent:

| Category           | Proportion | Purpose                                      |
|--------------------|------------|----------------------------------------------|
| Valid baseline     | 10%        | Establish correct behavior under normal input |
| Boundary values    | 20%        | Test integer overflow, empty, max-length      |
| Malformed structure| 30%        | Broken formats, wrong types, missing fields   |
| Adversarial payload| 40%        | Path traversal, injection, resource exhaust   |

### 3.2 Minimum Corpus Size

Each corpus directory must contain at least 50 seed inputs. This minimum is
enforced by the CI gate and verified by the check script.

### 3.3 Corpus Growth

The corpus is expected to grow as fuzzing discovers new code paths. Coverage
regression (coverage decrease) triggers a warning. Teams are expected to add
new seeds when new code paths are introduced.

## 4. Regression Seed Management

### 4.1 Preservation

Regression seeds are PERMANENT. Once a crash-triggering input is minimized and
added to `fuzz/regression/`, it must never be deleted unless the associated
code path is entirely removed from the codebase.

### 4.2 Triage Workflow

1. Fuzz run discovers a crash (FZT-003 event emitted)
2. Input is automatically saved to a timestamped file in `fuzz/regression/`
3. Developer triages the crash: fix the bug, add the regression seed
4. Fix PR must include the regression seed and a Rust `#[test]` reproducer
5. Regression seed is verified on every subsequent CI run

### 4.3 Regression Seed Naming

```
fuzz/regression/{domain}/crash_{timestamp}_{hash8}.bin
```

Where `{hash8}` is the first 8 characters of the SHA-256 hash of the input.

## 5. CI Gate Integration

### 5.1 Gate Position

The fuzz health gate runs after unit tests and before integration tests in the
CI pipeline.

### 5.2 Budget Enforcement

The gate reads `fuzz/config/fuzz_budget.toml` and verifies:

- Each registered target ran for at least `min_seconds_per_target`
- The total fuzz wall-clock time meets the aggregate budget
- All regression seeds were executed without crashes

### 5.3 Failure Handling

On gate failure:
- The crashing input is preserved in `fuzz/regression/`
- A structured JSON report is written to `artifacts/`
- The CI pipeline is blocked until the crash is triaged

## 6. Coverage Tracking

### 6.1 Coverage Reports

Each fuzz run produces a JSON coverage report containing:
- Target name, corpus size, lines covered, coverage percentage
- New paths discovered, crashes found, wall-clock time
- Event code FZT-004

### 6.2 Coverage Baselines

Coverage baselines are stored in `fuzz/coverage/` and updated on each
successful fuzz run. A coverage regression of > 2% triggers a warning.

## 7. Structured Logging

All fuzz activity is logged with structured JSON events using the event codes
defined in the spec contract (FZT-001 through FZT-004). Logs include:

- `event_code`: One of FZT-001, FZT-002, FZT-003, FZT-004
- `target`: Fuzz target name
- `session_id`: Unique session identifier
- `trace_id`: Distributed trace identifier
- `timestamp`: ISO 8601 timestamp

## 8. E2E Test Requirements

End-to-end fuzz workflow tests must:

1. Execute from clean fixtures (empty corpus directory)
2. Populate corpus with seed inputs
3. Run fuzz session for minimum budget
4. Verify no crashes discovered on clean inputs
5. Inject a known-bad input and verify crash detection
6. Verify regression seed auto-preservation
7. Emit deterministic machine-readable pass/fail evidence
8. Capture stepwise structured logs for root-cause triage

## 9. Review and Update

This policy is reviewed when:
- New fuzz targets are added
- Coverage baselines are adjusted
- Fuzz budget parameters are changed
- New adversarial input categories are identified
