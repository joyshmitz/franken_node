# bd-80g: Reference Capture Programs & Fixture Corpora

## Decision Rationale

The L1 lockstep oracle requires a comprehensive fixture corpus to measure compatibility. Reference capture programs generate these fixtures by executing API calls against Node.js and Bun, capturing inputs, outputs, and side effects as deterministic JSON fixtures.

## Scope

Build prioritized Node/Bun reference capture programs and fixture corpora per API band (CLI/process/fs/network/module/tooling).

## Architecture

### Capture Program Design

```
┌────────────────────────┐
│  Capture Orchestrator   │  ← Python: manages runs, validates output
├────────────────────────┤
│  Capture Templates (JS) │  ← Per-API scripts run against Node/Bun
├────────────────────────┤
│  Fixture Generator      │  ← Produces schema-valid JSON from captures
├────────────────────────┤
│  Corpus Validator       │  ← Validates corpus completeness per band
└────────────────────────┘
```

### Capture Template Structure

Each capture template is a JS file in `scripts/captures/` that:
1. Sets up preconditions (temp files, env vars, etc.)
2. Executes the target API
3. Captures return value, error, and side effects
4. Outputs structured JSON to stdout
5. Cleans up preconditions

### Fixture Corpus Organization

```
docs/fixtures/
├── core/           ← Phase 1: release-blocking
│   ├── fs/
│   ├── path/
│   ├── process/
│   └── buffer/
├── high_value/     ← Phase 2: ≥95% target
│   ├── http/
│   └── crypto/
├── edge/           ← Phase 3: best-effort
└── minimized/      ← Auto-generated regression fixtures
```

## Invariants

1. Every fixture validates against `schemas/compatibility_fixture.schema.json`.
2. Every capture template is idempotent and deterministic.
3. Fixture IDs follow the pattern `fixture:<family>:<api>:<scenario>`.
4. Core band fixtures exist for every API in the compatibility registry.
5. Corpus coverage is tracked per band with release gate thresholds.
6. Each fixture records its oracle source (runtime + version).

## Prioritization

| Phase | Band | Target Coverage | Release Gate |
|-------|------|----------------|--------------|
| 1 (Alpha) | core | ≥ 3 fixtures per API | 100% pass |
| 2 (Beta) | high-value | ≥ 3 fixtures per API | ≥ 95% pass |
| 3 (GA) | edge | ≥ 1 fixture per API | Best-effort |

## References

- [COMPATIBILITY_BANDS.md](../../COMPATIBILITY_BANDS.md)
- [COMPATIBILITY_REGISTRY.json](../../COMPATIBILITY_REGISTRY.json)
- [compatibility_fixture.schema.json](../../../schemas/compatibility_fixture.schema.json)
