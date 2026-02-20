# bd-2a0: Project Scanner for API/Runtime/Dependency Risk Inventory

## Decision Rationale

Before migrating a project to franken_node, operators need a clear inventory of what APIs, runtimes, and dependencies the project uses, and what migration risks each poses. The project scanner automates this audit, producing a structured risk inventory that feeds the migration confidence report and rollout planner.

## Scope

Build a project scanner that:
1. Scans JS/TS source files for Node.js/Bun API usage
2. Analyzes package.json dependencies for native addon risk
3. Maps detected APIs to compatibility bands and implementation status
4. Produces a structured risk inventory JSON report

## Architecture

```
┌──────────────────────────┐
│     Project Scanner       │
├──────────────────────────┤
│  API Usage Detector       │  ← Regex/AST scan for require/import patterns
├──────────────────────────┤
│  Dependency Analyzer      │  ← package.json + lockfile analysis
├──────────────────────────┤
│  Risk Classifier          │  ← Map to bands, score risk
├──────────────────────────┤
│  Report Generator         │  ← JSON risk inventory output
└──────────────────────────┘
```

## Risk Categories

| Category | Risk Level | Examples |
|----------|-----------|---------|
| Core API, implemented | Low | fs.readFile, path.join |
| Core API, stubbed | Medium | Buffer.alloc, stream.Readable |
| High-value API, stubbed | High | http.createServer, crypto.createHash |
| Native addon dependency | Critical | node-gyp, N-API bindings |
| Unsafe API usage | Critical | eval(), vm.runInNewContext |
| Unknown/untracked API | Medium | Unregistered API families |

## Output Schema

```json
{
  "project": "<path>",
  "scan_timestamp": "<ISO8601>",
  "summary": {
    "total_apis_detected": 0,
    "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "migration_readiness": "not-ready|partial|ready"
  },
  "api_usage": [...],
  "dependencies": [...],
  "recommendations": [...]
}
```

## Invariants

1. Scanner produces deterministic output for identical input.
2. Every detected API maps to a compatibility band or "unknown".
3. Native addon dependencies are always flagged as critical risk.
4. Unsafe API usage is always flagged as critical risk.
5. Report JSON validates against its schema.

## References

- [COMPATIBILITY_BANDS.md](../../COMPATIBILITY_BANDS.md)
- [COMPATIBILITY_REGISTRY.json](../../COMPATIBILITY_REGISTRY.json)
