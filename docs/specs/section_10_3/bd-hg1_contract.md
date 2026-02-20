# bd-hg1: One-Command Migration Report Export

## Decision Rationale

Enterprise adoption requires a single command that produces a comprehensive, shareable migration assessment. This command orchestrates scan → score → validate → plan → confidence into one exportable report.

## Scope

Build `franken-node migrate-report <project>` that:
1. Runs project scanner
2. Computes risk score
3. Generates rewrite suggestions
4. Produces rollout plan
5. Computes confidence report
6. Exports everything as a single JSON/HTML report

## Command Interface

```
franken-node migrate-report <project_dir> [--format json|html] [--output report.json]
```

## Report Sections

1. Executive Summary (go/no-go, confidence, risk score)
2. API Inventory (detected APIs by family and band)
3. Risk Assessment (score, features, difficulty)
4. Rewrite Suggestions (prioritized list)
5. Rollout Plan (phase-by-phase with gates)
6. Confidence Assessment (score with uncertainty bands)

## Invariants

1. Single command produces complete report.
2. Report is self-contained (no external references needed).
3. Output is deterministic for identical project state.
4. JSON output validates against schema.

## References

- All bd-* contracts in section_10_3/
