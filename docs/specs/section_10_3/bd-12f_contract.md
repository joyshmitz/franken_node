# bd-12f: Migration Confidence Report

## Decision Rationale

Operators need a single report that synthesizes scan results, risk scores, validation outcomes, and rollout plan into a confidence assessment with uncertainty bands, so they can make informed go/no-go decisions.

## Scope

Build a confidence report generator that:
1. Aggregates scan, risk, validation, and rollout data
2. Computes confidence level with uncertainty bands
3. Produces human-readable and machine-readable reports
4. Clearly communicates go/no-go recommendation

## Confidence Levels

| Level | Score Range | Recommendation |
|-------|-----------|----------------|
| High | 80-100 | Proceed with standard rollout |
| Medium | 50-79 | Proceed with extended monitoring |
| Low | 20-49 | Address risks before proceeding |
| Insufficient | 0-19 | Migration not recommended |

## Uncertainty Sources

- Incomplete test coverage (fixture gaps)
- Untracked API usage
- Untested edge cases
- Runtime-specific behavior differences

## Invariants

1. Confidence score is bounded [0, 100].
2. Uncertainty band width reflects data completeness.
3. Report is deterministic for identical input.
4. Go/no-go recommendation is consistent with confidence level.

## References

- [bd-33x_contract.md](bd-33x_contract.md) — Risk Scorer
- [bd-2st_contract.md](bd-2st_contract.md) — Validation Runner
- [bd-3dn_contract.md](bd-3dn_contract.md) — Rollout Planner
