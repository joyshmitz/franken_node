# bd-2ew: Automated Rewrite Suggestion Engine

## Decision Rationale

After scanning a project and scoring risks, operators need actionable rewrite suggestions. The suggestion engine maps detected API usage to franken_node equivalents, provides code transformation hints, and generates rollback plan artifacts so operators can safely test changes.

## Scope

1. Map Node.js/Bun API calls to franken_node equivalents
2. Generate rewrite suggestions with before/after examples
3. Produce rollback plan artifacts for each suggestion
4. Prioritize suggestions by risk level and migration impact

## Suggestion Categories

| Category | Description | Example |
|----------|-------------|---------|
| `direct-replacement` | 1:1 API mapping exists | `require('fs')` → native fs shim |
| `adapter-needed` | Adapter/wrapper required | `http.createServer` → engine-native server |
| `removal-needed` | API must be removed | `process.binding()` → remove or replace |
| `manual-review` | No automated rewrite possible | Native addon usage |

## Rollback Plan

Each suggestion includes:
- Original code snapshot
- Suggested replacement
- Test commands to verify equivalence
- Rollback command (git restore path)

## Invariants

1. Every suggestion maps to a compatibility registry entry or "untracked".
2. Rollback plans are always generated alongside suggestions.
3. Suggestions are prioritized: critical first, then high, medium, low.
4. Engine deterministically produces identical output for identical input.

## References

- [bd-2a0_contract.md](bd-2a0_contract.md) — Project Scanner
- [bd-33x_contract.md](bd-33x_contract.md) — Risk Scorer
