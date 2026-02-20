# bd-3dn: Rollout Planner

## Decision Rationale

Safe migration requires a graduated rollout strategy. The rollout planner generates a phase-by-phase plan from shadow deployment through full default, with gate conditions at each transition.

## Phases

| Phase | Description | Traffic | Gate Condition |
|-------|-------------|---------|----------------|
| `shadow` | Run both runtimes, compare outputs, serve from original | 0% | Validation runner passes |
| `canary` | Serve subset of traffic from franken_node | 1-5% | No critical divergences in shadow |
| `ramp` | Gradually increase franken_node traffic | 5-50% | Error rate < threshold |
| `default` | All traffic on franken_node, original as fallback | 100% | Sustained stability |

## Invariants

1. Phases are strictly ordered: shadow → canary → ramp → default.
2. Gate conditions must pass before phase transition.
3. Rollback to previous phase is always available.
4. Plan output is deterministic for identical scan + risk input.

## References

- [bd-2st_contract.md](bd-2st_contract.md) — Validation Runner
- [bd-33x_contract.md](bd-33x_contract.md) — Risk Scorer
