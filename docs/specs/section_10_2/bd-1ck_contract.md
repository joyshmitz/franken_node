# bd-1ck: L2 Engine-Boundary Semantic Oracle

## Decision Rationale

The canonical plan (Section 10.2) requires an L2 engine-boundary oracle that validates semantic integrity at the franken_engine trust boundary. While L1 validates external API behavior, L2 validates that engine trust gates, capability boundaries, and policy enforcement remain intact across all compatibility work.

## L2 vs L1

| Aspect | L1 Product Oracle | L2 Engine-Boundary Oracle |
|--------|------------------|--------------------------|
| **What** | External API behavior | Engine trust boundary semantics |
| **Compares** | Node/Bun/franken_node outputs | franken_engine contract compliance |
| **Validates** | Behavioral compatibility | Trust gate integrity |
| **Blocks on** | Core API divergences | Any trust boundary violation |

## Invariants

1. `docs/L2_ENGINE_BOUNDARY_ORACLE.md` design document exists.
2. Design covers: boundary definition, semantic checks, trust gate validation, release gate linkage.
3. L2 failures always block release (no mode-dependent behavior).
4. Policy references ENGINE_SPLIT_CONTRACT.md.
5. Integration with release pipeline documented.

## Failure Semantics

- Missing design: FAIL
- Incomplete boundary coverage: FAIL
- Missing release gate linkage: FAIL
