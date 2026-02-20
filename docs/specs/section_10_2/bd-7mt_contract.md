# bd-7mt: CI Gate — Spec Section & Fixture Reference Enforcement

## Decision Rationale

Compatibility implementations must be traceable to their spec sections and validated by fixture IDs. This CI gate enforces that every compatibility shim cites its authority (spec section) and its verification (fixture IDs). Missing references fail the review gate.

## Gate Rules

1. **Spec Reference Required**: Every compatibility implementation file must contain a reference to its spec section (e.g., `Spec: Section 10.2`, `ADR-001`, or a `docs/specs/` path).
2. **Fixture Reference Required**: Every compatibility implementation file must cite at least one fixture ID (pattern: `fixture:<family>:<api>:<scenario>`).
3. **Registry Alignment**: Every cited fixture ID must exist in the fixture corpus.
4. **Band Declaration**: Implementation files must declare which compatibility band they target.

## Enforcement

- The gate runs as `scripts/check_compat_ci_gate.py`
- Returns exit code 0 (pass) or 1 (fail)
- Produces machine-readable JSON report for CI integration
- Blocks PRs that add compatibility code without spec+fixture references

## Invariants

1. No compatibility implementation passes review without spec citation.
2. No compatibility implementation passes review without fixture citation.
3. Cited fixture IDs must resolve to real fixtures.
4. Gate produces deterministic, reproducible results.

## References

- [COMPATIBILITY_REGISTRY.json](../../COMPATIBILITY_REGISTRY.json)
- [IMPLEMENTATION_GOVERNANCE.md](../../IMPLEMENTATION_GOVERNANCE.md)
- [ADR-001](../../adr/ADR-001-hybrid-baseline-strategy.md)
