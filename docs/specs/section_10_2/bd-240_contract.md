# bd-240: Compatibility Regression Dashboard

## Decision Rationale

The canonical plan (Section 10.2) requires a compatibility regression dashboard organized by API family. This provides visibility into pass/fail rates across bands and families, tracks regressions over time, and feeds into release gating decisions.

## Dashboard Specification

### Data Sources
- Compatibility behavior registry (`COMPATIBILITY_REGISTRY.json`)
- L1 lockstep oracle results
- Divergence ledger (`DIVERGENCE_LEDGER.json`)
- Fixture runner results

### Dashboard Views
1. **By API Family**: Pass/fail counts and rates per family (fs, path, http, etc.)
2. **By Band**: Aggregate pass rates per band (core, high-value, edge, unsafe)
3. **Trend**: Pass rate over time per family and band
4. **Regressions**: Newly failing fixtures since last run

### Output Format
Machine-readable JSON dashboard artifact for CI/release gating.

## Invariants

1. `docs/COMPAT_DASHBOARD_SPEC.md` design document exists.
2. Design covers: data sources, views (family, band, trend, regressions), output format.
3. Dashboard schema exists at `schemas/compat_dashboard.schema.json`.
4. Integration with registry and ledger documented.

## Failure Semantics

- Missing design: FAIL
- Missing schema: FAIL
- Incomplete view coverage: FAIL
