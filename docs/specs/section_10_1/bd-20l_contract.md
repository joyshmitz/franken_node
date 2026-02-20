# bd-20l: ADR "Hybrid Baseline Strategy"

## Decision Rationale

The canonical plan (Section 10.1) requires an ADR codifying the hybrid baseline strategy: no Bun-first clone, spec-first compatibility extraction, and native franken architecture from day one. This formalizes the strategic direction already established in the plan (Section 3.3) and charter into a governance-enforceable document.

## What the ADR Codifies

1. No Bun-first clone path (off-charter)
2. Spec-first extraction discipline for all compatibility work
3. Native implementation on franken_engine (no binding-based core)
4. Line-by-line legacy translation forbidden
5. Fixture-oracle validation as verification gate
6. Trust-native capabilities preserved from day one

## Invariants

1. `docs/adr/ADR-001-hybrid-baseline-strategy.md` exists.
2. ADR contains all 6 rules (no-clone, spec-first, native-impl, no-translation, fixture-oracle, trust-native).
3. ADR status is "Accepted".
4. ADR references the canonical plan sections.
5. PRODUCT_CHARTER.md cross-references the ADR.

## Interface Boundaries

- **Input**: ADR document, charter, plan
- **Output**: PASS/FAIL verdict on ADR completeness and correctness

## Failure Semantics

- Missing ADR: FAIL
- Missing required rules: FAIL per rule
- Bad status: FAIL
- Missing cross-references: FAIL
