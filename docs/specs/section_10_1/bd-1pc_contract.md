# bd-1pc: Implementation-Governance Policy

## Decision Rationale

The canonical plan (Section 10.1) and ADR-001 require a governance policy that forbids line-by-line legacy translation and mandates spec+fixture references in all compatibility PRs. This enforces the hybrid baseline strategy at the PR review level.

## Policy Document

The policy is codified in `docs/IMPLEMENTATION_GOVERNANCE.md`.

## Rules

### Rule 1: No Line-by-Line Legacy Translation
Compatibility implementations must not be line-by-line translations of Node.js, Bun, or Deno source code. Legacy runtimes are oracle targets for specification and fixture extraction, not implementation blueprints.

### Rule 2: Spec References Required
Every compatibility PR must reference the specification section(s) it implements. PRs without spec references fail governance review.

### Rule 3: Fixture References Required
Every compatibility PR must reference the conformance fixture(s) it validates against. PRs without fixture references fail governance review.

### Rule 4: PR Description Format
Compatibility PRs must include a structured section with:
- `Spec-Ref:` — specification document and section
- `Fixture-Ref:` — fixture ID or test vector path
- `Oracle:` — which runtime(s) were used as behavioral oracle

## Invariants

1. `docs/IMPLEMENTATION_GOVERNANCE.md` exists and contains all 4 rules.
2. Policy references ADR-001 as the foundational decision.
3. Policy is cross-referenced from PRODUCT_CHARTER.md.
4. Enforcement script validates policy document structure.

## Interface Boundaries

- **Input**: `docs/IMPLEMENTATION_GOVERNANCE.md`
- **Output**: PASS/FAIL verdict on policy completeness

## Failure Semantics

- Missing policy document: FAIL
- Missing required rules: FAIL per rule
- Missing ADR reference: FAIL
- Missing charter cross-reference: FAIL
