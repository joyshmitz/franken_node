# bd-16fq: VEF Policy-Constraint Language + Compiler Contract

**Section:** 10.18 — Verifiable Execution Fabric (Enhancement Map 9L)  
**Track:** E — Frontier Industrialization  
**Status:** Active

## Purpose

Define the canonical policy-constraint language and deterministic compiler that
translates runtime policy to proof-checkable predicates for high-risk action
classes. This is the foundational contract for downstream receipt/proof gates
in section 10.18.

## Scope

### In scope

- Versioned policy language for six required high-risk action classes.
- Deterministic policy-to-predicate compiler.
- Predicate-to-rule traceability links.
- Versioned machine-readable constraint schema (`spec/vef_policy_constraints_v1.json`).
- Round-trip semantic projection checks.
- Classified compile error codes and structured compile events.

### Out of scope

- Cryptographic proof backend implementation.
- Distributed verifier orchestration and quorum policy.
- Runtime enforcement engine for compiled predicates.

## Required Action Classes

1. `network_access`
2. `filesystem_operation`
3. `process_spawn`
4. `secret_access`
5. `policy_transition`
6. `artifact_promotion`

## Compiler Semantics

- Input policy version must equal `vef-policy-lang-v1`.
- Output envelope version must equal `vef-policy-constraints-v1`.
- Rule normalization is deterministic (sorted IDs, deduped capabilities,
  ordered constraint keys).
- Each rule emits at least one decision predicate and optional capability /
  constraint predicates.
- `require_full_action_coverage=true` enforces complete six-class coverage.

## Event Codes

- `VEF-COMPILE-001`: compilation started
- `VEF-COMPILE-002`: compilation succeeded
- `VEF-COMPILE-ERR-001`: invalid input
- `VEF-COMPILE-ERR-002`: invalid version
- `VEF-COMPILE-ERR-003`: missing coverage
- `VEF-COMPILE-ERR-004`: invalid rule shape
- `VEF-COMPILE-ERR-005`: internal canonicalization failure

## Invariants

- `INV-VEF-COMP-DETERMINISTIC`
- `INV-VEF-COMP-COVERAGE`
- `INV-VEF-COMP-TRACEABLE`
- `INV-VEF-COMP-VERSIONED`
- `INV-VEF-COMP-ROUNDTRIP`

## Acceptance Criteria

1. All six required action classes have corresponding compiler mappings.
2. Compiler output is deterministic for identical policy + trace inputs.
3. Output envelope includes version metadata, policy snapshot hash, and
   predicate-to-rule traceability.
4. Round-trip semantics (`policy -> compile -> decompile`) preserves meaning.
5. Invalid inputs produce stable classified error codes (`VEF-COMPILE-ERR-*`).
6. Machine-readable schema exists at `spec/vef_policy_constraints_v1.json`.
7. Verification script and tests pass with reproducible evidence artifacts.

## Verification Artifacts

- `artifacts/10.18/vef_constraint_compiler_report.json`
- `artifacts/section_10_18/bd-16fq/verification_evidence.json`
- `artifacts/section_10_18/bd-16fq/verification_summary.md`

## Implementation Surfaces

- `crates/franken-node/src/connector/vef_policy_constraints.rs`
- `crates/franken-node/src/connector/mod.rs`
- `scripts/check_vef_policy_constraints.py`
- `tests/test_check_vef_policy_constraints.py`
- `tests/conformance/vef_policy_constraint_compiler.rs`
- `vectors/vef_policy_constraint_compiler.json`
