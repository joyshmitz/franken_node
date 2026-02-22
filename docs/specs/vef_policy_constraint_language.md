# VEF Policy-Constraint Language (v1)

**Bead:** bd-16fq  
**Section:** 10.18 — Verifiable Execution Fabric (VEF)  
**Language Version:** `vef-policy-lang-v1`  
**Compiler Version:** `vef-constraint-compiler-v1`

## Purpose

Define a deterministic language that maps runtime policy rules to
proof-checkable predicates for high-risk action classes:

- `network_access`
- `filesystem_operation`
- `process_spawn`
- `secret_access`
- `policy_transition`
- `artifact_promotion`

The compiler output is consumed by proof generators and verifiers, with
explicit rule-to-predicate traceability.

## Input Grammar (JSON)

`RuntimePolicy`:

- `schema_version: string` (`vef-policy-lang-v1`)
- `policy_id: string`
- `require_full_action_coverage: bool` (default `true`)
- `rules: PolicyRule[]`

`PolicyRule`:

- `rule_id: string` (non-empty, unique)
- `action_class: ActionClass`
- `effect: RuleEffect` (`allow | deny | require`)
- `required_capabilities: string[]` (optional)
- `constraints: map<string,string>` (optional)

## Compiler Contract

`compile_policy(policy, trace_id) -> CompiledConstraintEnvelope`

Envelope fields:

- `schema_version` = `vef-policy-constraints-v1`
- `language_version` = `vef-policy-lang-v1`
- `compiler_version` = `vef-constraint-compiler-v1`
- `trace_id` (required)
- `policy_id`
- `policy_snapshot_hash` (`sha256:<hex>` of canonical policy)
- `predicates[]` (proof-checkable predicate set)
- `coverage` (action class -> rule count)
- `rule_projections[]` (semantic round-trip representation)
- `events[]` (structured compile events)

### Predicate Mapping Rules

Each source rule produces:

1. One decision predicate:
- `permit(<action>)` for `allow`
- `deny(<action>)` for `deny`
- `require(<action>)` for `require`

2. Zero or more capability predicates:
- `requires_capability(<action>, "<capability>")`

3. Zero or more constraint predicates:
- `constraint(<action>, "<key>", "<value>")`

Every predicate includes:

- `predicate_id` (stable hash-derived ID)
- `source_rule_id`
- `trace_link` (`policy:<policy_id>/rule:<rule_id>`)

## Determinism Requirements

- Rule IDs are canonicalized and sorted before compile.
- Capability lists are sorted/deduplicated.
- Constraint keys are stored in sorted map order.
- Predicate IDs are hash-derived from canonical seeds.
- Recompiling identical input with identical `trace_id` yields byte-identical JSON.

## Round-Trip Semantics

`decompile_projection(envelope)` returns normalized `rule_projections`.

`round_trip_semantics(policy, trace_id)` must return `true` when compile output
semantics exactly match normalized input semantics.

## Error Model

Stable classified error codes:

- `VEF-COMPILE-ERR-001` invalid input
- `VEF-COMPILE-ERR-002` invalid/unsupported version
- `VEF-COMPILE-ERR-003` missing action-class coverage
- `VEF-COMPILE-ERR-004` invalid rule shape
- `VEF-COMPILE-ERR-005` internal canonicalization failure

## Event Model

Structured compile events:

- `VEF-COMPILE-001` compile started
- `VEF-COMPILE-002` compile succeeded
- `VEF-COMPILE-ERR-*` classified failure codes

All events carry `trace_id` for replay correlation.

## Invariants

- `INV-VEF-COMP-DETERMINISTIC`
- `INV-VEF-COMP-COVERAGE`
- `INV-VEF-COMP-TRACEABLE`
- `INV-VEF-COMP-VERSIONED`
- `INV-VEF-COMP-ROUNDTRIP`

## Implementation

- `crates/franken-node/src/connector/vef_policy_constraints.rs`
- `spec/vef_policy_constraints_v1.json`
- `vectors/vef_policy_constraint_compiler.json`

## Verification

- `scripts/check_vef_policy_constraints.py --json`
- `tests/test_check_vef_policy_constraints.py`
- `tests/conformance/vef_policy_constraint_compiler.rs`
