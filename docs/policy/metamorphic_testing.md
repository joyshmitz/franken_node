# Policy: Metamorphic Testing for Compatibility Invariants

**Bead:** bd-1u4
**Section:** 10.7 -- Conformance & Verification
**Effective:** 2026-02-20

## 1. Overview

This policy governs the metamorphic testing framework used to verify
compatibility invariants in franken_node. Metamorphic testing validates
relational properties that hold across families of inputs, providing
oracle-free verification of behavioral equivalence, backward compatibility,
idempotency, and operation commutativity.

## 2. Metamorphic Relations Catalog

### 2.1 Equivalence (MR-EQUIV)

The equivalence relation is the foundation of compatibility testing. For every
API call in the franken_node public surface, the output must match the
upstream Node.js output after normalization. Normalization removes:

- Timestamps and dates (replaced with sentinel values).
- Object identity hashes.
- Ordering of unordered collections (e.g., object keys, Set iteration order).
- Runtime-specific metadata (process.pid, memory addresses).

Documented divergences (tracked in the divergence ledger) are excluded from
equivalence checks.

### 2.2 Monotonicity (MR-MONO)

Adding optional parameters to an API call must not alter the fields returned
by the base call. This ensures backward compatibility for callers that upgrade
to newer API versions. The relation checks that every field present in the
base output is present and unchanged in the extended output.

### 2.3 Idempotency (MR-IDEM)

Operations that are declared idempotent (migrations, configuration updates,
policy applications) must produce identical results when applied twice.
The relation checks: `apply(apply(state)) == apply(state)` for all fields
in the output.

### 2.4 Commutativity (MR-COMM)

Independent operations (those with non-overlapping write sets) must produce
the same final state regardless of execution order. The relation checks
set-equality of the final observable state after permuting the operation order.

## 3. Test Generation Strategy

### 3.1 Base Input Selection

Base inputs are drawn from the corpus at `tests/metamorphic/corpus/`. The
corpus is partitioned into categories:

| Category | Minimum Count | Description |
|----------|--------------|-------------|
| `api_usage` | 30 | Standard API call patterns |
| `migration` | 25 | Migration scenario inputs |
| `policy` | 25 | Policy configuration variants |
| `edge_case` | 20 | Boundary conditions, empty inputs, large payloads |

### 3.2 Transformation Pipeline

For each base input, the generator:

1. Selects applicable metamorphic relations based on the input category.
2. Applies each relation's transformation to produce a follow-up input.
3. Records the transformation parameters for violation reporting.

### 3.3 Extensibility

New relations are registered by implementing the `MetamorphicRelation` trait
and adding them to the relation registry. The generator discovers relations
at startup via the registry -- no code changes to the generator are required.

## 4. Equivalence Oracle Design

### 4.1 Oracle-Free Verification

Metamorphic testing is oracle-free by design: it does not require knowledge of
the correct output for any individual input. Instead, it checks that the
relationship between outputs of related inputs holds. This makes it
particularly suitable for franken_node, where the "correct" behavior is
defined relationally (equivalent to Node.js).

### 4.2 Normalization Pipeline

Before comparing outputs, the normalization pipeline:

1. Strips non-deterministic fields (timestamps, PIDs, memory addresses).
2. Sorts unordered collections (object keys, array elements where order is
   not semantically significant).
3. Canonicalizes numeric representations (e.g., `1.0` vs `1`).
4. Applies documented divergence exclusions from the divergence ledger.

### 4.3 Comparison Modes

| Mode | Use Case |
|------|----------|
| `strict` | Byte-level equality after normalization |
| `structural` | Same JSON structure and types, values may differ within tolerance |
| `subset` | Original output is a subset of follow-up output (for monotonicity) |
| `set_equal` | Same elements, order irrelevant (for commutativity) |

## 5. Violation Handling

### 5.1 Severity Classification

| Severity | Criteria | CI Impact |
|----------|----------|-----------|
| `blocking` | Core compatibility or safety invariant broken | Gate fails |
| `degraded` | Non-critical divergence, functionality preserved | Warning logged |

### 5.2 Violation Report Format

Every violation report is a structured JSON object containing:

- `base_input`: The original test input.
- `transformation`: Name and parameters of the applied transformation.
- `expected_relation`: The metamorphic relation that was expected to hold.
- `original_output`: Output from the base input.
- `followup_output`: Output from the transformed input.
- `divergence_point`: The specific field path where the relation broke.
- `severity`: `blocking` or `degraded`.

### 5.3 Triage Workflow

1. Blocking violations must be resolved before merge.
2. Degraded violations are logged and tracked as beads.
3. All violations emit event code MMT-003 with the full report.

## 6. CI Integration

### 6.1 Trigger

The metamorphic test suite runs on every push to any branch targeting main.
This is non-negotiable (INV-MMT-RELATIONS).

### 6.2 Gate Criteria

- Zero blocking violations.
- Overall relation pass rate >= 95%.
- All 4 core relations exercised in every run.

### 6.3 Reporting

After each run, the system produces:

- Per-relation pass/fail summary.
- Total inputs tested, transformations applied, violations found.
- Trend comparison against previous 10 runs.

### 6.4 Structured Logging

Each run emits a JSON log containing:

```json
{
  "run_id": "...",
  "timestamp": "...",
  "relations_tested": ["MR-EQUIV", "MR-MONO", "MR-IDEM", "MR-COMM"],
  "base_inputs_count": 100,
  "transformations_applied": 400,
  "violations": [],
  "pass_count": 400,
  "fail_count": 0,
  "verdict": "PASS"
}
```

## 7. Corpus Maintenance

### 7.1 Version Control

The corpus is stored in-repo under `tests/metamorphic/corpus/` and is subject
to the same review process as production code. Modifications emit MMT-004.

### 7.2 Minimum Size

The corpus must contain at least 100 inputs (INV-MMT-CORPUS). If the count
drops below this threshold, the CI gate fails.

### 7.3 Coverage Requirements

The corpus must cover all 4 input categories with the minimum counts defined
in Section 3.1.

## 8. Revision History

| Date | Change |
|------|--------|
| 2026-02-20 | Initial policy created for bd-1u4. |
