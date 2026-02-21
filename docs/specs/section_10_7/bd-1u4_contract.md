# bd-1u4: Metamorphic Tests for Compatibility Invariants

## Scope

Systematic metamorphic testing framework for compatibility invariants in
franken_node. Metamorphic testing validates relational properties across
families of inputs, catching bugs that point-wise assertion-based tests miss.
The core compatibility promise (behavioral equivalence with Node.js) is
inherently a metamorphic property.

## Metamorphic Relations

| ID | Relation | Input Transformation | Output Relation |
|----|----------|---------------------|-----------------|
| MR-EQUIV | Equivalence | Identity (same API call) | Output equality after normalization |
| MR-MONO | Monotonicity | Add optional parameters | Original output fields unchanged |
| MR-IDEM | Idempotency | Repeat operation | Output equality |
| MR-COMM | Commutativity | Permute independent operations | Set equality of results |

### MR-EQUIV: Equivalence Relation

If API X produces output Y in Node.js, then API X must produce output Y in
franken_node (modulo documented divergences). The normalizer strips
non-deterministic fields (timestamps, object identity, ordering of unordered
collections) before comparison.

### MR-MONO: Monotonicity Relation

Extending an API call with additional optional parameters must not break
backward compatibility. Given a base call with parameters P, adding optional
parameter Q must preserve all output fields produced by P alone.

### MR-IDEM: Idempotency Relation

Applying a migration or configuration update twice produces the same result as
applying it once. Given operation O and state S: O(O(S)) = O(S).

### MR-COMM: Commutativity Relation

Independent policy evaluations produce the same results regardless of
execution order. Given independent operations A and B on state S:
A(B(S)) = B(A(S)) in terms of final observable state.

## Test Generator

The metamorphic test generator:

1. Loads base inputs from the corpus directory.
2. Applies registered transformations to produce metamorphic input pairs.
3. Executes both inputs through the system under test.
4. Validates the expected relation holds between the two outputs.

### Pluggable Interface

New relations are added by implementing the `MetamorphicRelation` trait:

- `name() -> &str` -- relation identifier.
- `transform(input: &BaseInput) -> BaseInput` -- produce the follow-up input.
- `validate(original_output: &Output, followup_output: &Output) -> RelationResult` -- check the relation.
- `description() -> &str` -- human-readable description.

The generator framework does not need modification to support new relations.

## Base Input Corpus

- Stored in `tests/metamorphic/corpus/`.
- Minimum 100 inputs covering: API usage patterns, migration scenarios, policy
  configurations, edge cases.
- Each input is a JSON file with fields: `id`, `category`, `api_family`,
  `input_params`, `expected_baseline`.
- Categories: `api_usage`, `migration`, `policy`, `edge_case`.

## Violation Reporting

When a metamorphic relation is violated, the report includes:

| Field | Description |
|-------|-------------|
| `base_input` | The original input that was transformed |
| `transformation` | Name and parameters of the transformation applied |
| `expected_relation` | The metamorphic relation that should have held |
| `original_output` | Output from the base input execution |
| `followup_output` | Output from the transformed input execution |
| `divergence_point` | Specific field or value where the relation broke |
| `severity` | `blocking` or `degraded` |

## Event Codes

| Code | Trigger |
|------|---------|
| MMT-001 | Metamorphic test suite run started |
| MMT-002 | Metamorphic relation validated successfully |
| MMT-003 | Metamorphic relation violation detected |
| MMT-004 | New metamorphic relation registered via plugin interface |

## Invariants

| ID | Statement |
|----|-----------|
| INV-MMT-RELATIONS | At least 4 metamorphic relations are defined and exercised |
| INV-MMT-CORPUS | Base input corpus contains >= 100 inputs |
| INV-MMT-PLUGGABLE | New relations can be added without modifying the generator |
| INV-MMT-REPORT | Violation reports include all required diagnostic fields |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR_MMT_CORPUS_EMPTY | Corpus directory contains no valid inputs |
| ERR_MMT_RELATION_INVALID | Relation implementation fails validation |
| ERR_MMT_TRANSFORM_FAILED | Input transformation produced invalid output |
| ERR_MMT_EXECUTION_TIMEOUT | Test execution exceeded time budget |

## CI Integration

- Metamorphic test suite runs on every CI push.
- Any relation violation classified as `blocking` fails the gate.
- Overall corpus pass rate must be >= 95%.
- Structured JSON log emitted per run with: relation name, base inputs tested,
  transformations applied, violations found, total pass/fail counts.

## Acceptance Criteria

1. At least 4 metamorphic relations formally defined and implemented (MR-EQUIV, MR-MONO, MR-IDEM, MR-COMM).
2. Metamorphic test generator produces input pairs from base inputs and validates relations, with pluggable relation/transformation support.
3. Base input corpus contains at least 100 inputs covering API usage, migration scenarios, and policy configurations.
4. Relation violation reports include: base input, transformation, expected relation, actual outputs, and specific divergence point.
5. CI gate runs metamorphic test suite and fails on any blocking relation violation.
6. New metamorphic relations can be added by implementing the relation interface without modifying the generator framework.
7. Verification script `scripts/check_metamorphic_testing.py` with `--json` flag validates relation coverage and violation detection.
8. Unit tests in `tests/test_check_metamorphic_testing.py` cover relation validation logic, generator correctness, corpus loading, and violation report formatting.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_7/bd-1u4_contract.md` |
| Policy doc | `docs/policy/metamorphic_testing.md` |
| Verification script | `scripts/check_metamorphic_testing.py` |
| Python unit tests | `tests/test_check_metamorphic_testing.py` |
| Verification evidence | `artifacts/section_10_7/bd-1u4/verification_evidence.json` |
| Verification summary | `artifacts/section_10_7/bd-1u4/verification_summary.md` |
