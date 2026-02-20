# bd-1z3: Deterministic Compatibility Fixture Runner

## Decision Rationale

The canonical plan (Section 10.2) requires a fixture runner that executes compatibility test fixtures deterministically and canonicalizes results for oracle comparison. This enables the L1 lockstep oracle (Node/Bun/franken_node) to compare outputs reliably.

## Fixture Format

Each fixture is a JSON file defining:
- **id**: Unique fixture identifier
- **api_family**: API family being tested
- **api_name**: Specific API
- **band**: Compatibility band
- **input**: Input arguments/state for the test
- **expected_output**: Expected canonical output
- **oracle_source**: Runtime that produced the expected output

## Result Canonicalization

The canonicalizer normalizes outputs to enable deterministic comparison:
- Timestamps → replaced with `<TIMESTAMP>`
- Absolute paths → replaced with `<ROOT>/relative/path`
- PIDs → replaced with `<PID>`
- Ordering of object keys → sorted alphabetically
- Floating-point numbers → rounded to 6 decimal places

## Invariants

1. `schemas/compatibility_fixture.schema.json` exists.
2. `docs/fixtures/` directory exists for fixture storage.
3. Fixture schema validates all required fields.
4. Canonicalizer handles timestamp/path/PID normalization.
5. Runner produces deterministic output for same input.

## Failure Semantics

- Missing fixture schema: FAIL
- Missing fixtures directory: FAIL
- Invalid fixture JSON: FAIL per fixture
- Non-deterministic output: FAIL
