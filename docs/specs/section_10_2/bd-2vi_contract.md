# bd-2vi: L1 Lockstep Runner Integration

## Decision Rationale

The canonical plan (Section 10.2) requires an L1 Product Oracle that runs the same compatibility fixtures across Node.js, Bun, and franken_node, then compares canonicalized results. This bead implements the lockstep runner framework and its validation infrastructure.

## L1 Oracle Architecture

The L1 lockstep runner:
1. Loads fixture files from `docs/fixtures/`
2. Executes each fixture against configured runtimes (Node, Bun, franken_node)
3. Canonicalizes outputs using the result canonicalizer
4. Compares canonical outputs to detect divergences
5. Produces a structured delta report

## Runner Configuration

```json
{
  "schema_version": "1.0",
  "runtimes": [
    {"name": "node", "command": "node", "version_flag": "--version"},
    {"name": "bun", "command": "bun", "version_flag": "--version"},
    {"name": "franken_node", "command": "franken-node", "version_flag": "--version"}
  ],
  "fixture_dir": "docs/fixtures",
  "output_dir": "artifacts/oracle"
}
```

## Invariants

1. `docs/L1_LOCKSTEP_RUNNER.md` design document exists.
2. `schemas/lockstep_runner_config.schema.json` defines runner configuration.
3. Runner configuration schema validates all required fields.
4. Design covers: fixture loading, runtime execution, canonicalization, delta detection.
5. Delta report format is machine-readable.

## Failure Semantics

- Missing design document: FAIL
- Missing config schema: FAIL
- Incomplete design (missing any of the 5 phases): FAIL
