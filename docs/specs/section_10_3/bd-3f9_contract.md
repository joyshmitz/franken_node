# bd-3f9: Deterministic Migration Failure Replay Tooling

## Decision Rationale

When migration validation detects divergences, operators need to deterministically replay the failure for diagnosis. The replay tooling captures sufficient context (inputs, environment, runtime version) to reproduce any detected failure.

## Scope

1. Capture failure context at detection time
2. Generate deterministic replay scripts
3. Store replay artifacts for later diagnosis
4. Support automated minimization of failure cases

## Replay Artifact Structure

```json
{
  "replay_id": "REPLAY-001",
  "failure_source": "validation_runner",
  "captured_at": "<ISO8601>",
  "context": {
    "runtime": "node-20.11.0",
    "fixture_id": "fixture:fs:readFile:utf8-basic",
    "input": {...},
    "expected_output": {...},
    "actual_output": {...},
    "environment": {"NODE_ENV": "test"}
  },
  "replay_command": "franken-node --replay <artifact_path>",
  "minimized": false
}
```

## Invariants

1. Replay artifacts are self-contained (no external state needed).
2. Replaying produces identical failure for identical artifact.
3. Every validation failure generates a replay artifact.
4. Replay artifacts are stored in `artifacts/replays/`.

## References

- [bd-2st_contract.md](bd-2st_contract.md) — Validation Runner
- [MINIMIZED_FIXTURE_SPEC.md](../../MINIMIZED_FIXTURE_SPEC.md)
