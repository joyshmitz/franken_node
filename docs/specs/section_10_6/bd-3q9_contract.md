# bd-3q9: Release Rollback Bundles with Deterministic Restoration

## Bead: bd-3q9 | Section: 10.6

## Purpose

Section 9I.10 requires crash-loop rollback capability, and Section 8.5 invariant #4
mandates two-phase effects -- every state change must be reversible. When a release
causes problems in production, operators need a guaranteed path back to the previous
known-good state. Ad-hoc rollback is error-prone and often incomplete (binary reverted
but configuration left in new format, or state migrations left half-applied).

This bead ensures every release ships with a rollback bundle that deterministically
restores the previous version, including binary reference, configuration, and state.
The rollback process is idempotent and produces a verifiable post-rollback state that
matches the pre-upgrade snapshot.

## Rollback Bundle Structure

A rollback bundle is a self-contained archive containing:

1. **Previous binary reference** -- SHA-256 hash of the previous version binary.
2. **Configuration diff** -- Reversible configuration delta that undoes any schema changes.
3. **State migration reversal** -- Scripts/records that undo data format changes.
4. **Health check definitions** -- Sequence of health checks to validate rollback success.
5. **Restore manifest** -- Machine-readable manifest listing all bundle contents with
   their checksums and application order.
6. **Compatibility proof** -- Record of which versions the bundle can safely roll back
   from/to, including version bounds.

## Acceptance Criteria

1. Every release build produces a rollback bundle alongside release artifacts, containing
   previous binary hash, config diff, state migration reversal, and health check definitions.
2. `franken-node rollback <bundle-path>` applies the bundle and runs the health check
   sequence, reporting structured JSON results.
3. `--dry-run` previews rollback actions without applying changes.
4. Pre/post state snapshots are compared after rollback; mismatches produce structured
   error reports with remediation guidance.
5. Rollback is idempotent -- applying the same bundle twice produces identical state.
6. Health check sequence covers: binary version, config schema, state integrity, and
   core workflow smoke tests.
7. Verification script `scripts/check_rollback_bundles.py` with `--json` flag validates
   bundle generation and restore correctness.
8. Unit tests in `tests/test_check_rollback_bundles.py` cover bundle generation, config
   diff application, state reversal, health check execution, idempotency, and dry-run mode.

## Event Codes

| Code    | When Emitted                                                                  |
|---------|-------------------------------------------------------------------------------|
| RRB-001 | Rollback bundle created: emitted after successful bundle generation.          |
| RRB-002 | Rollback initiated: emitted when a rollback operation begins.                 |
| RRB-003 | Rollback completed: emitted after successful rollback with health check pass. |
| RRB-004 | Rollback failed: emitted with failure reason when any step or health check fails. |

## Invariants

| ID               | Statement                                                                                      |
|------------------|------------------------------------------------------------------------------------------------|
| INV-RRB-DETERM   | Applying a rollback bundle produces a state that is byte-identical to the pre-upgrade snapshot (where applicable). |
| INV-RRB-IDEMPOT  | Applying the same rollback bundle twice produces identical post-rollback state.                 |
| INV-RRB-HEALTH   | The health check sequence must pass for rollback to be considered successful.                   |
| INV-RRB-MANIFEST | The restore manifest lists every bundle component with a correct SHA-256 checksum.             |

## Error Codes

| Code                      | Meaning                                                         |
|---------------------------|-----------------------------------------------------------------|
| ERR-RRB-MANIFEST-INVALID  | The restore manifest is malformed or has invalid checksums.     |
| ERR-RRB-CHECKSUM-MISMATCH | A bundle component's checksum does not match the manifest.      |
| ERR-RRB-HEALTH-FAILED     | One or more post-rollback health checks failed.                 |
| ERR-RRB-VERSION-MISMATCH  | The bundle targets a different version than the current install. |

## Quantitative Targets

| Metric                        | Target                                       |
|-------------------------------|----------------------------------------------|
| Bundle integrity hash         | SHA-256 (64 hex chars)                       |
| Restore time ceiling          | < 60 seconds for standard deployment         |
| Health check timeout          | 30 seconds per check                         |
| Max bundle component count    | 64 components per bundle                     |
| Idempotency guarantee         | Byte-identical state after repeated applies  |

## Restore Manifest Format

```text
{
  "manifest_version": "1.0.0",
  "source_version": "1.4.2",
  "target_version": "1.4.1",
  "created_at": "2026-02-20T12:00:00Z",
  "components": [
    { "name": "binary_ref", "checksum": "a1b2c3...", "order": 1 },
    { "name": "config_diff", "checksum": "d4e5f6...", "order": 2 },
    { "name": "state_reversal", "checksum": "789abc...", "order": 3 }
  ],
  "health_checks": ["binary_version", "config_schema", "state_integrity", "smoke_test"],
  "compatibility": { "rollback_from": "1.4.2", "rollback_to": "1.4.1" }
}
```

## Health Check Sequence

After rollback, the following health checks run in order:

1. **Binary version verification** -- Confirm active binary matches target version.
2. **Configuration schema validation** -- Validate config matches target version schema.
3. **State integrity check** -- Verify state checksums match pre-upgrade snapshot.
4. **Core workflow smoke tests** -- Run migration scan, compatibility check, and
   policy evaluation to ensure core paths work.

All checks must pass for rollback to be considered successful.

## Dependencies

- `bd-2pw` (artifact signing) -- provides checksum infrastructure.
- 10.3 state migration system -- for migration reversal scripts.
- `bd-n9r` (config system) -- for config diff generation.
- 10.13 health gate -- for health check infrastructure.

## Implementation

- `crates/franken-node/src/connector/rollback_bundle.rs` -- core module.
- Wired in `crates/franken-node/src/connector/mod.rs`.
- Verification: `scripts/check_rollback_bundles.py`.
- Tests: `tests/test_check_rollback_bundles.py`.
