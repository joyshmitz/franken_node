# bd-nglx Contract: Rollback Command

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.rollback_command` for subsystem proposals.

This field ensures every major subsystem proposal ships with a concrete,
tested rollback command and explicit rollback scope boundaries.

## Contract Field

Path:
- `change_summary.rollback_command`

Required sub-fields:
1. `command` (non-empty, copy-pasteable command string)
2. `idempotent` (boolean, must be `true`)
3. `tested_in_ci` (boolean, must be `true`)
4. `test_evidence_artifact` (non-empty artifact path that exists)
5. `rollback_scope` (object with explicit include/exclude lists)
6. `estimated_duration` (duration string such as `30s`, `2m`, or `1h30m`)

### command

Rules:
- MUST be a single-line executable command.
- MUST NOT contain unresolved placeholders.
- MUST be copy-pasteable without manual substitution.

Rejected placeholder patterns include:
- `<...>`
- `${...}`
- `{{...}}`
- `%s` / `%d`
- `TODO`

### idempotent and tested_in_ci

Rules:
- `idempotent` MUST be `true`.
- `tested_in_ci` MUST be `true`.
- `test_evidence_artifact` MUST point to an existing file.

### rollback_scope

Required fields:
- `reverts` (non-empty list of non-empty strings)
- `does_not_revert` (non-empty list of non-empty strings)

This contract requires explicit boundary declaration so operators understand
what is and is not reverted.

### estimated_duration

Rules:
- MUST be a non-empty duration string.
- Format must match compact duration tokens:
  - `NNs`
  - `NNm`
  - `NNh`
  - combinations like `1h30m`, `2m15s`.

## Enforcement

Validator:
- `scripts/check_rollback_command.py`

Unit tests:
- `tests/test_check_rollback_command.py`

CI gate:
- `.github/workflows/rollback-command-gate.yml`

## Event Codes

- `CONTRACT_ROLLBACK_COMMAND_VALIDATED` (info)
- `CONTRACT_ROLLBACK_COMMAND_MISSING` (error)
- `CONTRACT_ROLLBACK_COMMAND_INCOMPLETE` (error)

## Acceptance Mapping

- Rollback command required on every subsystem proposal: enforced by changed-file gate checks.
- Copy-pasteable command requirement: placeholder and multiline validation.
- Idempotent + CI-tested requirement: strict boolean checks plus evidence-artifact existence check.
- Scope boundaries: enforced `reverts` and `does_not_revert` non-empty arrays.
- Timing expectation: enforced duration format in `estimated_duration`.
