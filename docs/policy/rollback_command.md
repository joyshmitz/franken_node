# Rollback Command Policy

**Bead:** bd-nglx
**Section:** 11 (Evidence and Decision Contracts)
**Effective:** 2026-02-20

## Overview

This policy governs the `rollback_command` contract field required on every
change proposal in the franken_node governance system. The rollback command
ensures that every change is reversible by design, with deterministic
verification of successful reversion.

## Scope

All change proposals — including policy updates, configuration changes, schema
migrations, and code deployments — MUST include a conformant `rollback_command`
field before submission. No change proposal may be accepted without it.

## Required Fields

Every `rollback_command` object must contain:

| Field | Type | Constraint |
|-------|------|------------|
| `command` | string | Non-empty, no shell metacharacters |
| `idempotent` | boolean | Explicit declaration |
| `timeout_seconds` | integer | 1-120 inclusive |
| `verification_command` | string | Non-empty |
| `preconditions` | list[string] | May be empty |
| `affected_subsystems` | list[string] | At least one entry |
| `data_loss_risk` | enum | `none`, `minimal`, `partial`, `significant` |
| `requires_downtime` | boolean | Explicit declaration |

## Data Loss Risk Governance

The `data_loss_risk` field determines the approval workflow:

- **none / minimal**: Rollback may proceed without additional approval.
- **partial**: Rollback requires review by at least one peer operator before
  the change proposal is accepted.
- **significant**: Rollback requires explicit written approval from the
  designated authority. The change proposal must include an `approval_reference`
  linking to the approval record. Changes with `significant` data loss risk are
  subject to additional scrutiny during verification.

## Idempotency Requirements

When `idempotent` is `true`, the rollback command MUST:
- Produce the same end state regardless of how many times it is executed.
- Not fail or produce side effects on repeated execution.
- Be safe to retry after partial failure.

When `idempotent` is `false`, the system MUST:
- Execute the rollback command exactly once.
- Track execution state to prevent duplicate runs.
- Emit RBC-003 if re-execution is attempted.

## Timeout Enforcement

- Maximum allowed timeout: 120 seconds.
- The system MUST terminate rollback execution at the declared timeout.
- If termination occurs, event RBC-003 is emitted with detail "timeout".
- Rollbacks that consistently approach the timeout limit should be
  re-engineered or broken into smaller steps.

## Precondition Checking

Before executing a rollback:
1. Each precondition in the `preconditions` list is evaluated.
2. If any precondition fails, the rollback is skipped and RBC-004 is emitted.
3. The failing precondition is recorded in the event detail.

## Verification

After rollback execution:
1. The `verification_command` is executed.
2. Exit code 0 indicates success; RBC-002 is emitted.
3. Non-zero exit code indicates failure; RBC-003 is emitted.
4. Verification must complete within the same `timeout_seconds` window.

## Event Codes

| Code | When Emitted |
|------|--------------|
| RBC-001 | Rollback command executed |
| RBC-002 | Rollback verified (verification_command succeeded) |
| RBC-003 | Rollback failed (timeout or verification failure) |
| RBC-004 | Rollback skipped (precondition not met) |

## Invariants

| ID | Enforcement |
|----|-------------|
| INV-RBC-PRESENT | Every change proposal includes a rollback command |
| INV-RBC-IDEMPOTENT | Rollback commands marked idempotent are verified idempotent |
| INV-RBC-VERIFY | Rollback verification command confirms successful reversion |
| INV-RBC-TIMEOUT | Rollback execution completes within declared timeout |

## Upgrade Path

Change proposals created before this policy took effect are non-conformant.
They must be updated with a valid `rollback_command` field before resubmission.
No grandfather clause is provided.

## Downgrade Triggers

A rollback command is flagged as degraded when:
- The verification_command fails during dry-run validation.
- The timeout_seconds exceeds the 120-second maximum.
- The command contains shell metacharacters.
- The affected_subsystems list is empty.

## Compliance

Evidence of rollback command validation is maintained in structured JSON format.
The verification script (`scripts/check_rollback_command.py`) produces
machine-readable evidence suitable for audit and continuous integration.

## Appeal Process

If a change proposal cannot provide a conformant rollback command due to the
nature of the change (e.g., irreversible schema migration), the proposer must:
1. Document why rollback is infeasible.
2. Provide an alternative mitigation plan.
3. Obtain explicit approval from the governance authority.
4. The `data_loss_risk` must be set to `significant`.
