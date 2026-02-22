# bd-876n: Cancellation Injection for Critical Control Workflows — Spec Contract

**Section:** 10.14 | **Bead:** bd-876n | **Status:** Active

## Purpose

Systematically cancels workflows at every identified await point to verify that
the system maintains its invariants under all possible cancellation timings.
Ensures leak-free and half-commit-free properties for all critical control
workflows: epoch transition barrier, marker append, root publication, evidence
commit, and eviction saga.

## Workflow Coverage

| Workflow                  | Bead   | Await Points |
|--------------------------|--------|-------------|
| Epoch transition barrier | bd-2wsm | 6           |
| Marker stream append     | bd-126h | 4           |
| Root pointer publication | bd-nwhn | 4           |
| Evidence commit          | —      | 4           |
| Eviction saga            | bd-1ru2 | 6           |

Total: 24 (workflow, await_point) test cases (minimum 20 required).

## Invariants

- **INV-CANCEL-LEAK-FREE**: no resource leaks after cancellation at any await point
- **INV-CANCEL-HALFCOMMIT-FREE**: no partial state visible after cancellation
- **INV-CANCEL-MATRIX-COMPLETE**: every (workflow, await_point) pair is tested
- **INV-CANCEL-DETERMINISTIC**: same cancellation point produces same outcome
- **INV-CANCEL-BARRIER-SAFE**: epoch barriers survive cancellation without partial state
- **INV-CANCEL-SAGA-SAFE**: eviction sagas compensate correctly on cancellation

## Event Codes

| Code                     | Description                          |
|--------------------------|--------------------------------------|
| CANCEL_INJECTED          | Cancellation injected at await point |
| CANCEL_LEAK_CHECK        | Resource leak check performed        |
| CANCEL_HALFCOMMIT_CHECK  | Half-commit check performed          |
| CANCEL_MATRIX_COMPLETE   | Full matrix execution complete       |
| CANCEL_WORKFLOW_START    | Workflow execution started           |
| CANCEL_WORKFLOW_END      | Workflow execution ended             |
| CANCEL_RESOURCE_SNAPSHOT | Resource snapshot taken              |
| CANCEL_STATE_SNAPSHOT    | State snapshot taken                 |
| CANCEL_CASE_PASSED       | Cancel test case passed              |
| CANCEL_CASE_FAILED       | Cancel test case failed              |

## Error Codes

| Code                         | Description                     |
|------------------------------|--------------------------------|
| ERR_CANCEL_LEAK_DETECTED     | Resource leak detected          |
| ERR_CANCEL_HALFCOMMIT        | Half-commit state detected      |
| ERR_CANCEL_MATRIX_INCOMPLETE | Matrix below minimum coverage   |
| ERR_CANCEL_UNKNOWN_WORKFLOW  | Unknown workflow reference       |
| ERR_CANCEL_INVALID_POINT     | Invalid await point index        |
| ERR_CANCEL_FRAMEWORK_ERROR   | Framework internal error         |
| ERR_CANCEL_STATE_MISMATCH    | State mismatch                   |
| ERR_CANCEL_TIMEOUT           | Cancellation test timeout        |

## Dependencies

- **bd-2wsm**: Epoch transition barrier (primary workflow under test)
- **bd-1ru2**: Cancel-safe eviction saga (another workflow under test)

Schema version: `ci-v1.0`
