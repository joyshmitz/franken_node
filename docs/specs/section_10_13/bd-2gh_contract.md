# bd-2gh: Connector Lifecycle Enum, Transition Table, and Illegal-Transition Rejection

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Define a deterministic finite state machine (FSM) for connector lifecycle management.
Every connector instance must transition through a known set of states with explicitly
permitted transitions. All other transitions are illegal and must be rejected with
stable, machine-parseable error codes.

## Terminology

- **Connector**: An extension integration class that bridges external functionality
  into the franken_node runtime via the extension host.
- **Lifecycle state**: One of eight mutually exclusive states a connector occupies.
- **Transition**: A directed edge in the FSM graph from one state to another.
- **Illegal transition**: Any (source, target) pair not in the permitted set.

## States

| State        | Kind       | Description                                      |
|--------------|------------|--------------------------------------------------|
| `Discovered` | initial    | Connector artifact detected, not yet verified.   |
| `Verified`   | happy-path | Integrity and signature checks passed.           |
| `Installed`  | happy-path | Connector binary/package placed in runtime.      |
| `Configured` | happy-path | Configuration applied and validated.              |
| `Active`     | happy-path | Connector is serving requests.                   |
| `Paused`     | non-happy  | Temporarily suspended by operator or policy.     |
| `Stopped`    | non-happy  | Gracefully stopped; may be reconfigured.         |
| `Failed`     | non-happy  | Error state requiring investigation or reset.    |

## Transition Table

Legal transitions (source → target):

| From         | To           | Trigger                          |
|--------------|--------------|----------------------------------|
| Discovered   | Verified     | Verification passes              |
| Discovered   | Failed       | Verification fails               |
| Verified     | Installed    | Installation completes           |
| Verified     | Failed       | Installation fails               |
| Installed    | Configured   | Configuration applied            |
| Installed    | Failed       | Configuration fails              |
| Configured   | Active       | Activation succeeds              |
| Configured   | Failed       | Activation fails                 |
| Active       | Paused       | Operator/policy pause            |
| Active       | Stopped      | Operator/policy stop             |
| Active       | Failed       | Runtime failure                  |
| Paused       | Active       | Resume                           |
| Paused       | Stopped      | Stop while paused                |
| Paused       | Failed       | Failure while paused             |
| Stopped      | Configured   | Reconfigure for restart          |
| Stopped      | Failed       | Cleanup failure                  |
| Failed       | Discovered   | Reset/retry from scratch         |

Total: 17 legal transitions out of 56 possible (8×7 excluding self-loops).

## Invariants

1. **INV-LIFECYCLE-COMPLETE**: Every (source, target) pair where source ≠ target has
   a deterministic outcome: either the transition succeeds or it is rejected.
2. **INV-LIFECYCLE-STABLE-ERRORS**: Illegal transitions return error code
   `ILLEGAL_TRANSITION` with the source state, target state, and permitted targets.
3. **INV-LIFECYCLE-NO-SELF**: Self-transitions (state → same state) are illegal.
4. **INV-LIFECYCLE-ATOMIC**: A transition either fully completes or leaves the
   connector in its original state.

## Error Codes

| Code                 | Meaning                                      |
|----------------------|----------------------------------------------|
| `ILLEGAL_TRANSITION` | Requested transition is not in permitted set  |
| `SELF_TRANSITION`    | Source and target are the same state          |

## Interface

```rust
pub enum ConnectorState {
    Discovered, Verified, Installed, Configured, Active, Paused, Stopped, Failed,
}

pub fn transition(from: ConnectorState, to: ConnectorState) -> Result<ConnectorState, LifecycleError>;
pub fn legal_targets(from: &ConnectorState) -> &[ConnectorState];
```

## Artifacts

- `crates/franken-node/src/connector/lifecycle.rs` — FSM implementation
- `tests/conformance/connector_lifecycle_transitions.rs` — Full transition matrix tests
- `artifacts/section_10_13/bd-2gh/lifecycle_transition_matrix.json` — Evidence
- `artifacts/section_10_13/bd-2gh/verification_evidence.json` — Gate evidence
- `artifacts/section_10_13/bd-2gh/verification_summary.md` — Human summary
