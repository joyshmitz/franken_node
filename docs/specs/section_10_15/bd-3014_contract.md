# bd-3014: Integrate Canonical Remote Named-Computation Registry for Control-Plane Distributed Actions

## Summary

Integrates the canonical remote named-computation registry (bd-ac83, section 10.14) into
the control-plane layer by documenting the adoption mapping, creating a conformance
verification script, and producing an adoption report artifact.

## Scope

### Registry Integration

The canonical `ComputationRegistry` from `src/remote/computation_registry.rs` serves as
the single source of truth for all remote computation names used by control-plane modules.
This bead documents which control-plane operations map to registered computation names and
enforces that no module maintains a parallel dispatch table.

### Registered Computations

| Computation Name | Module | Description |
|-----------------|--------|-------------|
| connector.health_probe.v1 | connector/health_gate.rs | Remote health check |
| connector.rollout_notify.v1 | connector/rollout_state.rs | Rollout state notification |
| connector.fencing_acquire.v1 | connector/fencing.rs | Distributed fencing token |
| connector.migration_step.v1 | connector/lifecycle.rs | Migration step execution |
| federation.sync_delta.v1 | federation/ | Federation delta sync |

### Fail-Closed Behavior

Unregistered computation names produce `ERR_UNKNOWN_COMPUTATION`. This is validated by the
`validate_computation_name()` method on `ComputationRegistry`.

## Invariants

| ID | Statement |
|----|-----------|
| INV-CRA-CANONICAL | All control-plane remote operations use the canonical registry |
| INV-CRA-FAIL-CLOSED | Unregistered names produce ERR_UNKNOWN_COMPUTATION |
| INV-CRA-NO-DIVERGENT | No module maintains a parallel name-to-handler mapping |
| INV-CRA-VALIDATE | All remote dispatch goes through validate_computation_name() |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_UNKNOWN_COMPUTATION | Computation name not found in registry |
| ERR_MALFORMED_COMPUTATION_NAME | Name does not match domain.action.vN pattern |
| ERR_DUPLICATE_COMPUTATION | Attempt to register an already-registered name |

## Acceptance Criteria

1. Adoption document exists at `docs/integration/control_remote_registry_adoption.md`
2. All five computation names are documented with their source modules
3. Fail-closed contract with `ERR_UNKNOWN_COMPUTATION` is documented
4. Prohibition on divergent registries is documented
5. Adoption report artifact exists at `artifacts/10.15/remote_registry_adoption_report.json`
6. Verification script passes all checks
7. No connector or federation module contains a divergent name-to-handler mapping

## Dependencies

- **Upstream**: bd-ac83 (canonical computation registry, 10.14)
- **Downstream**: bd-20eg (section gate)

## Artifacts

| Artifact | Path |
|----------|------|
| Adoption document | `docs/integration/control_remote_registry_adoption.md` |
| Adoption report | `artifacts/10.15/remote_registry_adoption_report.json` |
| Verification script | `scripts/check_remote_registry_adoption.py` |
| Python tests | `tests/test_check_remote_registry_adoption.py` |
