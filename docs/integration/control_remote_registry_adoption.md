# Control-Plane Remote Registry Adoption

**Bead:** bd-3014 | **Section:** 10.15

## Overview

This document defines how the canonical remote named-computation registry
(bd-ac83, Section 10.14) is integrated into the control-plane layer.
All distributed actions use the same registry semantics with fail-closed
rejection for unknown computation names.

## Registered Computations

| Computation Name | Domain | Description | Timeout | Retry Policy |
|---|---|---|---|---|
| `connector.health_probe.v1` | connector | Remote health check probes | 5s | 2 retries, exponential backoff |
| `connector.rollout_notify.v1` | connector | Cross-node rollout coordination notifications | 10s | 1 retry |
| `connector.fencing_acquire.v1` | connector | Distributed fencing token acquisition | 5s | No retry (fail-fast) |
| `connector.migration_step.v1` | connector | Remote migration step execution | 30s | 3 retries, exponential backoff |
| `federation.sync_delta.v1` | federation | Cross-federation state delta synchronization | 15s | 2 retries |

All computation names follow the canonical format: `domain.action.vN` where
`domain` is the owning module, `action` is the operation in snake_case, and
`vN` is the schema version.

## Fail-Closed Contract

The canonical registry enforces fail-closed semantics:

1. Any computation name not registered in the canonical registry returns
   `RemoteComputationUnknown` error (stable error code: `ERR_UNKNOWN_COMPUTATION`).
2. Malformed computation names (not matching `domain.action.vN`) return
   `ERR_MALFORMED_COMPUTATION_NAME`.
3. These errors are **stable error classes** — they do not change across
   versions and downstream handlers can pattern-match on them.

## Prohibition on Divergent Registries

No module under `crates/franken-node/src/connector/` or
`crates/franken-node/src/federation/` may maintain a parallel
name-to-handler mapping. Specifically:

- No `HashMap<String, Box<dyn Handler>>` or `BTreeMap<String, fn(...)>` patterns.
- All computation dispatch goes through `ComputationRegistry::lookup()`.
- This is enforced by automated scanning in the verification gate.

## Error Handling

| Error Code | Trigger | Recovery |
|---|---|---|
| `ERR_UNKNOWN_COMPUTATION` | Unregistered computation name | Fail-closed, log, alert |
| `ERR_MALFORMED_COMPUTATION_NAME` | Name doesn't match `domain.action.vN` | Reject request |
| `ERR_DUPLICATE_COMPUTATION` | Re-registering an existing name | Reject registration |
| `ERR_REGISTRY_VERSION_REGRESSION` | Version downgrade attempt | Reject, keep current |
| `ERR_INVALID_COMPUTATION_ENTRY` | Entry with missing/invalid fields | Reject registration |

## Invariants

| ID | Rule |
|----|------|
| INV-CRA-FAIL-CLOSED | Unknown computation names always rejected |
| INV-CRA-NO-DIVERGENT | No parallel name-to-handler registries exist |
| INV-CRA-CANONICAL-NAME | All names match `domain.action.vN` format |
| INV-CRA-STABLE-ERROR | Error codes do not change across versions |
| INV-CRA-SINGLE-REGISTRY | One canonical registry instance per node |

## Startup Registration

At control-plane initialization, all 5 computations are registered with the
canonical `ComputationRegistry`. Registration happens during the lifecycle
init phase before any remote operations are dispatched.
