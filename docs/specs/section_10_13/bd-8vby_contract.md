# bd-8vby: Device Profile Registry and Placement Policy Schema

## Purpose

Maintain a registry of device profiles with validated schema and freshness checks. Placement policies reject invalid constraints. Policy evaluation is deterministic for execution targeting.

## Invariants

- **INV-DPR-SCHEMA**: Every registered device profile passes schema validation before acceptance.
- **INV-DPR-FRESHNESS**: Stale profiles (beyond max-age) are rejected from placement decisions.
- **INV-DPR-DETERMINISTIC**: Same profiles + same policy → same placement result.
- **INV-DPR-REJECT-INVALID**: Placement policies with invalid constraints are rejected with a classified error.

## Types

### DeviceProfile

A device profile: device_id, capabilities (list), region, tier, registered_at epoch, schema_version.

### PlacementConstraint

A placement constraint: required_capabilities, preferred_region, min_tier, max_latency_ms.

### PlacementPolicy

Collection of constraints + freshness max-age.

### PlacementResult

Result of evaluating a policy against registered profiles: matched devices, rejected devices with reasons, trace_id.

### DeviceProfileRegistry

Registry holding profiles, supporting register/deregister/query/evaluate_placement.

## Functions

- `register(profile)` → validates schema, adds to registry
- `deregister(device_id)` → removes from registry
- `evaluate_placement(policy, now)` → `PlacementResult`
- `validate_profile(profile)` → `Result<(), RegistryError>`
- `validate_constraints(constraints)` → `Result<(), RegistryError>`

## Error Codes

- `DPR_SCHEMA_INVALID` — profile fails schema validation
- `DPR_STALE_PROFILE` — profile exceeds freshness max-age
- `DPR_INVALID_CONSTRAINT` — placement constraint is malformed
- `DPR_NO_MATCH` — no profiles match placement policy
