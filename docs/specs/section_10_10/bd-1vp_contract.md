# bd-1vp Contract: Zone/Tenant Trust Segmentation Policies

**Bead:** bd-1vp
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Implement trust boundary segmentation between zones and tenants in a
multi-tenant deployment of franken_node. Different organizational units must
operate within cryptographically enforced trust boundaries -- a team's control
actions, tokens, and policies must not leak into or affect another team's zone.
Without zone segmentation, the no-ambient-authority invariant (8.5) is violated
at the organizational level: any authenticated entity could potentially affect
resources outside its intended scope.

This bead delivers the product-level zone segmentation policy engine that
partitions the trust domain into isolated zones, each with its own policy
namespace, key bindings, token scope, and delegation depth limit -- ensuring
that cross-zone operations require explicit, auditable authorization with
dual-owner bridge tokens.

## Dependencies

- **Upstream:** bd-2sx (zone deletion and bridge creation require freshness-gated authorization)
- **Upstream (implicit):** bd-1r2 (token chains carry zone claims)
- **Upstream (implicit):** bd-364 (zone-scoped key bindings)
- **Upstream (implicit):** bd-174 (zone changes recorded in checkpoint chain)
- **Downstream:** bd-1jjq (section-wide verification gate)
- **Downstream:** bd-13q (zone errors use stable error taxonomy)

## Data Structures

### IsolationLevel

Isolation enforcement level for a zone:

| Variant    | Description                                                     |
|------------|-----------------------------------------------------------------|
| Strict     | No cross-zone communication unless explicit bridge exists       |
| Permissive | Cross-zone reads allowed, writes require bridge authorization   |
| Custom     | Operator-defined isolation rules with explicit allowed actions  |

### ZonePolicy

Per-zone trust configuration:

| Field                     | Type              | Description                                        |
|---------------------------|-------------------|----------------------------------------------------|
| zone_id                   | String            | Globally unique zone identifier (domain-separated) |
| trust_ceiling             | u32               | Maximum trust score allowed in this zone (0-100)   |
| delegation_depth_limit    | u32               | Maximum delegation chain depth within zone         |
| allowed_cross_zone_targets| Vec\<String\>     | Zone IDs this zone may bridge to                   |
| isolation_level           | IsolationLevel    | Isolation enforcement level                        |

### TenantBinding

Binds a tenant to exactly one zone:

| Field               | Type     | Description                                    |
|---------------------|----------|------------------------------------------------|
| tenant_id           | String   | Unique tenant identifier                       |
| zone_id             | String   | Zone this tenant is bound to                   |
| trust_scope         | String   | Scoped trust capabilities for this tenant      |
| max_extension_count | u32      | Maximum number of trust extensions allowed     |

### CrossZoneRequest

Request to perform an action across zone boundaries:

| Field                | Type     | Description                                      |
|----------------------|----------|--------------------------------------------------|
| source_zone          | String   | Zone originating the request                     |
| target_zone          | String   | Zone where the action will take effect           |
| action               | String   | Action descriptor                                |
| requester            | String   | Identity of the requesting entity                |
| authorization_proof  | String   | Dual-owner bridge token or authorization proof   |

### ZoneSegmentationEngine

The core engine managing zone lifecycle and cross-zone authorization:

| Method               | Signature                                                          | Description                                   |
|----------------------|--------------------------------------------------------------------|-----------------------------------------------|
| register_zone()      | (&mut self, policy: ZonePolicy) -> Result<(), SegmentationError>   | Register a new zone with its policy           |
| bind_tenant()        | (&mut self, binding: TenantBinding) -> Result<(), SegmentationError>| Bind a tenant to a zone                      |
| authorize_cross_zone() | (&self, req: &CrossZoneRequest) -> Result<(), SegmentationError> | Authorize a cross-zone action                 |
| check_isolation()    | (&self, zone_id: &str) -> Result<IsolationLevel, SegmentationError>| Query isolation level for a zone              |
| resolve_zone()       | (&self, resource_id: &str) -> Result<String, SegmentationError>   | Resolve which zone owns a resource            |
| delete_zone()        | (&mut self, zone_id: &str) -> Result<(), SegmentationError>       | Delete a zone (requires freshness gate)       |

### SegmentationError

Error enumeration for zone segmentation failures:

| Variant                  | Description                                                 |
|--------------------------|-------------------------------------------------------------|
| CrossZoneViolation       | Action crosses zone boundary without authorization          |
| TenantNotBound           | Tenant has no zone binding                                  |
| ZoneNotFound             | Referenced zone does not exist                              |
| DelegationDepthExceeded  | Delegation chain depth exceeds zone's configured limit      |
| IsolationViolation       | Action violates zone isolation level policy                 |
| DuplicateZone            | Attempted to register a zone with an existing zone_id       |
| DuplicateTenant          | Tenant is already bound to a zone                           |
| BridgeAuthIncomplete     | Cross-zone bridge lacks dual-owner authorization            |
| FreshnessStale           | Zone deletion blocked -- freshness proof is stale           |
| KeyZoneMismatch          | Key not bound to the target zone                            |

## Invariants

- **INV-ZTS-ISOLATE:** Zone actions cannot affect other zones without explicit
  cross-zone authorization. A token with zone claim "zone-A" cannot authorize
  actions on resources in "zone-B".
- **INV-ZTS-CEILING:** Trust ceiling is enforced per zone. No entity within a
  zone may exceed the zone's configured trust ceiling score.
- **INV-ZTS-DEPTH:** Delegation depth is limited per zone. Delegation chains
  deeper than `delegation_depth_limit` are rejected.
- **INV-ZTS-BIND:** Tenants are bound to exactly one zone. A tenant cannot
  simultaneously belong to multiple zones.

## Event Codes

| Code    | Severity | Description                                                 |
|---------|----------|-------------------------------------------------------------|
| ZTS-001 | INFO     | Zone registered -- new zone created with policy             |
| ZTS-002 | INFO     | Tenant bound -- tenant assigned to zone                     |
| ZTS-003 | INFO     | Cross-zone authorized -- bridge action approved             |
| ZTS-004 | ERROR    | Isolation violation detected -- cross-zone action rejected  |

## Error Codes

| Code                          | Description                                              |
|-------------------------------|----------------------------------------------------------|
| ERR_ZTS_CROSS_ZONE_VIOLATION  | Action crosses zone boundary without bridge token        |
| ERR_ZTS_TENANT_NOT_BOUND      | Tenant has no zone binding                               |
| ERR_ZTS_ZONE_NOT_FOUND        | Zone does not exist in registry                          |
| ERR_ZTS_DELEGATION_EXCEEDED   | Delegation chain depth exceeds zone limit                |
| ERR_ZTS_ISOLATION_VIOLATION   | Action violates zone isolation policy                    |
| ERR_ZTS_DUPLICATE_ZONE        | Zone ID already registered                               |
| ERR_ZTS_DUPLICATE_TENANT      | Tenant already bound to a zone                           |
| ERR_ZTS_BRIDGE_INCOMPLETE     | Bridge authorization lacks dual-owner signature          |
| ERR_ZTS_FRESHNESS_STALE       | Zone deletion blocked by stale freshness proof           |
| ERR_ZTS_KEY_ZONE_MISMATCH     | Key not bound to target zone                             |

## Acceptance Criteria

1. `ZonePolicy` struct includes all required fields (zone_id, trust_ceiling,
   delegation_depth_limit, allowed_cross_zone_targets, isolation_level) with
   documented invariants.
2. Zone isolation is enforced: a token with zone claim "zone-A" cannot authorize
   actions on resources in "zone-B" -- rejected with `CrossZoneViolation`.
3. Cross-zone bridge requires dual-owner authorization: a bridge token must
   carry valid `authorization_proof`, and an incomplete proof is rejected with
   `BridgeAuthIncomplete`.
4. Zone deletion is freshness-gated: deletion without a valid freshness proof is
   rejected with `FreshnessStale`.
5. All zone boundary changes (create, delete, bridge) produce checkpoint events.
6. Zone-scoped key bindings restrict which keys are valid within a zone: using a
   key not bound to the target zone is rejected with `KeyZoneMismatch`.
7. Resource-to-zone resolution is deterministic and consistent: `resolve_zone()`
   returns the same zone for a given resource.
8. Verification evidence JSON includes zone count, cross-zone bridge scenarios
   tested, boundary violation rejection counts, and checkpoint coverage.
9. All four event codes (ZTS-001 through ZTS-004) emitted at correct severity.
10. All four invariants (INV-ZTS-ISOLATE, INV-ZTS-CEILING, INV-ZTS-DEPTH,
    INV-ZTS-BIND) enforced.
11. >= 25 unit tests covering zone registration, tenant binding, cross-zone
    authorization, isolation enforcement, delegation depth, and boundary
    conditions.

## Test Scenarios

### Scenario 1: Zone Registration
- Register zone "production" with trust_ceiling=90, delegation_depth=3, Strict isolation
- Expected: ZTS-001 emitted, zone queryable via resolve_zone

### Scenario 2: Tenant Binding
- Bind tenant "team-alpha" to zone "production"
- Expected: ZTS-002 emitted, tenant-zone mapping established

### Scenario 3: Cross-Zone Authorized
- Register zones "prod" and "staging" with cross-zone bridge
- Submit CrossZoneRequest with valid dual-owner authorization_proof
- Expected: ZTS-003 emitted, action authorized

### Scenario 4: Cross-Zone Violation
- Attempt cross-zone action without bridge authorization
- Expected: ZTS-004 emitted, SegmentationError::CrossZoneViolation

### Scenario 5: Delegation Depth Exceeded
- Zone has delegation_depth_limit=3, attempt delegation at depth 4
- Expected: SegmentationError::DelegationDepthExceeded

### Scenario 6: Duplicate Zone Registration
- Attempt to register zone with existing zone_id
- Expected: SegmentationError::DuplicateZone

### Scenario 7: Tenant Already Bound
- Attempt to bind tenant already bound to a zone
- Expected: SegmentationError::DuplicateTenant

### Scenario 8: Zone Deletion with Stale Freshness
- Attempt zone deletion without freshness proof
- Expected: SegmentationError::FreshnessStale

### Scenario 9: Strict Isolation
- Zone with Strict isolation, attempt any cross-zone action without bridge
- Expected: ZTS-004, SegmentationError::IsolationViolation

### Scenario 10: Resource-to-Zone Resolution
- Register resource-zone mappings, query resolve_zone
- Expected: Deterministic, consistent results

## Threshold

Zone isolation must achieve 0 boundary violation bypasses -- every unauthorized
cross-zone action must be rejected. Trust ceiling enforcement must be 100%
compliant with no elevation above the configured ceiling.

## Alert Pipeline

Zone boundary violations (ZTS-004) trigger immediate alert escalation to the
zone owner and security team. Repeated violations (>= 3 within 5 minutes)
trigger automatic zone lockdown and incident creation.

## Verification

- Script: `scripts/check_zone_segmentation.py --json`
- Evidence: `artifacts/section_10_10/bd-1vp/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-1vp/verification_summary.md`
