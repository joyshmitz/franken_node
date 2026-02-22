# Zone/Tenant Trust Segmentation Policy

**Bead:** bd-1vp
**Section:** 10.10 (FCP-Inspired Hardening)
**Risk Category:** Trust-System Boundary Violation

## Overview

This policy defines zone-level trust segmentation for multi-tenant deployments
of franken_node. Each zone operates as an isolated trust domain with its own
policy namespace, delegation limits, and key bindings. Cross-zone operations
require explicit dual-owner authorization through bridge tokens.

## Risk: Cross-Zone Trust Leakage

### Description

In a multi-tenant environment, organizational units (teams, projects, tenants)
share infrastructure. Without enforced trust boundaries, control actions from
one organizational unit can affect another -- violating the no-ambient-authority
invariant at the organizational level.

### Impact

**High.** Unauthorized cross-zone trust propagation could allow:
- A compromised tenant to escalate privileges across zone boundaries
- Policy changes in one zone to cascade into unrelated zones
- Token delegation chains to extend beyond organizational boundaries
- Key bindings to be reused across zones without authorization

### Likelihood

**Medium.** Multi-tenant deployments inherently create shared-resource
boundaries. Misconfiguration or missing zone checks can silently permit
cross-zone trust leakage.

## Countermeasures

### 1. Zone Isolation Enforcement (INV-ZTS-ISOLATE)

Every trust decision includes zone context. Actions targeting resources in a
different zone from the requester are rejected unless an explicit cross-zone
bridge exists. Zone claims are embedded in all tokens (via bd-1r2) and validated
at every authorization point.

**Enforcement:** The `ZoneSegmentationEngine` validates zone boundaries before
any trust-bearing action. Tokens without a zone claim are rejected outright.

### 2. Trust Ceiling Per Zone (INV-ZTS-CEILING)

Each zone has a configurable trust ceiling (0-100) that caps the maximum trust
score any entity can achieve within that zone. This prevents privilege
escalation within constrained environments (e.g., a staging zone should never
grant production-level trust).

**Enforcement:** The `ZonePolicy.trust_ceiling` field is checked against all
trust score computations within the zone.

### 3. Delegation Depth Limits (INV-ZTS-DEPTH)

Each zone configures a maximum delegation chain depth. This prevents unbounded
trust delegation that could create complex, hard-to-audit trust chains within
a zone. The complexity budget (bd-kiqr) operates per-zone, not globally.

**Enforcement:** `ZonePolicy.delegation_depth_limit` is checked at each
delegation step. Chains exceeding the limit are rejected with
`DelegationDepthExceeded`.

### 4. Single-Zone Tenant Binding (INV-ZTS-BIND)

Each tenant is bound to exactly one zone at any time. This ensures clear
ownership and prevents split-brain scenarios where a tenant's resources span
multiple zones with conflicting policies.

**Enforcement:** The `ZoneSegmentationEngine` maintains a tenant-to-zone map
and rejects duplicate bindings.

### 5. Cross-Zone Bridge Authorization

Cross-zone operations (resource migration, shared access) require a bridge
token signed by both zone owners. Single-owner signatures are rejected with
`BridgeAuthIncomplete`. Bridge establishment is recorded in the policy
checkpoint chain (bd-174) for auditability.

**Enforcement:** `authorize_cross_zone()` verifies dual-owner authorization in
the `CrossZoneRequest.authorization_proof` field.

### 6. Freshness-Gated Zone Deletion

Zone deletion is a Tier-1 critical action requiring freshness-gated
authorization (bd-2sx). Deletion without a valid freshness proof is rejected
with `FreshnessStale`. This prevents stale credentials from being used to
destroy zone infrastructure.

## Monitoring and Dashboard

Zone boundary events are tracked with structured logging:

- **Zone creation/deletion velocity:** Track rate of zone lifecycle events.
  Abnormal spikes indicate potential automation misuse.
- **Cross-zone authorization rate:** Dashboard widget showing bridge usage
  patterns. High cross-zone traffic may indicate misconfigured zone boundaries.
- **Isolation violation count:** Zero-tolerance metric. Any non-zero value
  triggers immediate alert escalation.
- **Delegation depth distribution:** Per-zone histogram showing delegation
  chain depths. Clusters near the limit indicate potential budget exhaustion.

## Escalation

Zone boundary violations (ZTS-004) follow the standard escalation path:

1. **Immediate:** Alert zone owner and security team within 30 seconds.
2. **Threshold:** >= 3 violations within 5 minutes triggers automatic zone
   lockdown (all cross-zone bridges suspended).
3. **Critical:** >= 10 violations within 1 hour triggers incident creation with
   P1 severity.
4. **Review:** All zone boundary changes require post-change review within 24h.

## Evidence Requirements

Verification evidence must include:

- Total zone count and per-zone isolation level
- Cross-zone bridge scenarios tested (authorized + rejected)
- Boundary violation rejection counts (must be 100% for unauthorized attempts)
- Checkpoint coverage for zone lifecycle events
- Review cadence compliance for recent zone changes
