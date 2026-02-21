# bd-1xao: Impossible-by-Default Adoption Success Criterion

## Scope

Track and gate production-grade adoption of impossible-by-default capabilities.
The system must ensure that all dangerous or unsafe operations are architecturally
prevented unless explicitly enabled with auditable authorization. This bead
instruments the success criterion that measures how thoroughly the
impossible-by-default posture has been adopted across the codebase.

**Section:** 13 (Program Success Criteria Instrumentation)
**Predecessor:** bd-2hrg (Impossible-by-Default Capability Index)

## Purpose

franken_node enforces an impossible-by-default security posture: every dangerous
operation is blocked at the architecture level until an explicit, auditable
authorization grants access. This success criterion measures adoption coverage,
detects bypass attempts, validates authorization audit completeness, and
computes an overall adoption tier that gates release readiness.

Without this instrumentation, the project cannot objectively answer whether
impossible-by-default is a marketing claim or a measured reality.

## Capability States

Each dangerous capability tracked by the impossible-by-default framework
progresses through a strict state machine:

| State | Description |
|-------|-------------|
| BLOCKED | Default state. The capability is architecturally prevented. No code path can invoke it. |
| AUTHORIZED | An explicit authorization has been granted via the approval workflow. The capability may be activated. |
| ACTIVE | The capability is in active use under the granted authorization. |
| REVOKED | A previously granted authorization has been revoked. The capability returns to BLOCKED behavior. |

### State Transitions

```
BLOCKED -> AUTHORIZED  (via approval workflow, emits IBD-002)
AUTHORIZED -> ACTIVE   (via activation, emits IBD-002)
ACTIVE -> REVOKED      (via revocation, emits IBD-002)
REVOKED -> AUTHORIZED  (via re-approval, emits IBD-002)
BLOCKED -> ACTIVE      (FORBIDDEN: bypass attempt, emits IBD-003)
REVOKED -> ACTIVE      (FORBIDDEN: bypass attempt, emits IBD-003)
```

## Adoption Tiers

Coverage is computed as the ratio of dangerous operations that are properly gated
(state machine enforced) to the total number of identified dangerous operations.

| Tier | Coverage Range | Release Gate |
|------|---------------|--------------|
| A0 | < 50% | Not release-ready |
| A1 | 50% - 74% | Not release-ready |
| A2 | 75% - 89% | Not release-ready |
| A3 | 90% - 94% | Minimum for release gate |
| A4 | >= 95% | Full adoption |

**Success threshold:** A3 or higher is required to pass the release gate.

## Event Codes

| Code | Trigger |
|------|---------|
| IBD-001 | Capability blocked by default (initial gate enforcement verified) |
| IBD-002 | Capability authorization state transition (authorized, activated, or revoked) |
| IBD-003 | Bypass attempt detected (attempt to use capability without valid authorization) |
| IBD-004 | Adoption metric computed (periodic coverage calculation emitted) |

## Invariants

| ID | Statement |
|----|-----------|
| INV-IBD-DEFAULT | All identified dangerous operations are blocked by default with no code path bypassing the gate |
| INV-IBD-AUTH | Authorization is required for activation; no capability may transition from BLOCKED to ACTIVE without passing through AUTHORIZED |
| INV-IBD-AUDIT | All state transitions are recorded in the audit log with actor, timestamp, justification, and approval reference |
| INV-IBD-COVERAGE | Coverage metric must be >= 95% of identified dangerous operations for A4 tier, >= 90% for release gate |

## Quantitative Targets

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| capability_coverage | >= 95% for A4, >= 90% for release gate | Ratio of gated operations to total identified dangerous operations |
| bypass_detection_rate | 100% | Ratio of detected bypass attempts to total bypass attempts (verified via adversarial testing) |
| authorization_audit_completeness | 100% | Ratio of state transitions with complete audit records to total state transitions |
| operator_adoption_rate | >= 90% | Ratio of operators who have completed impossible-by-default training to total operators |
| mean_time_to_authorize | <= 24 hours | Average wall-clock time from authorization request to approval/denial decision |
| revocation_latency | <= 1 hour | Wall-clock time from revocation trigger to capability being fully blocked |

## Dangerous Operations Catalog

The following categories of dangerous operations must be gated:

| Category | Examples | Minimum Gates |
|----------|----------|---------------|
| Credential management | Key generation, certificate signing, secret rotation | 3 |
| Network exposure | Port opening, firewall rule modification, TLS downgrade | 3 |
| Data exfiltration paths | Bulk export, cross-boundary transfer, debug dump | 3 |
| Privilege escalation | Role elevation, capability grant, admin mode | 3 |
| Configuration override | Policy bypass, threshold override, safety limit change | 3 |

## Authorization Workflow

```
1. Operator submits authorization request with justification
2. Request is validated against policy constraints
3. Approval authority reviews and decides (approve/deny)
4. If approved: capability transitions to AUTHORIZED, IBD-002 emitted
5. If denied: capability remains BLOCKED, denial recorded in audit log
6. Activation: operator activates capability, IBD-002 emitted
7. Periodic review: active authorizations are reviewed on schedule
8. Revocation: authorization revoked when no longer needed, IBD-002 emitted
```

## Acceptance Criteria

1. Spec contract exists at `docs/specs/section_13/bd-1xao_contract.md` with all dimensions documented
2. Policy document exists at `docs/policy/impossible_by_default_adoption.md` with risk, impact, escalation, and monitoring
3. All four event codes (IBD-001 through IBD-004) are defined and documented in spec and policy
4. All four invariants (INV-IBD-DEFAULT, INV-IBD-AUTH, INV-IBD-AUDIT, INV-IBD-COVERAGE) are defined in spec
5. Capability states (BLOCKED, AUTHORIZED, ACTIVE, REVOKED) are documented with state transitions
6. Adoption tiers (A0 through A4) are documented with coverage thresholds and release gate criteria
7. Quantitative targets are specified: capability_coverage >= 95%, bypass_detection_rate = 100%, authorization_audit_completeness = 100%
8. Dangerous operations catalog is documented with categories and minimum gates
9. Authorization workflow is documented with full lifecycle
10. Verification script passes all checks with PASS verdict
11. Evidence artifact and summary produced with PASS verdict

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_13/bd-1xao_contract.md` |
| Policy document | `docs/policy/impossible_by_default_adoption.md` |
| Verification script | `scripts/check_impossible_adoption.py` |
| Python unit tests | `tests/test_check_impossible_adoption.py` |
| Verification evidence | `artifacts/section_13/bd-1xao/verification_evidence.json` |
| Verification summary | `artifacts/section_13/bd-1xao/verification_summary.md` |
