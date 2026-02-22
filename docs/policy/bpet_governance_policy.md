# BPET Governance Policy

## Purpose
This policy governs how BPET model outputs are operationalized when they may trigger risky controls.
It balances fast containment with explicit false-positive and appeal handling.

## Policy Version
- Version: `v1`
- Owner: `security-governance`
- Review cadence: every 30 days or after any severity-1 incident

## Thresholding Policy
BPET risk scores are mapped to deterministic bands:
- `T0 Informational` (`< 0.35`): observe only
- `T1 Elevated` (`0.35 - 0.59`): require triage within SLA
- `T2 High` (`0.60 - 0.79`): apply reversible mitigations, open governance record
- `T3 Critical` (`>= 0.80`): apply containment, require dual-approval for override consideration

Threshold recalibration requires a policy change record and cannot be done ad hoc at runtime.

## False Positive Handling
1. Detection enters `triaged` state with owner and due time.
2. Triage requires explicit evidence notes:
   - phenotype features
   - observed behavior deltas
   - confidence decomposition
3. If false positive is confirmed, mitigation is rolled back and event `BPET-GOV-007` is emitted.

## Appeal Lifecycle
Appeals are required for disputed T2/T3 decisions.

Lifecycle:
1. `BPET-GOV-003` appeal filed with `appeal_id`, `appeal_reason`, and supporting evidence links.
2. Governance review board assigns reviewer and expected resolution time.
3. Resolution outcomes:
   - `upheld`
   - `partially_upheld`
   - `rejected`
4. Final resolution emits `BPET-GOV-007` and closes the decision trace.

## Override Workflow
Overrides are allowed only for non-hard-stop classes and must be explicit.

Required fields:
- `decision_id`
- `override_scope`
- `override_ttl_minutes`
- `rationale`
- `signature`
- `actor_id`
- `approver_id`

Flow:
1. `BPET-GOV-004` override requested with signed rationale.
2. Guardrails validate scope and TTL bounds.
3. If approved, emit `BPET-GOV-005`; if denied, emit `BPET-GOV-006`.

## Signed Rationale Requirements
Every override rationale must:
- identify the constrained objective (availability, legal, safety)
- reference concrete evidence IDs
- include cryptographic signature material
- include approver identity distinct from requester for T3

Unsigned rationale is invalid and rejected.

## Safety Constraints
Non-overridable hard-stop conditions:
- evidence tampering detection
- unsafe control-plane key-role violations
- unresolved revocation freshness hard failures

Even with appeal/override activity, hard-stop constraints remain active and cannot be overridden.

## Auditability and Logging
All governance actions must emit structured events with stable codes:
- `BPET-GOV-001` thresholded
- `BPET-GOV-002` triage started
- `BPET-GOV-003` appeal filed
- `BPET-GOV-004` override requested
- `BPET-GOV-005` override approved
- `BPET-GOV-006` override rejected
- `BPET-GOV-007` appeal resolved

Every event must include `trace_id` and `decision_id`.

## Deterministic Replay Rules
Given the same decision inputs and governance artifacts:
- threshold classification outcome must be deterministic
- appeal resolution state machine path must be deterministic
- override validity checks (scope/TTL/signature) must be deterministic

## Compliance Checklist
- [ ] Threshold bands documented and versioned
- [ ] False-positive triage flow documented
- [ ] Appeal lifecycle documented
- [ ] Override workflow requires signed rationale
- [ ] Hard-stop non-overridable conditions documented
- [ ] Stable event codes defined
- [ ] Audit schema fields defined
