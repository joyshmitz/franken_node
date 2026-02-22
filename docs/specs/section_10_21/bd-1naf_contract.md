# bd-1naf Contract

## Scope
Section 10.21 BPET governance policy contract for thresholding, appeals, and evidence-backed overrides.

This contract defines the auditable decision flow used when BPET (Behavioral Phenotype Evolution Tracker)
classification outputs may trigger high-impact operational controls.

## Why This Exists
BPET is intentionally conservative for safety, but conservative models can produce false positives.
Operators need a bounded, auditable mechanism to challenge outcomes without creating silent bypass channels.

## Required Capabilities
1. Explicit threshold classes with deterministic escalation behavior.
2. False-positive handling workflow with bounded states.
3. Appeal lifecycle with initiation, review, and resolution semantics.
4. Override workflow requiring signed rationale and approver attribution.
5. Safety constraints that cannot be bypassed by override.
6. Structured audit trail with stable event codes and trace IDs.

## Decision States
- `detected`
- `triaged`
- `appealed`
- `override_requested`
- `override_approved`
- `override_rejected`
- `resolved`

## Event Codes
- `BPET-GOV-001` Threshold classification generated
- `BPET-GOV-002` False-positive triage started
- `BPET-GOV-003` Appeal submitted
- `BPET-GOV-004` Override request signed
- `BPET-GOV-005` Override approved (with bounded TTL)
- `BPET-GOV-006` Override rejected
- `BPET-GOV-007` Appeal resolved

## Safety Invariants
- `INV-BPET-GOV-EXPLICIT-THRESHOLDS`: Threshold bands are explicit and versioned.
- `INV-BPET-GOV-NO-SILENT-OVERRIDE`: Every override requires signed rationale and approver identity.
- `INV-BPET-GOV-BOUNDED-OVERRIDE`: Overrides have TTL and scope limits.
- `INV-BPET-GOV-APPEAL-AUDITABLE`: Appeal transitions are audit-logged end-to-end.
- `INV-BPET-GOV-HARD-STOPS`: Critical hard-stop categories cannot be overridden.

## Audit Schema
Each governance event entry MUST include:
- `event_code`
- `event_type`
- `decision_id`
- `trace_id`
- `timestamp`
- `actor_id`
- `threshold_band`
- `rationale`
- `signature`
- `status`

Override-specific events additionally include:
- `override_scope`
- `override_ttl_minutes`
- `approver_id`

Appeal-specific events additionally include:
- `appeal_id`
- `appeal_reason`
- `resolution`

## Acceptance Criteria
- False-positive handling, override, and appeal states are explicit and bounded.
- Every override emits signed rationale and approver attribution.
- Governance audit log entries are schema-valid and trace-linked.
- Hard-stop categories remain non-overridable.

## Evidence Artifacts
- Policy: `docs/policy/bpet_governance_policy.md`
- Rust test fixture: `tests/policy/bpet_override_audit.rs`
- Audit log sample: `artifacts/10.21/bpet_governance_audit_log.jsonl`
- Verification evidence: `artifacts/section_10_21/bd-1naf/verification_evidence.json`
- Verification summary: `artifacts/section_10_21/bd-1naf/verification_summary.md`
