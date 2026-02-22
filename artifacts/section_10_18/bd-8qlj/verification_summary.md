# bd-8qlj Verification Summary

**Bead:** bd-8qlj
**Title:** VEF verification state in high-risk control transitions and action authorization
**Section:** 10.18
**Verdict:** PASS

## Implementation

The control-transition gate is implemented in `crates/franken-node/src/vef/control_integration.rs` and wired into the VEF module via `src/vef/mod.rs`.

### Core Types

| Type | Purpose |
|------|---------|
| `ControlTransitionGate` | Top-level gate evaluating transition requests against VEF evidence |
| `TransitionType` | Classification: CapabilityGrant, TrustLevelChange, ArtifactPromotion, PolicyOverride |
| `VerificationState` | Evidence state: Verified, Unverified, Expired, Invalid |
| `AuthorizationDecision` | Outcome: Authorized, Denied(DenialReason), PendingVerification |
| `VefEvidenceRef` | Reference to VEF evidence with scope, hash, state, and expiration |
| `TransitionRequest` | Request binding actor, target, transition type, and evidence references |
| `DenialReason` | Structured denial with error code, event code, and message |
| `GateEvent` | Structured event emitted during evaluation |
| `GatePolicy` | Configuration: evidence age, min count, trust level, per-type overrides |
| `GateMetrics` | Tracking: authorized/denied/pending counts per transition type |
| `ActorTrustContext` | Actor identity, trust level, and capabilities |

### Contract Compliance

- **INV-CTL-EVIDENCE-REQUIRED:** Every high-risk transition requires at least one valid VEF evidence entry. Transitions with no evidence are denied unconditionally.
- **INV-CTL-DENY-LOGGED:** Every denial emits a structured GateEvent with the corresponding CTL event code and human-readable reason.
- **INV-CTL-NO-BYPASS:** All four transition types return `true` from `requires_evidence()`. The `evaluate` method asserts this invariant and has no early-return paths that skip evidence validation.
- **Missing evidence:** Denied with ERR-CTL-MISSING-EVIDENCE / CTL-003.
- **Expired evidence:** Denied with ERR-CTL-EXPIRED-EVIDENCE / CTL-004.
- **Scope mismatch:** Denied with ERR-CTL-SCOPE-MISMATCH / CTL-005.
- **Invalid evidence:** Denied with ERR-CTL-INVALID-HASH / CTL-007.
- **Unverified evidence:** Produces PendingVerification decision / CTL-006.
- **Trust level enforcement:** Actors below the minimum trust level are denied with ERR-CTL-INSUFFICIENT-TRUST / CTL-008.
- **Per-transition overrides:** GatePolicy supports per-TransitionType min_evidence_count, max_evidence_age_millis, and min_trust_level overrides.
- **Batch evaluation:** `evaluate_batch` processes multiple requests in order.
- **Serde round-trip:** TransitionRequest and AuthorizationDecision serialize/deserialize correctly.

### Event Codes

| Code | Meaning |
|------|---------|
| CTL-001 | Transition request received |
| CTL-002 | Transition authorized |
| CTL-003 | Denied: missing evidence |
| CTL-004 | Denied: expired evidence |
| CTL-005 | Denied: evidence scope mismatch |
| CTL-006 | Pending verification |
| CTL-007 | Denied: invalid evidence hash |
| CTL-008 | Denied: insufficient trust level |

### Unit Tests (31)

1. `test_authorize_with_valid_evidence` -- valid evidence produces Authorized
2. `test_deny_missing_evidence` -- no evidence produces Denied (INV-CTL-EVIDENCE-REQUIRED)
3. `test_deny_expired_evidence` -- expired evidence produces Denied
4. `test_deny_scope_mismatch` -- wrong-scope evidence produces Denied
5. `test_deny_invalid_evidence_state` -- Invalid state produces Denied
6. `test_pending_verification_for_unverified` -- Unverified produces PendingVerification
7. `test_all_transition_types_require_evidence` -- INV-CTL-NO-BYPASS
8. `test_denial_emits_events` -- INV-CTL-DENY-LOGGED
9. `test_multiple_evidence_one_valid` -- mixed evidence, one valid suffices
10. `test_empty_hash_rejected` -- empty hash string rejected
11. `test_policy_override_min_evidence` -- per-type min_evidence enforced
12. `test_policy_override_min_evidence_satisfied` -- per-type min_evidence satisfied
13. `test_deny_insufficient_trust_level` -- trust level below minimum denied
14. `test_deny_evidence_too_old` -- evidence age exceeds max
15. `test_per_transition_type_metrics` -- per-type metrics tracked
16. `test_batch_evaluate` -- batch evaluation works
17. `test_drain_events` -- drain clears events
18. `test_schema_version_defined` -- schema version constant
19. `test_invariant_constants_defined` -- invariant constants
20. `test_transition_type_display` -- Display trait
21. `test_verification_state_validity` -- is_valid predicate
22. `test_evidence_ref_expiration` -- is_expired_at
23. `test_evidence_ref_scope_coverage` -- covers_transition
24. `test_set_now_millis` -- time advancement
25. `test_gate_policy_defaults` -- default policy values
26. `test_authorization_decision_predicates` -- is_authorized/denied/pending
27. `test_expired_verification_state_rejected` -- Expired state rejected
28. `test_denial_reason_display` -- DenialReason Display
29. `test_serde_roundtrip_transition_request` -- serde round-trip
30. `test_serde_roundtrip_authorization_decision` -- serde round-trip
31. `test_gate_event_trace_id_propagation` -- trace_id in events

## Verification Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/vef/control_integration.rs` |
| Module wiring | `crates/franken-node/src/vef/mod.rs` |
| Spec contract | `docs/specs/section_10_18/bd-8qlj_contract.md` |
| Check script | `scripts/check_vef_control_integration.py` |
| Test suite | `tests/test_check_vef_control_integration.py` |
| Evidence JSON | `artifacts/section_10_18/bd-8qlj/verification_evidence.json` |
