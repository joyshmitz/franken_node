# bd-1o4v Verification Summary

**Bead:** bd-1o4v
**Title:** Proof-verification gate API for control-plane trust decisions
**Section:** 10.18
**Verdict:** PASS

## Implementation

The proof-verification gate is implemented in `crates/franken-node/src/vef/proof_verifier.rs` and wired into the VEF module via `src/vef/mod.rs`.

### Core Types

| Type | Purpose |
|------|---------|
| `ProofVerifier` | Core verifier: validates a compliance proof against a single policy predicate |
| `VerificationGate` | Control-plane integration point managing predicates and producing reports |
| `VerificationGateConfig` | Configuration: max proof age, degrade threshold, policy version enforcement |
| `TrustDecision` | Trust outcome: Allow, Deny(reason), Degrade(level) |
| `PolicyPredicate` | Policy predicate with action class, confidence, witness, and freshness requirements |
| `ComplianceProof` | Compliance proof with identity, hash, confidence, expiry, and witness references |
| `VerificationRequest` | Request envelope with proof, timestamp, and trace context |
| `VerificationReport` | Full report with decision, evidence, events, and deterministic digest |
| `PredicateEvidence` | Per-check evidence for a single predicate evaluation |
| `DecisionSummary` | Aggregate summary of trust decisions rendered by the gate |

### Contract Compliance

- **INV-PVF-DETERMINISTIC:** Identical proof inputs and policy state produce identical trust decisions and report digests (tested with `deterministic_same_inputs_same_decision`).
- **INV-PVF-DENY-LOGGED:** Every Deny decision emits a PVF-004 event with reason and trace context (tested with `deny_decision_emits_deny_logged_event`).
- **INV-PVF-EVIDENCE-COMPLETE:** Every report includes 6 predicate evidence entries covering expiry, freshness, action class, confidence, witnesses, and policy version (tested with `evidence_includes_all_predicate_checks`).

### Trust Decision Logic

- **Allow:** All 6 predicate checks pass.
- **Deny:** Any hard failure (expired, stale, wrong action class, low confidence below degrade threshold, insufficient witnesses, policy version mismatch).
- **Degrade:** Confidence is below `min_confidence` but above `degrade_threshold` (partial satisfaction).

### Event Codes

| Code | Meaning |
|------|---------|
| PVF-001 | Verification request received |
| PVF-002 | Proof validated successfully |
| PVF-003 | Trust decision emitted |
| PVF-004 | Deny decision logged |
| PVF-005 | Degrade decision logged |
| PVF-006 | Verification report finalized |

### Error Codes

| Code | Meaning |
|------|---------|
| ERR-PVF-PROOF-EXPIRED | Proof expired or exceeds maximum age |
| ERR-PVF-POLICY-MISSING | No predicate for the action class |
| ERR-PVF-INVALID-FORMAT | Proof payload format invalid |
| ERR-PVF-INTERNAL | Internal verification error |

### Unit Tests (31)

1. `valid_proof_produces_allow_decision` -- valid proof gets Allow
2. `expired_proof_produces_deny_decision` -- expired proof gets Deny
3. `stale_proof_produces_deny_decision` -- old proof gets Deny with ERR-PVF-PROOF-EXPIRED
4. `missing_policy_predicate_produces_error` -- no predicate returns ERR-PVF-POLICY-MISSING
5. `empty_proof_id_produces_invalid_format_error` -- empty proof_id returns ERR-PVF-INVALID-FORMAT
6. `empty_proof_hash_produces_invalid_format_error` -- empty proof_hash returns ERR-PVF-INVALID-FORMAT
7. `deterministic_same_inputs_same_decision` -- identical inputs produce identical decisions and digests
8. `deny_decision_emits_deny_logged_event` -- deny always emits PVF-004 event
9. `evidence_includes_all_predicate_checks` -- reports contain 6 evidence entries
10. `report_digest_is_deterministic` -- digest recomputes identically
11. `very_low_confidence_produces_deny` -- confidence below degrade threshold denied
12. `marginal_confidence_produces_degrade` -- confidence between degrade and min produces Degrade
13. `insufficient_witnesses_produces_deny` -- too few witnesses denied
14. `policy_version_mismatch_produces_deny` -- wrong policy hash denied
15. `action_class_mismatch_produces_policy_missing_error` -- wrong class returns error
16. `register_and_remove_predicate` -- predicate lifecycle
17. `batch_verify_processes_all_requests` -- batch processes all
18. `decision_summary_counts_correctly` -- summary counts match
19. `all_events_contain_trace_id` -- trace propagation
20. `report_contains_schema_version` -- schema version in report
21. `request_received_event_emitted_first` -- PVF-001 is first event
22. `report_finalized_event_emitted_last` -- PVF-006 is last event
23. `policy_version_enforcement_disabled` -- enforcement toggle works
24. `no_witnesses_required_passes_with_empty_list` -- optional witnesses
25. `multiple_predicates_independent_verification` -- multiple action classes
26. `registering_predicate_overwrites_existing` -- overwrite semantics
27. `trust_decision_display_format` -- Display trait formatting
28. `verifier_error_display` -- error Display formatting
29. `empty_action_class_rejected_by_verifier` -- ProofVerifier format validation
30. `default_config_values` -- default config values correct
31. `report_created_at_matches_request_now` -- timestamp propagation

## Verification Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_18/bd-1o4v_contract.md` |
| Check script | `scripts/check_proof_verifier.py` |
| Test suite | `tests/test_check_proof_verifier.py` |
| Evidence JSON | `artifacts/section_10_18/bd-1o4v/verification_evidence.json` |
