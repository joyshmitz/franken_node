# bd-33kj: Claim-Language Policy for Trust/Replay Claims -- Verification Summary

**Section:** 10.15 | **Bead:** bd-33kj | **Date:** 2026-02-22

## Gate Result: PASS

| Metric | Value |
|--------|-------|
| Claim types defined | 3 (trust, replay, safety) |
| Approved templates | 6 |
| Prohibited phrasings | 5 |
| Conformance tests | 18 |
| Broken references | 0 |
| Prohibited violations | 0 |

## Implementation

- `docs/policy/claim_language_asupersync_requirements.md` -- Policy document defining claim taxonomy, approved templates, prohibited phrasings, and enforcement rules
- `tests/conformance/claim_language_gate.rs` -- Rust conformance test module that scans documentation for claim-like language and validates evidence anchors
- `artifacts/10.15/claim_language_gate_report.json` -- Structured gate report (initial baseline)
- `artifacts/section_10_15/bd-33kj/verification_evidence.json` -- Verification evidence record
- `artifacts/section_10_15/bd-33kj/verification_summary.md` -- This summary

## What Was Implemented

### Claim Taxonomy (Section 1)

Three claim types are formally defined with required evidence references:

1. **Trust claims** -- assertions about integrity, authenticity, or provenance guarantees. Require `INV-EP-*` invariant references.
2. **Replay claims** -- assertions about deterministic reproducibility of operations. Require `INV-EP-*` or `INV-RP-*` invariant references.
3. **Safety claims** -- assertions about behavior under failure or attack conditions. Require `INV-EP-*`, `INV-SF-*`, or `INV-CR-*` invariant references.

### Approved Claim Templates (Section 2)

Six approved templates with embedded evidence references:

- T-TRUST-01: Epoch-Scoped Trust Binding
- T-TRUST-02: Fail-Closed Epoch Availability
- T-REPLAY-01: Deterministic Execution Replay
- T-REPLAY-02: Incident Bundle Reconstruction
- T-SAFETY-01: Compromise Reduction via Evidence-by-Default
- T-SAFETY-02: Immutable Creation Epoch

### Prohibited Phrasings (Section 3)

Five prohibited phrasings that trigger hard gate failure:

- "military-grade security"
- "guaranteed uptime"
- "incredibly reliable"
- "enterprise-grade"
- "unbreakable"

### Claim Language Gate (conformance test)

The gate test module provides:

- File scanning via `std::fs` and `std::path::Path`
- Claim detection using keyword matching for trust, replay, and safety keywords
- Evidence anchor validation (inline `[verified by ...]` or HTML comment annotations)
- Prohibited phrasing detection (case-insensitive)
- Broken reference detection (file existence check)
- Structured report output

### Conformance Test Coverage

- `test_approved_claim_passes` -- validates that claims with evidence anchors pass
- `test_vague_claim_detected` -- validates that claims without evidence anchors are rejected
- `test_prohibited_phrasing_detected` -- validates that prohibited language is caught
- `test_broken_evidence_reference` -- validates that references to non-existent files are flagged
- Additional tests for claim type detection, evidence anchor parsing, report formatting, case insensitivity, and edge cases

## Verdict

**PASS** -- All artifacts produced, policy document complete, conformance tests cover required scenarios, no prohibited phrasings or broken references detected in baseline scan.
