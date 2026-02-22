---
schema: gate-v1.0
bead_id: bd-1rwq
section: "10.7"
title: "Section 10.7 Verification Gate"
---

# bd-1rwq: Section 10.7 Verification Gate

## Summary

Aggregates verification evidence from all Section 10.7 (Conformance + Verification)
beads and validates that the conformance and verification infrastructure is complete.
This gate ensures golden corpus coverage, fuzz testing, metamorphic testing, verifier
CLI conformance, trust vector adoption, and external reproduction readiness.

## Scope

### Upstream Beads

| Bead | Title | Domain |
|------|-------|--------|
| bd-2ja | Compatibility golden corpus and fixture metadata schema | Corpus |
| bd-s6y | Canonical trust protocol vectors from 10.13 + 10.14 | Vectors |
| bd-1ul | Fuzz/adversarial tests for migration and shim logic | Fuzz |
| bd-1u4 | Metamorphic tests for compatibility invariants | Metamorphic |
| bd-3ex | Verifier CLI conformance contract tests | CLI |
| bd-2pu | External-reproduction playbook and automation scripts | Reproduction |

### Coverage Requirements

- **Corpus bands**: core, high_value, edge, unsafe — all four must be covered
- **Trust vectors**: at least 4 sources and 8 vector sets verified
- **Fuzz corpus**: migration and shim directories populated with seeds
- **Metamorphic relations**: MR-EQUIV, MR-MONO, MR-IDEM, MR-COMM tested
- **Verifier CLI**: contract-driven checks all passing
- **Reproduction**: playbook and claims registry present and validated

## Invariants

| ID | Statement |
|----|-----------|
| INV-GATE-10-7-ALL-PASS | Every upstream bead must have a PASS verdict |
| INV-GATE-10-7-CORPUS-COMPLETE | Golden corpus covers all required compatibility bands |
| INV-GATE-10-7-FUZZ-COMPLETE | Fuzz tests exercise migration and shim domains |
| INV-GATE-10-7-REPRO-COMPLETE | External reproduction playbook is self-contained |
| INV-GATE-10-7-DETERMINISTIC | Gate verdict is deterministic given the same evidence |

## Event Codes

| Code | Description |
|------|-------------|
| GATE_10_7_EVALUATION_STARTED | Gate evaluation initiated |
| GATE_10_7_BEAD_CHECKED | Individual bead evidence evaluated |
| GATE_10_7_CORPUS_COVERAGE | Corpus band coverage validated |
| GATE_10_7_VERDICT_EMITTED | Final gate verdict produced |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_GATE_EVIDENCE_MISSING | Upstream bead evidence file not found |
| ERR_GATE_VERDICT_FAIL | Upstream bead has non-PASS verdict |
| ERR_GATE_CORPUS_INCOMPLETE | Required corpus band not covered |
| ERR_GATE_REPRO_MISSING | Reproduction playbook or claims registry missing |

## Acceptance Criteria

1. All 6 upstream beads have PASS verdicts in their verification evidence
2. Golden corpus covers core, high_value, edge, and unsafe bands
3. Fuzz corpus directories exist with populated seeds
4. Metamorphic test checks all pass
5. Verifier CLI contract checks all pass
6. External reproduction playbook and claims registry exist
7. Gate script and test suite pass

## Dependencies

- **Upstream**: bd-2ja, bd-s6y, bd-1ul, bd-1u4, bd-3ex, bd-2pu, bd-1dpd, bd-2twu
- **Downstream**: bd-2j9w (program-wide gate), bd-3rc (plan tracker)

## Artifacts

| Artifact | Path |
|----------|------|
| Gate script | `scripts/check_section_10_7_gate.py` |
| Test suite | `tests/test_check_section_10_7_gate.py` |
| Spec contract | `docs/specs/section_10_7/bd-1rwq_contract.md` |
| Verification evidence | `artifacts/section_10_7/bd-1rwq/verification_evidence.json` |
| Verification summary | `artifacts/section_10_7/bd-1rwq/verification_summary.md` |
