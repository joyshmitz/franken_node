# bd-pga7: Verification Summary

## Deterministic Incident Containment and Explanation

**Section:** 13 (Program Success Criteria)
**Status:** PASS
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Overview

This bead establishes the success criterion that incident containment and
root-cause explanation are deterministic and reproducible. Given the same
incident telemetry, the same containment actions are taken. Given the same
evidence bundle, the same root-cause explanation is produced.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_13/bd-pga7_contract.md` |
| Policy document | `docs/policy/deterministic_incident_containment.md` |
| Verification script | `scripts/check_incident_containment.py` |
| Unit tests | `tests/test_check_incident_containment.py` |
| Verification evidence | `artifacts/section_13/bd-pga7/verification_evidence.json` |
| Verification summary | `artifacts/section_13/bd-pga7/verification_summary.md` |

## Key Properties

- **Containment determinism:** Same incident telemetry always produces same containment actions (INV-DIC-CONTAIN)
- **Explanation reproducibility:** Same evidence bundle always produces same root-cause explanation (INV-DIC-EXPLAIN)
- **Blast radius bound:** Maximum 3 components affected before containment activates (INV-DIC-BOUND)
- **Evidence completeness:** >= 95% of relevant telemetry captured in evidence bundle (INV-DIC-COMPLETE)

## Quantitative Targets

| Metric | Target | Status |
|--------|--------|--------|
| blast_radius | <= 3 components | Documented |
| time_to_contain | <= 60 seconds | Documented |
| evidence_completeness | >= 95% | Documented |
| explanation_reproducibility | 100% | Documented |

## Event Codes

| Code | Description | Status |
|------|-------------|--------|
| DIC-001 | Incident contained deterministically | Documented |
| DIC-002 | Containment divergence detected | Documented |
| DIC-003 | Explanation produced | Documented |
| DIC-004 | Explanation divergence detected | Documented |

## Invariants

| ID | Status |
|----|--------|
| INV-DIC-CONTAIN | Documented in spec |
| INV-DIC-EXPLAIN | Documented in spec |
| INV-DIC-BOUND | Documented in spec |
| INV-DIC-COMPLETE | Documented in spec |

## Predecessor

- **bd-2a4l:** Externally Verifiable Trust/Security Claims -- establishes the evidence
  bundle and claim registry framework that this bead builds upon for incident
  containment and explanation evidence.
