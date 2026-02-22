# bd-cv49 — Published Security/Ops Improvement Case Studies

**Section:** 15 — Ecosystem Capture Strategy
**Bead:** bd-cv49
**Status:** Implementation
**Depends on:** bd-elog (safe-extension onboarding)

## Overview

This contract defines deterministic publication requirements for real-world
security and operational case studies. The objective is to make adoption claims
machine-verifiable and release-gated instead of narrative-only.

## Required Case Study Fields

Every case study MUST include:

1. Organization context (size/industry/anonymization state)
2. Pre-adoption security metrics
3. Post-adoption security metrics
4. Pre/post operational metrics
5. Migration effort and timeline
6. Lessons learned and concrete recommendations
7. Publication metadata (reviewed by featured organization, website status,
   external submission status, publication URL)

## Acceptance Thresholds

- At least **3** published case studies in the registry.
- At least **2** studies with measurable security improvement.
- All published studies reviewed by featured organizations before publication.
- At least **1** external publication or conference submission.
- A reusable partner-facing template is available.

## Event Codes

| Code | Description |
|------|-------------|
| `CSC-001` | Case study registered |
| `CSC-002` | Case study reviewed |
| `CSC-003` | Case study published to website |
| `CSC-004` | Case study submitted to external publication |
| `CSC-005` | Security improvement metrics recorded |
| `CSC-006` | Operational improvement metrics recorded |
| `CSC-007` | Registry summary generated |
| `CSC-008` | Registry gate passed |
| `CSC-009` | Registry gate failed |
| `CSC-010` | Schema version embedded in summary |
| `CSC-ERR-001` | Duplicate case-study id rejected |
| `CSC-ERR-002` | Invalid case-study payload rejected |
| `CSC-ERR-003` | Publication contract violation rejected |

## Invariants

| ID | Rule |
|----|------|
| `INV-CSC-PUBLISHED` | Registry contains >= 3 published case studies |
| `INV-CSC-MEASURED` | >= 2 studies show measurable security improvement |
| `INV-CSC-REVIEWED` | Every published case is reviewed by featured org |
| `INV-CSC-DISTRIBUTED` | >= 1 external publication/conference submission |
| `INV-CSC-TEMPLATE` | Stable case-study template exists for partner reuse |
| `INV-CSC-AUDITABLE` | Every mutation emits an audit record |

## Verification Surfaces

- Rust implementation: `crates/franken-node/src/tools/security_ops_case_studies.rs`
- Gate script: `scripts/check_case_study_registry.py`
- Python tests: `tests/test_check_case_study_registry.py`
- Registry evidence: `artifacts/15/case_study_registry.json`
- Bead evidence: `artifacts/section_15/bd-cv49/verification_evidence.json`
