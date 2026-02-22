# bd-3id1: External Red-Team and Independent Evaluations — Spec Contract

**Section:** 16 — Contribution: Open Datasets & Tooling
**Bead:** bd-3id1
**Status:** CLOSED

## Purpose

Publish external red-team reports and independent evaluation results with
scope tracking, finding severity classification, and remediation status.

## Acceptance Criteria

1. Five finding severity levels: Critical, High, Medium, Low, Informational.
2. Five evaluation types: RedTeam, PenetrationTest, SecurityAudit, IndependentReview, FormalVerification.
3. Remediation status tracking: Open → InProgress → Resolved → Verified.
4. Engagement scope and rules of engagement validation.
5. Confidence scoring for evaluation reports.
6. At least 12 event codes and 6 invariants.
7. At least 22 Rust unit tests.

## Invariants

| ID | Description |
|---|---|
| INV-RTE-SCOPED | Every engagement has defined scope and rules |
| INV-RTE-DETERMINISTIC | Same inputs produce same catalog output |
| INV-RTE-CLASSIFIED | Every finding has severity classification |
| INV-RTE-TRACKED | Every finding has remediation status tracking |
| INV-RTE-VERSIONED | Schema version embedded in every report |
| INV-RTE-AUDITABLE | Every state change produces audit record |

## Implementation

| Artifact | Path |
|---|---|
| Rust module | `crates/franken-node/src/tools/redteam_evaluations.rs` |
| Verification script | `scripts/check_redteam_evaluations.py` |
| Unit tests | `tests/test_check_redteam_evaluations.py` |
