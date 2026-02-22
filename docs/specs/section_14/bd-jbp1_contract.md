# bd-jbp1 — Replay Determinism and Artifact Completeness Metrics

**Section:** 14 — Benchmark & reporting
**Bead:** bd-jbp1
**Status:** Implementation

## Overview

Validates that replayed operations produce identical outputs and that all required
verification artifacts are present. Tracks hash-based output comparison, artifact
coverage by category, divergence detection, and provides release-gated enforcement.

## Artifact Categories

| Category               | Description                       |
|-----------------------|-----------------------------------|
| VerificationEvidence   | Machine-readable evidence JSON    |
| SpecContract           | Spec/contract document            |
| GateScript             | Verification gate script          |
| UnitTests              | Test suite files                  |
| CheckReport            | Gate check report JSON            |

## Event Codes

| Code         | Description                        |
|-------------|-------------------------------------|
| RDM-001     | Replay run recorded                 |
| RDM-002     | Comparison started                  |
| RDM-003     | Hash matched                        |
| RDM-004     | Divergence detected                 |
| RDM-005     | Artifact checked                    |
| RDM-006     | Completeness computed               |
| RDM-007     | Gate evaluated                      |
| RDM-008     | Report generated                    |
| RDM-009     | Category registered                 |
| RDM-010     | Version embedded                    |
| RDM-ERR-001 | Output divergence                   |
| RDM-ERR-002 | Incomplete artifacts                |

## Invariants

| ID                    | Rule                                                  |
|-----------------------|-------------------------------------------------------|
| INV-RDM-HASH          | Output hashes match between original and replay       |
| INV-RDM-COMPLETE      | All required artifact categories present              |
| INV-RDM-DETERMINISTIC | Same inputs produce same report hash                  |
| INV-RDM-GATED         | Divergences above threshold block release             |
| INV-RDM-VERSIONED     | Metric version embedded in every report               |
| INV-RDM-AUDITABLE     | Every comparison logged with event code               |

## Verification

- Gate script: `scripts/check_replay_determinism_metrics.py`
- Tests: `tests/test_check_replay_determinism_metrics.py`
- Min inline tests: 24
