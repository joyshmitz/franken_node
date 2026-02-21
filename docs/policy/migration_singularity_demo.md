# Migration Singularity Demo Policy

**Bead:** bd-1e0 | **Section:** 10.9

## Purpose

This policy governs the operation, security, and reproducibility of the
migration singularity demo pipeline. The pipeline is both a technical proof
and a category marketing asset; it must therefore meet high standards for
correctness, reproducibility, and presentation quality.

## Pipeline Execution Policy

### Single-Command Invocation

The demo pipeline is triggered by a single command. No interactive prompts
or manual steps are permitted during pipeline execution. The operator provides
the target repository URL and pinned version; all subsequent stages run
autonomously.

### Stage Ordering

Pipeline stages execute in strict sequential order:

1. Discovery
2. Analysis (audit + risk map)
3. Migration plan generation (rewrite suggestions)
4. Execution (apply transformations)
5. Validation (test suite + benchmarks + security posture)
6. Rollback (conditional, only on validation failure)

No stage may be skipped. If a stage fails fatally, the pipeline halts and
produces a partial report covering all completed stages.

### Timeout Policy

Each stage has a maximum execution time:

| Stage | Timeout |
|-------|---------|
| Discovery | 30 seconds |
| Analysis | 120 seconds |
| Plan generation | 60 seconds |
| Execution | 120 seconds |
| Validation | 300 seconds |
| Rollback | 30 seconds |

If a stage exceeds its timeout, the pipeline emits the corresponding error
code and halts. The total pipeline execution time must not exceed 10 minutes
for a medium-sized project.

## Flagship Repository Selection

### Qualification Criteria

A repository qualifies as "flagship" when it meets ALL of the following:

- GitHub stars >= 10,000
- Weekly npm downloads >= 500,000
- Direct dependency count >= 5
- Test coverage >= 60% line coverage
- Active maintenance (commit within last 90 days)

### Pinned Versions

All flagship repositories are pinned to specific version tags. Version pins
are recorded in `fixtures/migration-demos/` configuration files. Changing a
pin requires updating the configuration and re-running the full pipeline to
regenerate evidence.

## Confidence Grading Policy

### Transformation Confidence Grades

| Grade | Threshold | Auto-Apply |
|-------|-----------|------------|
| High | >= 90% confidence | Yes, applied automatically |
| Medium | 70-89% confidence | Staged for review, not auto-applied |
| Low | < 70% confidence | Flagged only, never auto-applied |

### Confidence Calculation

Confidence is determined by:
- API compatibility band (safe = high base, conditional = medium base, unsafe = low base)
- Test coverage of the affected code path (higher coverage = higher confidence)
- Historical success rate of similar transformations
- Presence of type annotations (typed code = higher confidence)

## Rollback Policy

### Automatic Rollback Triggers

Rollback is triggered automatically when:
- Test pass rate drops below configurable threshold (default: 80% of baseline)
- Any critical test (marked as must-pass) fails
- Security posture degrades (trust verification fails)
- Performance regression exceeds configurable threshold (default: 20% slower)

### Rollback Completeness

Rollback must revert ALL transformations applied during the execution stage.
Partial rollback is not acceptable. If rollback itself fails, the pipeline
emits `ERR-MSD-ROLLBACK-INCOMPLETE` and preserves both the transformed and
original states for manual inspection.

## Evidence Integrity Policy

### Hash Chain

Every artifact produced by the pipeline includes a SHA-256 content hash.
The final evidence bundle includes a manifest listing all artifacts and their
hashes. The manifest hash serves as the root integrity proof.

### Reproducibility

The pipeline runs in a hermetic container with:
- Pinned base image (hash recorded in evidence)
- Pinned tool versions (Node.js, franken_node, npm)
- Pinned repository versions (git commit SHA)
- Deterministic build settings (no network access during transformation)

An external party reproducing the pipeline with the same inputs must obtain
bit-identical evidence artifacts (excluding timestamps).

## Migration Report Policy

### Publication Quality

The auto-generated Markdown migration report must be suitable for external
publication without manual editing. It must include:

- Executive summary (1-2 paragraphs)
- Migration verdict (pass/partial/fail)
- Before/after comparison tables
- Detailed findings organized by pipeline stage
- Confidence assessment per transformation category
- Recommended manual steps for low-confidence items
- Appendix: full evidence manifest with hashes

### Sensitive Data

The migration report must NOT include:
- Internal infrastructure details
- Credentials or tokens
- Unreleased API surface information
- Performance numbers that could be misleading without context

## Event Logging Policy

All pipeline events are logged at INFO level with structured JSON payloads.
Stage transitions emit MSD-002 events with stage name, duration, and outcome.
Failures are logged at ERROR level with root cause classification.

| Event Code | Level | Payload |
|------------|-------|---------|
| MSD-001 | INFO | repository URL, pinned version, pipeline run ID |
| MSD-002 | INFO | stage name, duration_ms, outcome (pass/fail) |
| MSD-003 | INFO | validation summary, test counts, performance deltas |
| MSD-004 | WARN | rollback reason, affected files count, rollback duration_ms |

## Compliance

This policy enforces invariants:

- **INV-MSD-PIPELINE**: All stages execute in order; no skipping.
- **INV-MSD-VALIDATION**: Only the project's own test suite is used for validation.
- **INV-MSD-ROLLBACK**: Automatic and complete rollback on validation failure.
- **INV-MSD-ARTIFACTS**: Every run produces integrity-hashed evidence.
