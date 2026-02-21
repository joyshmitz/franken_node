# Policy: Category-Shift Reporting Pipeline

**Bead:** bd-15t
**Section:** 10.9 -- Moonshot Disruption Track
**Effective:** 2026-02-20

## 1. Overview

This policy governs the category-shift reporting pipeline for franken_node.
Category-shift reports are the primary mechanism by which the project
demonstrates, with reproducible evidence, that franken_node changes what is
possible in the runtime security space. Every claim published in a
category-shift report must be independently verifiable.

## 2. Report Generation

### 2.1 Schedule

Category-shift reports are generated:
- On demand via pipeline invocation
- On a configurable schedule (default: monthly)
- Before every major release milestone

### 2.2 Data Source Requirements

The pipeline aggregates data from five mandatory source systems:

| Source | Bead | Required Data |
|--------|------|---------------|
| Benchmark infrastructure | bd-f5d | Throughput, latency, capability comparison |
| Adversarial campaign runner | bd-9is | Attack neutralization rates, coverage metrics |
| Migration demo pipeline | bd-1e0 | Success rates, time-to-migrate, complexity reduction |
| Verifier portal | bd-m8p | Registration count, attestation volume |
| Trust economics dashboard | bd-10c | Cost-benefit ratios, attacker-ROI deltas |

If a source is unavailable, the pipeline logs an ERROR and populates the
dimension with the most recent available data, clearly marking it as stale.

### 2.3 Freshness Window

Artifacts older than the configured freshness window (default: 30 days) are
flagged as stale. Stale artifacts may appear in the report but are annotated
with a warning and do not count toward threshold compliance.

## 3. Claim Integrity

### 3.1 Verification Before Inclusion

Every claim undergoes three-phase verification before inclusion:

1. **Existence check**: The referenced artifact file exists at the declared path.
2. **Integrity check**: The SHA-256 hash of the artifact matches the declared hash.
3. **Accuracy check**: The claim's numeric or categorical assertion matches the
   artifact's actual data (no selective reporting).

Claims that fail any phase are excluded from the report and logged at WARN.

### 3.2 Reproducibility

Each claim generates a "reproduce this claim" script that an independent party
can run to verify the claim. Scripts must:
- Be self-contained (no internal-only dependencies)
- Exit 0 when the claim is confirmed
- Exit non-zero with a diagnostic message when the claim diverges
- Complete within 5 minutes on standard hardware

## 4. Category-Defining Thresholds

Per the project charter (Section 3), every report MUST evaluate against:

| Threshold | Minimum | Status Values |
|-----------|---------|---------------|
| Compatibility | 95% API pass rate | `exceeded` / `met` / `not_met` |
| Migration velocity | 3x faster than manual | `exceeded` / `met` / `not_met` |
| Compromise reduction | 10x surface reduction | `exceeded` / `met` / `not_met` |

A report with any threshold at `not_met` status triggers an escalation review
within 5 business days.

## 5. Moonshot Bet Status

Each report includes a bet-status section for every moonshot initiative defined
in Section 9F. Bet status is one of:

| Status | Definition |
|--------|-----------|
| `on_track` | Progress matches or exceeds projected timeline |
| `at_risk` | Progress behind by <= 2 weeks with identified mitigation |
| `blocked` | Progress blocked with no current mitigation path |
| `completed` | Initiative delivered and verified |

## 6. Output Format Requirements

### 6.1 JSON Format

- Canonical JSON with sorted keys
- UTF-8 encoding
- Claim identifiers in format `CSR-CLAIM-{NNN}`
- Top-level fields: `version`, `generated_at`, `dimensions`, `thresholds`,
  `bet_status`, `manifest`, `claims`

### 6.2 Markdown Format

- GitHub-flavored Markdown
- Table-based data presentation
- Inline claim references matching JSON identifiers
- Summary dashboard at top

## 7. Versioning and Retention

- Each report is assigned a monotonically increasing version number.
- Reports are retained for at least 12 months.
- Diffs between consecutive versions are generated automatically.
- Threshold status transitions (pass to fail or vice versa) are highlighted
  in diff output.

## 8. Idempotency

The pipeline MUST produce byte-identical output when run with identical inputs.
This is enforced through:
- Deterministic data structure iteration (sorted maps)
- Canonical serialization (sorted keys, consistent separators)
- Injected timestamps (not wall-clock dependent)

## 9. Audit and Compliance

All pipeline executions are logged with:
- Trace correlation IDs for every operation
- Per-dimension timing measurements
- Claim verification outcomes (pass/fail with reason)
- Source system availability status

Logs are retained for at least 90 days and are queryable by trace ID.
