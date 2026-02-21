# bd-3e74 -- Success Criterion: Benchmark/Verifier External Usage

**Section:** 13 (Program Success Criteria Instrumentation)
**Bead:** bd-3e74
**Status:** in-progress
**Owner:** CrimsonCrane

## Summary

Defines the success criterion for external adoption of franken_node's benchmark
suite and verification tools by third parties. External usage is an ecosystem
health signal: when independent parties run, reproduce, and attest to benchmark
results, the project's claims gain credibility and the ecosystem grows in a
verifiable manner.

## Quantitative Targets

| Metric                         | Target    | Measurement Point                         |
|--------------------------------|-----------|-------------------------------------------|
| external_project_adoption      | >= 3      | Third-party projects/organizations running benchmarks |
| external_validation_parties    | >= 2      | External parties performing independent validation |
| external_citations             | >= 1      | Publications, blog posts, or conference presentations citing results |
| packaging_formats              | >= 1      | Externally consumable formats available (npm, Docker, binary) |
| getting_started_time           | <= 15 min | Time for new external user to complete first benchmark run |
| tracking_channels              | >= 2      | Independent tracking channels active |

## Metric Dimensions

### 1. External Project Adoption

The number of distinct third-party projects or organizations that have executed
the franken_node benchmark suite. Each adoption is registered via event code
BVE-001. Target: >= 3 external projects or organizations.

### 2. External Validation Parties

Number of external parties that perform independent validation using the
verifier toolkit. Tracked via usage reports or attestations. Event code
BVE-002. Target: >= 2 external parties.

### 3. External Citations

Number of external publications, blog posts, or conference presentations that
cite benchmark results. Tracked via citation tracking (manual + Scholar).
Event code BVE-003. Target: >= 1 citation.

### 4. Packaging Formats

Benchmark and verifier are packaged for easy external consumption. At least
one of the following formats must be available:

| Format | Distribution Channel |
|--------|---------------------|
| npm package | npm registry |
| Docker image | Docker Hub / GHCR |
| Standalone binary | GitHub Releases |

Each format must include a self-contained getting-started guide and emit
structured JSON output compatible with CI pipelines.

### 5. Getting Started Guide

Documentation includes a getting-started guide for external users that enables
first benchmark run in <= 15 minutes. The guide covers:

1. Prerequisites and dependency list
2. Installation command (one-liner preferred)
3. Minimal configuration for first run
4. Command to run benchmark or verifier
5. Output format and interpretation
6. CI integration example

### 6. Usage Tracking Channels

External usage is tracked via multiple independent channels:

| Channel | Metric |
|---------|--------|
| npm downloads | npm download counts |
| Docker pulls | Docker pull counts |
| GitHub stars | GitHub stars on benchmark repo |
| GitHub forks | GitHub forks on benchmark repo |
| Citations | Citation tracking via manual + Scholar |
| Usage reports | Submitted attestations / reports |

At least 2 of these channels must be active for the tracking invariant.

## Adoption Tiers

| Tier | Criteria                                                              |
|------|-----------------------------------------------------------------------|
| U0   | No external usage detected                                            |
| U1   | >= 1 external user, < 3 project adoptions                             |
| U2   | >= 2 external validation parties                                      |
| U3   | >= 3 external projects or organizations adopt the benchmark           |
| U4   | >= 1 external publication or presentation cites benchmark results     |

**Success threshold:** U3 and U4 must both be achieved for the release gate
to pass. U3 ensures breadth of adoption; U4 ensures academic/industry
recognition.

## Release Gate Thresholds

- **Alpha gate:** U2 or higher
- **Beta gate:** U3 or higher
- **GA gate:** U3 + U4

## Event Codes

| Code    | Name                              | Trigger                                           |
|---------|-----------------------------------|---------------------------------------------------|
| BVE-001 | External benchmark adoption       | Third-party project registers benchmark execution  |
| BVE-002 | External validation report        | Independent verification completed by external party |
| BVE-003 | External citation detected        | Benchmark results cited in external publication    |
| BVE-004 | Usage metric snapshot computed    | Periodic adoption measurement emitted              |

All events are emitted as structured JSON with ISO-8601 timestamps, external
party identifier (anonymized hash), and correlation ID.

## Invariants

| ID                  | Statement                                                           |
|---------------------|---------------------------------------------------------------------|
| INV-BVE-PACKAGE     | Benchmark and verifier are packaged in at least one externally consumable format |
| INV-BVE-GUIDE       | Getting-started guide enables first benchmark run within 15 minutes |
| INV-BVE-TRACK       | External usage is tracked via at least two independent channels     |
| INV-BVE-REPORT      | External usage report is generated with download counts, known users, and citation list |

## Provenance Requirements

Each external usage event must include:

- **Timestamp:** ISO-8601 format
- **Party identifier:** SHA-256 hash of the external party's identity
- **Execution environment:** OS, CPU architecture, runtime versions
- **Artifact hash:** SHA-256 of the benchmark or verifier artifact used
- **Correlation ID:** Unique identifier linking related events

## External Usage Report

The `external_usage_report.json` artifact must contain:

```json
{
  "report_date": "ISO-8601 timestamp",
  "bead_id": "bd-3e74",
  "download_counts": {
    "npm": 0,
    "docker": 0,
    "github_releases": 0
  },
  "known_external_users": [],
  "citations": [],
  "usage_tier": "U0",
  "tracking_channels_active": [],
  "packaging_formats_available": []
}
```

## Acceptance Criteria

1. Spec contract exists at `docs/specs/section_13/bd-3e74_contract.md` with all dimensions documented
2. Policy document exists at `docs/policy/benchmark_verifier_external_usage.md` with risk, impact, escalation, and monitoring
3. All four event codes (BVE-001 through BVE-004) are defined and documented in spec and policy
4. All four invariants (INV-BVE-PACKAGE, INV-BVE-GUIDE, INV-BVE-TRACK, INV-BVE-REPORT) are defined in spec and policy
5. External usage tiers (U0 through U4) are documented with criteria and evidence requirements
6. Packaging formats are documented with distribution channels
7. Quantitative targets are specified: external_project_adoption >= 3, external_validation_parties >= 2, external_citations >= 1
8. Getting-started guide requirements are documented with <= 15 minute time target
9. Usage tracking methods are documented with at least 6 tracking channels
10. External usage report schema is documented with required fields
11. Verification script passes all checks with PASS verdict
12. Evidence artifact and summary produced with PASS verdict

## Dependencies

- bd-1xao (Impossible-by-Default Adoption, closed) -- prerequisite success criterion
- bd-1ta (10.13 epic, closed) -- connector modules that benchmarks build upon

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_13/bd-3e74_contract.md` |
| Policy document | `docs/policy/benchmark_verifier_external_usage.md` |
| Verification script | `scripts/check_benchmark_external.py` |
| Python unit tests | `tests/test_check_benchmark_external.py` |
| Verification evidence | `artifacts/section_13/bd-3e74/verification_evidence.json` |
| Verification summary | `artifacts/section_13/bd-3e74/verification_summary.md` |
