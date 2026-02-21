# Policy: Benchmark/Verifier External Usage

**Bead:** bd-3e74
**Section:** 13 (Program Success Criteria Instrumentation)
**Owner:** CrimsonCrane
**Effective:** 2026-02-20

## Purpose

This policy governs the tracking, validation, and gating of external usage of
franken_node's benchmark suite and verifier tools. External adoption is a key
ecosystem health signal and a prerequisite for release gates.

## Scope

This policy applies to:

- All benchmark suites published by the franken_node project
- All verifier tools distributed to third parties
- All external usage tracking and reporting
- Release gate decisions that depend on external adoption metrics

## Risk

Without external adoption tracking, the project cannot demonstrate that its
benchmark and verification claims are independently validated. This creates
risk of:

- Credibility gap: claims cannot be independently verified
- Ecosystem stagnation: no feedback loop from external users
- Gate bypass: release decisions made without external validation evidence

## Impact

External usage metrics directly affect release gate decisions. Insufficient
external adoption blocks progression through alpha, beta, and GA gates.

## Metric Definitions

### External Project Adoption

The number of distinct third-party projects or organizations that have executed
the franken_node benchmark suite. Each adoption must be accompanied by a valid
execution receipt containing environment fingerprint and artifact hash.

**Target:** >= 3 external projects or organizations.

### External Validation Parties

Number of external parties that perform independent validation using the
verifier toolkit. Tracked via usage reports or attestations.

**Target:** >= 2 external parties.

### External Citations

Number of external publications, blog posts, or conference presentations that
cite benchmark results. Tracked via citation tracking (manual + Scholar).

**Target:** >= 1 citation.

### Packaging Formats

Benchmark and verifier must be packaged in at least one externally consumable
format (npm, Docker, standalone binary). Each format must include a
self-contained getting-started guide and emit structured JSON output.

**Target:** >= 1 format.

### Getting Started Time

Time for a new external user to complete their first benchmark run, following
the getting-started guide.

**Target:** <= 15 minutes.

### Tracking Channels

Number of independent channels actively tracking external usage (npm downloads,
Docker pulls, GitHub stars, GitHub forks, citations, usage reports).

**Target:** >= 2 channels.

## Adoption Tiers

| Tier | Requirements                                                     | Gate Level |
|------|------------------------------------------------------------------|------------|
| U0   | No external usage detected                                       | None       |
| U1   | >= 1 external user, < 3 project adoptions                        | None       |
| U2   | >= 2 external validation parties                                 | Alpha      |
| U3   | >= 3 external projects or organizations adopt the benchmark      | Beta       |
| U4   | >= 1 external publication or presentation cites benchmark results | GA         |

**Success threshold:** U3 and U4 must both be achieved for the GA release gate
to pass. U3 ensures breadth of adoption; U4 ensures academic/industry
recognition.

## Event Codes

| Code    | Description                         | Required Fields                          |
|---------|-------------------------------------|------------------------------------------|
| BVE-001 | External benchmark adoption         | party_hash, env_fingerprint, artifact_hash |
| BVE-002 | External validation report          | party_hash, tool_version, channel        |
| BVE-003 | External citation detected          | party_hash, citation_ref, source         |
| BVE-004 | Usage metric snapshot computed      | metric_snapshot, tier, timestamp         |

All events must include ISO-8601 timestamp and correlation ID.

## Invariants

### INV-BVE-PACKAGE

Benchmark and verifier are packaged in at least one externally consumable
format. Each package must include installation instructions, a getting-started
guide, and produce structured JSON output. Packaging is validated as part of
the release pipeline.

### INV-BVE-GUIDE

Getting-started guide enables first benchmark run within 15 minutes. The guide
must cover prerequisites, installation, configuration, execution, output
interpretation, and CI integration example.

### INV-BVE-TRACK

External usage is tracked via at least two independent channels. Channels
include npm downloads, Docker pulls, GitHub stars, GitHub forks, citation
tracking, and usage reports. Each channel must be independently queryable.

### INV-BVE-REPORT

External usage report is generated with download counts, known users, and
citation list. The report is produced periodically (at minimum before each
gate decision) and includes all active tracking channel data.

## Provenance Requirements

Each external usage event must include:

1. **Party identifier:** SHA-256 hash of the external party's verified identity
2. **Timestamp:** ISO-8601 with timezone, recorded at event source
3. **Environment fingerprint:** OS, CPU architecture, memory, runtime versions
4. **Artifact hash:** SHA-256 of the benchmark or verifier artifact used
5. **Correlation ID:** UUID v4 linking related events in a session

## Sybil Defense

To prevent metric inflation through fake external parties:

1. Party identifiers are derived from verifiable identities (e.g., GitHub org)
2. A minimum of 7 days must elapse between first registration and first
   counted adoption event for a new party
3. Reproduction attempts are validated against reference results server-side
4. Anomalous patterns (burst registrations, identical environments) trigger
   manual review

## CI Integration

The verification script supports CI gate integration:

```bash
python scripts/check_benchmark_external.py --json
```

Exit code 0 indicates all checks pass (PASS verdict). Non-zero exit indicates
at least one check failed (FAIL verdict). The `--json` flag produces
machine-readable output for pipeline consumption.

## Monitoring and Alerting

- Dashboard tracks all six metric dimensions in real time
- Alert when any metric regresses below its target threshold
- Weekly digest of adoption tier changes
- Monthly report of external usage activity

## Escalation

- If adoption tier drops below gate threshold: block release pipeline
- If external validation parties drop below 2: investigate outreach
- If no citations after 6 months: increase publication and presentation efforts
- If Sybil defense triggers: manual review within 48 hours

## Evidence Requirements

All gate decisions must be backed by:

1. Aggregated metric snapshot at decision time
2. Event log covering the measurement window
3. Sybil defense audit report
4. External usage report with download counts, known users, and citations
