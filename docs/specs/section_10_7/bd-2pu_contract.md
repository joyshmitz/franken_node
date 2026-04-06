# bd-2pu: External-Reproduction Playbook and Automation Scripts

## Bead: bd-2pu | Section: 10.7

## Purpose

Provides a self-contained external-reproduction playbook and automation scripts
that enable independent parties -- academic researchers, auditors, competing
runtime teams -- to reproduce franken_node's headline claims (compatibility,
security, performance) without insider knowledge or access to internal tooling.
Section 13 mandates ">= 2 independent external reproductions" as a success
criterion; this bead removes all barriers to achieving that goal.

## Scope

### Reproduction Playbook

A comprehensive written guide (`docs/reproduction_playbook.md`) covering:

1. **Environment setup**: OS requirements (Linux x86_64, macOS ARM64), Rust
   nightly toolchain version, Node.js version, Python 3.11+, dependency list
   with pinned versions.
2. **Fixture download**: Where to get test fixtures, expected SHA-256
   checksums, fallback fixture generation scripts.
3. **Benchmark execution**: Exact commands, expected wall-clock duration,
   resource requirements (CPU cores, memory).
4. **Result comparison**: How to interpret outputs, what constitutes pass/fail,
   acceptable variance ranges for performance numbers (e.g., +/-10% for
   latency benchmarks).
5. **Troubleshooting**: Common issues and solutions (missing system libraries,
   nightly-only features, platform differences).

### Automation Scripts

A single entry point (`scripts/reproduce.py`) that automates the entire
playbook:

- Installs dependencies (with user confirmation via `--yes` flag).
- Downloads or generates fixtures.
- Runs all verification suites.
- Collects results into a structured reproduction report.
- Supports `--skip-install` for pre-configured environments.
- Supports `--dry-run` to list steps without executing.
- Supports `--verbose` to print resolved command/status detail per claim.
- Is idempotent and can be re-run safely.

### Headline Claims Registry

A machine-readable file (`docs/headline_claims.toml`) listing each headline
claim with:

| Field | Description |
|-------|-------------|
| `claim_id` | Unique identifier (e.g., `HC-001`) |
| `claim_text` | Human-readable claim statement |
| `verification_method` | How the claim is verified (test suite, benchmark, audit) |
| `acceptance_threshold` | Quantitative pass/fail boundary |
| `test_reference` | Path to the specific test or benchmark |
| `procedure_ref` | Public procedure or evidence-bundle path the harness resolves before execution |
| `harness_kind` | Adapter used to execute the claim (`procedure`, `cargo_test`, `cargo_bench`, `cli`, or `python`) |
| `measurement_key` | Stable result field compared against `acceptance_threshold` |

The registry is the authoritative dispatch table for external reproduction.
The automation layer must resolve a claim through these mapping fields instead
of embedding claim-specific shortcuts in `scripts/reproduce.py`.

### Reproduction Report

The automation script produces a structured JSON report
(`reproduction_report.json`) containing:

| Field | Description |
|-------|-------------|
| `schema_version` | Report schema identifier for downstream automation |
| `run_mode` | `plan` for `--dry-run`, `executed` for real verification |
| `environment` | OS, CPU, memory, toolchain versions |
| `claims` | Per-claim results including mapping metadata, execution state, measurement, and artifact refs |
| `verdict` | Overall `PLANNED`, `PASS`, `FAIL`, or `ERROR` |
| `timestamp` | ISO-8601 UTC timestamp |
| `duration_seconds` | Total wall-clock duration |
| `execution_log` | Ordered structured events for plan resolution, claim execution, and report completion |

Per-claim results must carry:

- `execution_state` — `planned`, `executed`, `skipped`, or `error`
- `result_kind` — `not_run`, `pass`, `fail`, or `error`
- `procedure_ref`, `harness_kind`, and `measurement_key`
- `command`, `resolved_procedure_ref`, and `detail`
- `measured_value` only when execution actually occurred

`--dry-run` / planning output is explicitly non-evidence-bearing:

- `run_mode` MUST be `plan`
- `verdict` MUST be `PLANNED`
- each claim MUST emit `execution_state = planned` and `result_kind = not_run`
- an unexecuted claim MUST NOT be rendered as `PASS`

## Event Codes

| Code | When Emitted |
|------|--------------|
| ERP-001 | Playbook incomplete: missing required section or step |
| ERP-002 | Reproduction failure: a headline claim failed its threshold |
| ERP-003 | Environment mismatch: detected toolchain version differs from pinned |
| ERP-004 | Seed data missing: fixture file absent or checksum mismatch |

## Invariants

| ID | Statement |
|----|-----------|
| INV-ERP-COMPLETE | Playbook covers all 5 required sections (environment, fixtures, execution, comparison, troubleshooting) |
| INV-ERP-REPLAY | Automation script can replay the full verification flow from a clean state |
| INV-ERP-ENVIRONMENT | Environment fingerprint captures OS, CPU, memory, and all toolchain versions |
| INV-ERP-DETERMINISM | Given identical environment and fixtures, reproduction produces identical verdict |

## Error Codes

| Code | Condition |
|------|-----------|
| ERR_ERP_PLAYBOOK_MISSING | Playbook file not found |
| ERR_ERP_CLAIMS_MISSING | Headline claims registry not found or empty |
| ERR_ERP_SCRIPT_MISSING | Automation script not found |
| ERR_ERP_FIXTURE_CHECKSUM | Fixture file checksum does not match expected value |

## Dependencies

- Upstream: All verification gates from 10.2-10.6 (produce the results being reproduced)
- Upstream: bd-3lh (performance benchmarks / latency gates)
- Upstream: 10.2 compatibility test suite
- Downstream: bd-1rwq (section 10.7 verification gate)
- Downstream: bd-3rc (section 10.7 plan rollup)

## Acceptance Criteria

1. `docs/reproduction_playbook.md` provides complete step-by-step instructions
   for independent reproduction, assuming no insider knowledge.
2. `scripts/reproduce.py` automates the full reproduction flow as a single
   command with structured JSON output.
3. `docs/headline_claims.toml` lists every headline claim with verification
   method, acceptance threshold, test reference, and explicit
   claim-to-harness mapping fields (`procedure_ref`, `harness_kind`,
   `measurement_key`).
4. Reproduction report (`reproduction_report.json`) includes environment
   fingerprint, explicit `run_mode`, per-claim execution state, overall
   verdict, and timestamp.
5. The reproduction flow works with only publicly available tools and fixtures
   -- no internal CI access required.
6. Script is idempotent and supports `--skip-install` for pre-configured
   environments.
7. Verification script `scripts/check_external_reproduction.py` with `--json`
   flag validates playbook completeness, claim registry coverage, and script
   functionality.
8. Unit tests in `tests/test_check_external_reproduction.py` cover claim
   registry parsing, report generation, environment fingerprinting, and
   threshold evaluation.
9. Dry-run output cannot be mistaken for executed evidence: planning mode uses
   `PLANNED` / `not_run` semantics and never manufactures passing claim
   verdicts.
10. The reproduction report carries structured execution-log events, and
    subprocess-driven tests cover dry-run, missing-mapping, harness-failure,
    and verbose CLI status surfaces.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_7/bd-2pu_contract.md` |
| Policy doc | `docs/policy/external_reproduction.md` |
| Playbook | `docs/reproduction_playbook.md` |
| Claims registry | `docs/headline_claims.toml` |
| Automation script | `scripts/reproduce.py` |
| Verification script | `scripts/check_external_reproduction.py` |
| Python unit tests | `tests/test_check_external_reproduction.py` |
| Verification evidence | `artifacts/section_10_7/bd-2pu/verification_evidence.json` |
| Verification summary | `artifacts/section_10_7/bd-2pu/verification_summary.md` |
