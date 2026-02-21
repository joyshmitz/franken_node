# Policy: External Reproduction Playbook and Automation

**Bead:** bd-2pu
**Section:** 10.7 -- Conformance & Verification
**Effective:** 2026-02-20

## 1. Overview

This policy governs the external reproduction system for franken_node. External
reproduction enables independent parties to verify headline claims --
compatibility, security, and performance -- without insider knowledge, access
to internal CI systems, or proprietary tooling. The goal is full transparency:
any competent engineer with standard tools can confirm or refute every claim.

## 2. Playbook Format

### 2.1 Required Sections

Every reproduction playbook MUST contain the following five sections
(INV-ERP-COMPLETE):

| Section | Content |
|---------|---------|
| Environment Setup | OS requirements, toolchain installation, dependency list with pinned versions |
| Fixture Download | Where to get test fixtures, expected SHA-256 checksums, generation fallback |
| Benchmark Execution | Exact commands, expected duration, resource requirements |
| Result Comparison | Output interpretation, pass/fail criteria, acceptable variance ranges |
| Troubleshooting | Common issues and solutions for each supported platform |

### 2.2 Formatting Requirements

- Use Markdown with clear numbered steps.
- Every command must be copy-pasteable (no placeholders without default values).
- All version numbers must be pinned, not floating (e.g., `rustc 1.82.0-nightly`
  not `rustc nightly`).
- Resource requirements must include minimum values (CPU cores, RAM, disk space).

## 3. Automation Requirements

### 3.1 Entry Point

A single script (`scripts/reproduce.py`) serves as the automation entry point.
It MUST:

- Be executable with `python3 scripts/reproduce.py` from the repo root.
- Accept `--skip-install` to bypass dependency installation.
- Accept `--dry-run` to list all steps without executing them.
- Accept `--yes` to skip interactive confirmation prompts.
- Produce structured JSON output when passed `--json`.
- Be idempotent: re-running produces the same result.

### 3.2 Execution Phases

The automation script executes in ordered phases:

1. **Environment Check**: Verify OS, toolchain versions, available resources.
   Emit ERP-003 if any version mismatches the pinned specification.
2. **Fixture Acquisition**: Download or generate fixtures. Verify SHA-256
   checksums. Emit ERP-004 on mismatch.
3. **Test Execution**: Run each verification suite referenced by headline
   claims. Capture per-claim results.
4. **Report Generation**: Assemble the reproduction report with environment
   fingerprint, per-claim results, overall verdict, timestamp, and duration.

### 3.3 Failure Handling

- If any phase fails, the script continues to subsequent phases but records
  the failure.
- The overall verdict is FAIL if any headline claim fails its threshold.
- All failures are logged with the relevant event code (ERP-001 through
  ERP-004).

## 4. Environment Specification

### 4.1 Fingerprint Requirements (INV-ERP-ENVIRONMENT)

The environment fingerprint MUST capture:

| Field | Example |
|-------|---------|
| `os` | `Linux 6.17.0-14-generic x86_64` |
| `cpu` | `AMD EPYC 7R13 48-Core Processor` |
| `memory_gb` | `64` |
| `rust_version` | `rustc 1.82.0-nightly (abc1234 2026-02-15)` |
| `node_version` | `v22.3.0` |
| `python_version` | `3.11.9` |
| `cargo_version` | `cargo 1.82.0-nightly` |

### 4.2 Supported Platforms

The playbook targets:

- Linux x86_64 (primary)
- macOS ARM64 (secondary)

Other platforms may work but are not covered by the playbook.

## 5. Seed Data Management

### 5.1 Fixture Provenance

Every fixture file used in reproduction MUST have:

- A documented source URL or generation script.
- A SHA-256 checksum recorded in the playbook.
- A size estimate.

### 5.2 Fixture Generation Fallback

If download is unavailable (e.g., network restrictions), the playbook provides
generation scripts that produce byte-identical fixtures from deterministic
seeds.

### 5.3 Checksum Verification

The automation script verifies checksums before using any fixture. On
mismatch, it emits ERP-004 and records the failure but continues with
remaining claims.

## 6. Headline Claims Registry

### 6.1 Format

The headline claims registry (`docs/headline_claims.toml`) uses TOML format:

```toml
[[claim]]
claim_id = "HC-001"
claim_text = "franken_node passes 100% of the Node.js compatibility test suite"
verification_method = "test_suite"
acceptance_threshold = "100% pass rate"
test_reference = "tests/compatibility/"
category = "compatibility"
```

### 6.2 Required Fields

Every claim entry MUST have all five fields: `claim_id`, `claim_text`,
`verification_method`, `acceptance_threshold`, `test_reference`.

### 6.3 Categories

Claims are categorized as:

- `compatibility` -- behavioral equivalence with Node.js
- `security` -- security properties and hardening
- `performance` -- latency, throughput, resource usage
- `migration` -- migration pathway correctness
- `trust` -- supply chain trust and integrity

### 6.4 Coverage

Every headline claim made in project documentation (README, website, talks)
MUST have a corresponding entry in the registry. The verification script
checks this coverage.

## 7. CI Integration

### 7.1 Gate

The external reproduction verification script runs as a CI gate. The gate
checks:

- Playbook file exists and contains all 5 required sections.
- Claims registry is non-empty and well-formed.
- Automation script exists and is executable.
- All invariants hold.

### 7.2 Nightly Full Reproduction

A nightly CI job runs the full reproduction flow (`scripts/reproduce.py`) and
archives the resulting `reproduction_report.json`. Trend analysis compares
against previous 30 days.

### 7.3 Release Gate

Before any release, a full external reproduction must pass with a clean
environment (fresh container, no cached artifacts).

## 8. Determinism (INV-ERP-DETERMINISM)

Given identical:
- Source code (same commit)
- Environment (same OS, toolchain, hardware class)
- Fixtures (same checksums)

The reproduction MUST produce an identical verdict. Non-determinism in any
claim's verification is a bug and must be resolved before the claim can be
included in the registry.

## 9. Event Codes

| Code | When Emitted | Severity |
|------|--------------|----------|
| ERP-001 | Playbook missing required section | ERROR |
| ERP-002 | Headline claim failed its threshold | ERROR |
| ERP-003 | Environment toolchain version mismatch | WARNING |
| ERP-004 | Fixture file absent or checksum mismatch | ERROR |

## 10. Revision History

| Date | Change |
|------|--------|
| 2026-02-20 | Initial policy created for bd-2pu. |
