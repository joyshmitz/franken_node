# bd-3kn: Packaging Profiles for Local/Dev/Enterprise Deployments

## Bead: bd-3kn | Section: 10.6

## Purpose

Defines three packaging profiles -- `local`, `dev`, and `enterprise` -- that
tailor the franken-node build output, default configuration, and bundled assets
to each deployment target. A single undifferentiated build cannot serve local
development, CI pipelines, and enterprise production equally well. Profiles
ensure the right trade-offs are applied automatically.

## Profiles Overview

| Profile | Target | Key Traits |
|---------|--------|------------|
| `local` | Developer laptop | Minimal size, fastest cold-start, no ceremony |
| `dev` | CI/dev pipeline | Debug symbols, verbose logging, reproducibility tooling |
| `enterprise` | Production fleet | Signed binaries, audit logging, compliance evidence |

## Profile Definitions

### `local`

- **Components**: Core binary only. No debug symbols, no compliance bundles,
  no audit infrastructure, no fixture generators.
- **Defaults**: Telemetry off. Audit logging off. Binary signing verification
  disabled. Verbose logging off. Strict policy evaluation off.
- **Startup**: Lazy initialization. Deferred policy loading. No integrity
  self-check.
- **Size Budget**: Max 25 MB. Debug symbols stripped. Compliance bundles
  excluded.

### `dev`

- **Components**: Core binary, debug symbols, lockstep harness, fixture
  generators. No compliance bundles, no audit infrastructure.
- **Defaults**: Telemetry debug-local (local-only debug-level). Audit logging
  off. Binary signing verification disabled. Verbose logging on.
- **Startup**: Eager module loading for comprehensive error checking at
  startup. No integrity self-check.
- **Size Budget**: Max 60 MB. Debug symbols retained.

### `enterprise`

- **Components**: Core binary, compliance evidence bundles
  (verification_evidence.json from all gates), audit log infrastructure,
  signed binary verification, telemetry export configuration.
- **Defaults**: Telemetry structured-export to configured endpoint with PII
  filtering. Audit logging mandatory. Binary signing verification mandatory.
  Strict policy evaluation on.
- **Startup**: Full integrity self-check at startup (binary signature,
  configuration checksum, policy schema validation). Eager module loading.
- **Size Budget**: Max 80 MB. Debug symbols stripped. Compliance bundles
  included.

## Profile Selection

Profiles are selected via:

1. `--profile <name>` CLI flag (highest priority).
2. `FRANKEN_NODE_PROFILE` environment variable.
3. Default: `local` if neither is set.

Unknown profile names produce a clear error listing valid options and exit
non-zero with event code PKG-004.

## Configuration File

Profile definitions are stored in `packaging/profiles.toml` -- a checked-in,
auditable, versionable configuration file. The build system reads this file to
determine what to include in the output artifact.

## Invariants

| ID | Statement |
|----|-----------|
| INV-PKG-PROFILES | Exactly three profiles are defined: `local`, `dev`, `enterprise`. No additional profiles are accepted without governance review. |
| INV-PKG-SELECTION | CLI flag `--profile` takes strict precedence over `FRANKEN_NODE_PROFILE` env var. If neither is set, `local` is used. |
| INV-PKG-SIZE | The `local` profile binary is at least 30% smaller than the `enterprise` profile binary, measured after stripping debug symbols and excluding compliance bundles. |
| INV-PKG-INTEGRITY | The `enterprise` profile performs a full startup integrity self-check: binary signature verification, configuration checksum, and policy schema validation. |
| INV-PKG-COMPONENTS | Each profile includes exactly the components listed in its definition; no extra components leak across profiles. |
| INV-PKG-TELEMETRY | Telemetry levels are enforced per profile: `local` = off, `dev` = debug-local, `enterprise` = structured-export. |
| INV-PKG-AUDIT | The `enterprise` profile mandates audit logging; `local` and `dev` disable it by default. |
| INV-PKG-ERROR | Unknown profile names produce event PKG-004, list valid options, and exit non-zero. |

## Event Codes

| Code | Severity | Emitted When |
|------|----------|-------------|
| PKG-001 | info | Profile selected and activated at startup |
| PKG-002 | info | Profile components loaded and defaults applied |
| PKG-003 | info | Enterprise integrity self-check completed successfully |
| PKG-004 | error | Unknown profile name rejected; valid options listed |

## Startup Behavior

### `local` Startup Sequence

1. Emit PKG-001 with profile=local.
2. Skip integrity self-check.
3. Lazy-load policy configuration (deferred until first policy evaluation).
4. Emit PKG-002 with component list.

### `dev` Startup Sequence

1. Emit PKG-001 with profile=dev.
2. Skip integrity self-check.
3. Eager-load all modules for comprehensive error checking.
4. Enable verbose logging output.
5. Emit PKG-002 with component list.

### `enterprise` Startup Sequence

1. Emit PKG-001 with profile=enterprise.
2. Perform full integrity self-check:
   a. Binary signature verification.
   b. Configuration checksum validation.
   c. Policy schema validation.
3. Emit PKG-003 on self-check success; abort on failure.
4. Eager-load all modules.
5. Enable audit logging and structured telemetry export.
6. Emit PKG-002 with component list.

## Telemetry Levels

| Profile | Level | Behavior |
|---------|-------|----------|
| `local` | off | No telemetry emitted or collected |
| `dev` | debug-local | Debug-level telemetry to local stdout/file only |
| `enterprise` | structured-export | Structured telemetry exported to configured endpoint with PII filtering |

## Component Matrix

| Component | `local` | `dev` | `enterprise` |
|-----------|---------|-------|-------------|
| core_binary | yes | yes | yes |
| debug_symbols | no | yes | no |
| lockstep_harness | no | yes | no |
| fixture_generators | no | yes | no |
| compliance_evidence | no | no | yes |
| audit_log_infra | no | no | yes |
| signed_binary_verification | no | no | yes |
| telemetry_export | no | no | yes |

## Size Budget Enforcement

| Profile | Max Binary (MB) | Strip Debug | Exclude Compliance |
|---------|----------------|-------------|-------------------|
| `local` | 25 | yes | yes |
| `dev` | 60 | no | yes |
| `enterprise` | 80 | yes | no |

The `local` binary MUST be at least 30% smaller than `enterprise` to satisfy
INV-PKG-SIZE.

## Dependencies

- **bd-n9r**: CLI framework (cli.rs, config.rs) -- profile flag integration.
- **bd-2pw**: Binary signing -- enterprise profile signing verification.
- **10.13 telemetry**: Telemetry namespace -- structured export configuration.

## Artifacts

- Spec: `docs/specs/section_10_6/bd-3kn_contract.md`
- Policy: `docs/policy/packaging_profiles.md`
- Profile config: `packaging/profiles.toml`
- Verification script: `scripts/check_packaging_profiles.py`
- Unit tests: `tests/test_check_packaging_profiles.py`
- Evidence: `artifacts/section_10_6/bd-3kn/verification_evidence.json`
- Summary: `artifacts/section_10_6/bd-3kn/verification_summary.md`
