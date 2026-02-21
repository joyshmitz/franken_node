# Policy: Packaging Profiles

**Bead:** bd-3kn
**Section:** 10.6 -- Performance + Packaging
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Overview

franken-node supports three packaging profiles that tailor build output,
default configuration, and bundled assets to each deployment context. This
policy governs profile definitions, artifact contents, size budgets, feature
flags, and selection precedence.

## 2. Profile Definitions

### 2.1 `local` -- Developer Workstation

Optimized for local development with minimal friction.

- **Target**: Developer laptops, local testing environments.
- **Philosophy**: Fastest cold-start, smallest binary, no ceremony.
- **Components**: Core binary only.
- **Telemetry**: Off.
- **Audit logging**: Disabled.
- **Startup**: Lazy initialization with deferred policy loading.

### 2.2 `dev` -- CI/Dev Pipeline

Optimized for debugging, reproducibility, and comprehensive error detection.

- **Target**: CI runners, staging environments, QA pipelines.
- **Philosophy**: Debug symbols, verbose logging, reproducibility tooling.
- **Components**: Core binary, debug symbols, lockstep harness, fixture
  generators.
- **Telemetry**: Debug-level, local-only.
- **Audit logging**: Disabled.
- **Startup**: Eager module loading for comprehensive error checking.

### 2.3 `enterprise` -- Production Fleet

Optimized for security, compliance, and auditability.

- **Target**: Production deployments, regulated environments, enterprise fleet.
- **Philosophy**: Signed binaries, audit logging, compliance evidence bundled.
- **Components**: Core binary, compliance evidence bundles, audit log
  infrastructure, signed binary verification, telemetry export configuration.
- **Telemetry**: Structured export to configured endpoint with PII filtering.
- **Audit logging**: Mandatory.
- **Startup**: Full integrity self-check (binary signature, configuration
  checksum, policy schema validation).

## 3. Artifact Contents per Profile

| Artifact | `local` | `dev` | `enterprise` |
|----------|---------|-------|-------------|
| core_binary | included | included | included |
| debug_symbols | excluded | included | excluded |
| lockstep_harness | excluded | included | excluded |
| fixture_generators | excluded | included | excluded |
| compliance_evidence | excluded | excluded | included |
| audit_log_infra | excluded | excluded | included |
| signed_binary_verification | excluded | excluded | included |
| telemetry_export | excluded | excluded | included |

## 4. Size Budgets

| Profile | Max Binary Size (MB) | Strip Debug Symbols | Exclude Compliance Bundles |
|---------|---------------------|---------------------|---------------------------|
| `local` | 25 | yes | yes |
| `dev` | 60 | no | yes |
| `enterprise` | 80 | yes | no |

**INV-PKG-SIZE**: The `local` profile binary MUST be at least 30% smaller than
the `enterprise` profile binary. This constraint is enforced by the
verification script and CI gate.

## 5. Feature Flags per Profile

| Feature Flag | `local` | `dev` | `enterprise` |
|-------------|---------|-------|-------------|
| telemetry | off | debug-local | structured-export |
| audit_logging | false | false | true |
| binary_signing_verification | false | false | true |
| verbose_logging | false | true | false |
| strict_policy_evaluation | false | false | true |

## 6. Profile Selection Precedence

1. **CLI flag** `--profile <name>` (highest priority).
2. **Environment variable** `FRANKEN_NODE_PROFILE`.
3. **Default**: `local` if neither is set.

The CLI flag always overrides the environment variable. This ensures
predictable behavior in automation scripts and CI pipelines.

## 7. Error Handling

- Unknown profile names produce event **PKG-004**, emit a clear error
  listing valid options (`local`, `dev`, `enterprise`), and exit non-zero.
- Profile configuration file (`packaging/profiles.toml`) must be present
  and parseable at build time; missing or malformed files abort the build.

## 8. Startup Behavior

### 8.1 `local` Startup

- Emit PKG-001 (profile activated).
- Skip integrity self-check.
- Lazy-load policy configuration.
- Emit PKG-002 (components loaded).

### 8.2 `dev` Startup

- Emit PKG-001 (profile activated).
- Skip integrity self-check.
- Eager-load all modules for error checking.
- Enable verbose logging.
- Emit PKG-002 (components loaded).

### 8.3 `enterprise` Startup

- Emit PKG-001 (profile activated).
- Full integrity self-check: binary signature, config checksum, policy schema.
- Emit PKG-003 on success; abort on failure.
- Eager-load all modules.
- Enable audit logging and structured telemetry.
- Emit PKG-002 (components loaded).

## 9. Governance

### 9.1 Adding New Profiles

New profiles require:
1. Written proposal with rationale and impact analysis.
2. Approval from at least 2 reviewers.
3. 14-day notice period.
4. Update to `packaging/profiles.toml` and verification scripts.

### 9.2 Modifying Existing Profiles

Changes to component inclusion, default policies, or size budgets require:
1. Bead filed with before/after comparison.
2. Verification that INV-PKG-SIZE constraint is maintained.
3. CI gate validation of updated profile.

## 10. Event Codes

| Code | Severity | Emitted When |
|------|----------|-------------|
| PKG-001 | info | Profile selected and activated at startup |
| PKG-002 | info | Profile components loaded and defaults applied |
| PKG-003 | info | Enterprise integrity self-check completed successfully |
| PKG-004 | error | Unknown profile name rejected; valid options listed |

## 11. Invariants

| ID | Rule |
|----|------|
| INV-PKG-PROFILES | Exactly three profiles exist: `local`, `dev`, `enterprise` |
| INV-PKG-SELECTION | CLI flag overrides env var; default is `local` |
| INV-PKG-SIZE | `local` binary at least 30% smaller than `enterprise` |
| INV-PKG-INTEGRITY | `enterprise` performs full startup integrity self-check |
| INV-PKG-COMPONENTS | Each profile includes exactly its defined components |
| INV-PKG-TELEMETRY | Telemetry levels enforced per profile |
| INV-PKG-AUDIT | `enterprise` mandates audit logging; others disable by default |
| INV-PKG-ERROR | Unknown profiles produce PKG-004 and exit non-zero |
