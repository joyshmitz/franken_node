# Policy: Packaging Profiles

**Bead:** bd-3kn
**Section:** 10.6 -- Performance + Packaging
**Status:** Active
**Last reviewed:** 2026-02-20

---

## ⚠️ IMPLEMENTATION STATUS

**This document describes packaging profiles for FUTURE implementation.**
**The current franken-node binary does NOT implement packaging profile selection.**

- **Current reality**: Only runtime profiles work (`--profile strict|balanced|legacy-risky`)
- **Future specification**: This document defines packaging profiles (`local|dev|enterprise`)
- **Error codes PKG-001..004**: Reserved for future implementation, not currently emitted
- **Configuration file**: `packaging/profiles.toml` exists for validation/planning only

See Section 6 for current vs. future profile selection behavior.

---

## 1. Overview

This policy defines three packaging profiles (`local`, `dev`, `enterprise`) for
future franken-node build tooling. When implemented, these profiles will tailor
build output, default configuration, and bundled assets to each deployment
context. This specification governs profile definitions, artifact contents,
size budgets, feature flags, and selection precedence for the future packaging
selector implementation.

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

## 6. Profile Selection Precedence (Future Implementation)

**Future behavior:** These profiles will be selected by packaging/release tooling,
not by the runtime CLI/config selector path.

1. **Future packaging tooling** will select `local`, `dev`, or `enterprise`.
2. **Default**: `local` if future tooling does not override the selection.

**Current behavior:** Runtime `franken-node` configuration uses runtime policy
profiles (`strict`, `balanced`, `legacy-risky`) via `config.rs`, `cli.rs`, and
README examples. Packaging profiles are explicitly rejected as invalid runtime
`--profile` or `FRANKEN_NODE_PROFILE` values with helpful error messages.

## 7. Error Handling

- The shipped `franken-node` binary does not currently expose a packaging
  profile selector. Runtime `--profile` / `FRANKEN_NODE_PROFILE` parsing
  remains limited to `strict`, `balanced`, and `legacy-risky` in
  `crates/franken-node/src/config.rs`.
- If dedicated packaging/release tooling is added, unknown packaging profile
  names MUST use reserved event **PKG-004**, list valid options (`local`,
  `dev`, `enterprise`), and exit non-zero in that future packaging/release
  selection path.
- Profile configuration file (`packaging/profiles.toml`) must be present
  and parseable for packaging docs/gates and any future packaging selector;
  missing or malformed files fail verification and packaging-time validation.

## 8. Profile Metadata and Non-Shipped Startup Expectations

The `startup` tables in `packaging/profiles.toml` are packaging metadata. They
document intended packaged-artifact behavior for a future packaging/release
selector, but the current `franken-node` CLI/startup code does not consume
those tables and does not emit PKG-001, PKG-002, or PKG-003.

### 8.1 `local` Startup

- `packaging/profiles.toml` records `mode = "lazy"` and
  `integrity_self_check = false`.
- The packaging metadata implies deferred policy loading and no packaging-only
  integrity self-check if a dedicated packaging selector is later implemented.
- No shipped `franken-node` runtime path currently emits PKG-001 or PKG-002
  for `local`.

### 8.2 `dev` Startup

- `packaging/profiles.toml` records `mode = "eager"` and
  `integrity_self_check = false`.
- The packaging metadata implies eager module loading and verbose defaults for
  a future packaging selector, not for the shipped runtime `--profile` path.
- No shipped `franken-node` runtime path currently emits PKG-001 or PKG-002
  for `dev`.

### 8.3 `enterprise` Startup

- `packaging/profiles.toml` records `mode = "full-integrity"` and
  `integrity_self_check = true`.
- The packaging metadata implies a future packaging selector should run binary
  signature, configuration checksum, and policy schema checks before declaring
  a packaged artifact ready.
- No shipped `franken-node` runtime path currently emits PKG-001, PKG-002, or
  PKG-003 for `enterprise`, and no current CLI/startup path consumes
  `packaging/profiles.toml`.

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
| PKG-001 | info | Reserved for a future packaging/release selector when a packaging profile is chosen; not emitted by current CLI/startup code |
| PKG-002 | info | Reserved for a future packaging/release selector when packaging components/defaults are applied; not emitted by current CLI/startup code |
| PKG-003 | info | Reserved for a future packaging/release selector when enterprise integrity metadata is satisfied; not emitted by current CLI/startup code |
| PKG-004 | error | Reserved for a future packaging/release selector when rejecting an unknown packaging profile; current runtime profile parsing fails separately in `config.rs` |

## 11. Invariants

| ID | Rule |
|----|------|
| INV-PKG-PROFILES | Exactly three profiles exist: `local`, `dev`, `enterprise` |
| INV-PKG-SELECTION | Packaging selection is owned by packaging/release tooling; current runtime `--profile` / `FRANKEN_NODE_PROFILE` remain runtime policy selectors (`strict`, `balanced`, `legacy-risky`) |
| INV-PKG-SIZE | `local` binary at least 30% smaller than `enterprise` |
| INV-PKG-INTEGRITY | `enterprise` packaging metadata sets `integrity_self_check = true`; no shipped CLI/startup path currently executes that packaging-specific check |
| INV-PKG-COMPONENTS | Each profile includes exactly its defined components |
| INV-PKG-TELEMETRY | Packaging metadata declares telemetry levels per profile; the current runtime selector remains separate |
| INV-PKG-AUDIT | `enterprise` packaging metadata enables audit logging by default; `local` and `dev` disable it by default |
| INV-PKG-ERROR | A future packaging/release selector must reject unknown packaging profiles with reserved code PKG-004; the shipped runtime does not currently implement that selector |
