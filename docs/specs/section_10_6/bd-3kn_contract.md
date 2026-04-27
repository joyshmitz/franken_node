# bd-3kn: Packaging Profiles for Local/Dev/Enterprise Deployments

## Bead: bd-3kn | Section: 10.6

## ⚠️ IMPLEMENTATION STATUS

**This specification describes packaging profiles for FUTURE implementation.**
**The current franken-node binary does NOT implement packaging profile selection.**

- **Current reality**: Only runtime profiles work (`--profile strict|balanced|legacy-risky`)
- **Future specification**: This document defines packaging profiles (`local|dev|enterprise`)
- **Error codes PKG-001..004**: Reserved for future implementation, not currently emitted
- **Configuration file**: `packaging/profiles.toml` exists for validation/planning only

## Purpose

This specification defines three packaging profiles -- `local`, `dev`, and `enterprise` -- for
future franken-node build tooling. When implemented, these profiles will tailor the build output,
default configuration, and bundled assets to each deployment target. A single undifferentiated
build cannot serve local development, CI pipelines, and enterprise production equally well.
Future packaging tooling will ensure the right trade-offs are applied automatically.

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

Packaging profiles are selected by packaging/release tooling that reads
`packaging/profiles.toml`. The current runtime binary does **not** consume
`local`, `dev`, or `enterprise` through its `--profile` / `FRANKEN_NODE_PROFILE`
path; that runtime selector continues to mean runtime policy profiles
`strict`, `balanced`, and `legacy-risky`.

Packaging/release selection rules are:

1. Packaging/release tooling selects one of `local`, `dev`, or `enterprise`.
2. If tooling does not override the selection, `local` is the default
   packaging profile.

Unknown packaging profile names produce a clear error listing valid options
and exit non-zero with event code PKG-004 in the packaging/release selection
path.

The shipped `franken-node` binary does **not** currently expose that packaging
selection path. Runtime `--profile` / `FRANKEN_NODE_PROFILE` parsing remains
limited to `strict`, `balanced`, and `legacy-risky` in `crates/franken-node/src/config.rs`.

## Configuration File

Profile definitions are stored in `packaging/profiles.toml` -- a checked-in,
auditable, versionable configuration file. The build system reads this file to
determine what to include in the output artifact.

## Invariants

| ID | Statement |
|----|-----------|
| INV-PKG-PROFILES | Exactly three profiles are defined: `local`, `dev`, `enterprise`. No additional profiles are accepted without governance review. |
| INV-PKG-SELECTION | Packaging profile selection is a packaging/release concern. The current runtime `--profile` / `FRANKEN_NODE_PROFILE` path continues to select runtime policy profiles `strict`, `balanced`, `legacy-risky`, while packaging defaults to `local` when tooling does not override it. |
| INV-PKG-SIZE | The `local` profile binary is at least 30% smaller than the `enterprise` profile binary, measured after stripping debug symbols and excluding compliance bundles. |
| INV-PKG-INTEGRITY | The `enterprise` packaging metadata records `integrity_self_check = true`; no shipped CLI/startup path currently performs that packaging-specific integrity flow. |
| INV-PKG-COMPONENTS | Each profile includes exactly the components listed in its definition; no extra components leak across profiles. |
| INV-PKG-TELEMETRY | Packaging metadata declares telemetry levels per profile: `local` = off, `dev` = debug-local, `enterprise` = structured-export; the current runtime selector remains separate. |
| INV-PKG-AUDIT | The `enterprise` packaging metadata enables audit logging by default; `local` and `dev` disable it by default. |
| INV-PKG-ERROR | A future packaging/release selector must reject unknown packaging profile names with reserved code PKG-004; the shipped runtime does not currently implement that selector. |

## Event Codes (Reserved for Future Implementation)

| Code | Severity | Future Behavior | Current Status |
|------|----------|-----------------|----------------|
| PKG-001 | info | Future packaging selector: emitted when a packaging profile is chosen | **NOT EMITTED** - no packaging selector implemented |
| PKG-002 | info | Future packaging selector: emitted when packaging components/defaults are applied | **NOT EMITTED** - no packaging selector implemented |
| PKG-003 | info | Future packaging selector: emitted when enterprise integrity metadata is satisfied | **NOT EMITTED** - no packaging selector implemented |
| PKG-004 | error | Future packaging selector: emitted when rejecting an unknown packaging profile | **NOT EMITTED** - current runtime profile parsing fails separately in `config.rs` |

## Profile Metadata and Non-Shipped Startup Expectations

The `startup` tables in `packaging/profiles.toml` are packaging metadata. They
document intended packaged-artifact behavior for a future packaging/release
selector, but the current `franken-node` CLI/startup code does not consume
those tables and does not emit PKG-001, PKG-002, or PKG-003.

### `local` Startup Sequence

1. `packaging/profiles.toml` records `mode = "lazy"` and
   `integrity_self_check = false`.
2. The packaging metadata implies deferred policy loading in a future packaging
   selector.
3. No shipped `franken-node` runtime path currently emits PKG-001 or PKG-002
   for `local`.

### `dev` Startup Sequence

1. `packaging/profiles.toml` records `mode = "eager"` and
   `integrity_self_check = false`.
2. The packaging metadata implies eager module loading and verbose defaults for
   a future packaging selector.
3. No shipped `franken-node` runtime path currently emits PKG-001 or PKG-002
   for `dev`.

### `enterprise` Startup Sequence

1. `packaging/profiles.toml` records `mode = "full-integrity"` and
   `integrity_self_check = true`.
2. The packaging metadata implies a future packaging selector should perform:
   a. Binary signature verification.
   b. Configuration checksum validation.
   c. Policy schema validation.
3. No shipped `franken-node` runtime path currently emits PKG-001, PKG-002, or
   PKG-003 for `enterprise`.
4. No current CLI/startup path consumes `packaging/profiles.toml`.

These startup sequences describe behavior for a package assembled under the
corresponding packaging profile. They do not redefine the current runtime
`--profile` / `FRANKEN_NODE_PROFILE` selector used by `config.rs`.

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
