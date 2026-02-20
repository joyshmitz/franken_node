# bd-3ua7: Sandbox Profile System with Policy Compiler

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Implement a sandbox profile system with four tiers (`strict`, `strict_plus`,
`moderate`, `permissive`) and a policy compiler that emits enforceable
low-level policies. Profile downgrades are blocked. Profile selection is
auditable.

## Dependencies

- bd-b44: State schema version contracts and migration hints

## Sandbox Profiles

| Profile       | Level | Description                                    |
|---------------|-------|------------------------------------------------|
| `strict`      | 0     | Maximum isolation, no network, no fs writes    |
| `strict_plus` | 1     | Strict + microVM/hardened backend when avail   |
| `moderate`    | 2     | Scoped fs access, filtered network, no exec    |
| `permissive`  | 3     | Minimal restrictions, full network, audit only |

Higher level = more permissive. Downgrades (level decrease) are blocked.

## Policy Capabilities

The policy compiler translates a profile into a set of capability grants:

| Capability       | strict | strict_plus | moderate | permissive |
|------------------|--------|-------------|----------|------------|
| `network_access` | deny   | deny        | filtered | allow      |
| `fs_read`        | deny   | deny        | scoped   | allow      |
| `fs_write`       | deny   | deny        | deny     | allow      |
| `process_exec`   | deny   | deny        | deny     | allow      |
| `ipc`            | deny   | deny        | scoped   | allow      |
| `env_access`     | deny   | deny        | filtered | allow      |

### Access Levels

| Level      | Meaning                              |
|------------|--------------------------------------|
| `deny`     | Capability fully blocked             |
| `scoped`   | Allowed within declared boundaries   |
| `filtered` | Allowed with configurable filters    |
| `allow`    | Full access, audit-only enforcement  |

## Invariants

1. **INV-SANDBOX-TIERED**: Profiles form a strict partial order by level.
2. **INV-SANDBOX-NO-DOWNGRADE**: A connector cannot move to a lower-level profile
   without explicit override authorization.
3. **INV-SANDBOX-COMPILED**: The policy compiler must produce a deterministic
   output for each profile.
4. **INV-SANDBOX-AUDIT**: Profile selection and changes are recorded in an
   audit log.

## Error Codes

| Code                       | Meaning                                    |
|----------------------------|--------------------------------------------|
| `SANDBOX_DOWNGRADE_BLOCKED`| Attempted to move to a less restrictive profile |
| `SANDBOX_PROFILE_UNKNOWN`  | Unknown profile name                        |
| `SANDBOX_POLICY_CONFLICT`  | Compiled policy has conflicting capabilities |
| `SANDBOX_COMPILE_ERROR`    | Policy compilation failed                   |

## Artifacts

- `crates/franken-node/src/security/sandbox_policy_compiler.rs` — Policy compiler
- `crates/franken-node/src/security/mod.rs` — Security module
- `tests/conformance/sandbox_profile_conformance.rs` — Conformance tests
- `fixtures/sandbox_profiles/*.json` — Profile test fixtures
- `artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json` — Compiled output
- `docs/specs/section_10_13/bd-3ua7_contract.md` — This specification
