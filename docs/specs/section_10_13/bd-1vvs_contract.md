# bd-1vvs: Strict-Plus Isolation Backend

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

The `strict_plus` sandbox profile maps to a microVM isolation backend
where supported (Linux with KVM). On unsupported platforms, a hardened
fallback backend provides equivalent policy guarantees using OS-level
sandboxing primitives.

## Dependencies

- bd-3ua7: Sandbox profile system with policy compiler

## Isolation Backends

| Backend        | Platform           | Isolation Level           |
|----------------|--------------------|---------------------------|
| `microvm`      | Linux + KVM        | Full hardware virtualization |
| `hardened`     | Linux (no KVM)     | seccomp + namespaces + cgroups |
| `os_sandbox`   | macOS              | sandbox-exec + entitlements |
| `container`    | Any with OCI       | OCI container with restricted caps |

## Backend Selection

The backend is selected at runtime based on platform capabilities:

1. Probe for KVM support → `microvm`
2. Probe for seccomp + namespaces → `hardened`
3. Probe for macOS sandbox → `os_sandbox`
4. Fall back to OCI container → `container`

## Runtime Matrix

| OS      | Arch    | KVM | Backend     | Equivalent |
|---------|---------|-----|-------------|------------|
| Linux   | x86_64  | yes | microvm     | full       |
| Linux   | x86_64  | no  | hardened    | equivalent |
| Linux   | aarch64 | yes | microvm     | full       |
| Linux   | aarch64 | no  | hardened    | equivalent |
| macOS   | aarch64 | no  | os_sandbox  | equivalent |
| any     | any     | no  | container   | baseline   |

## Invariants

1. **INV-STRICT-PLUS-PROBE**: Backend selection must probe actual platform
   capabilities, not assume based on OS name alone.
2. **INV-STRICT-PLUS-EQUIVALENT**: The hardened fallback must enforce all
   capabilities at the same access level as microVM.
3. **INV-STRICT-PLUS-AUDIT**: Backend selection is logged with probe results.
4. **INV-STRICT-PLUS-FALLBACK**: If the preferred backend fails to initialize,
   fall back to the next option without reducing policy guarantees.

## Error Codes

| Code                          | Meaning                                    |
|-------------------------------|--------------------------------------------|
| `ISOLATION_BACKEND_UNAVAILABLE` | No suitable backend found for this platform |
| `ISOLATION_PROBE_FAILED`      | Backend capability probe failed              |
| `ISOLATION_INIT_FAILED`       | Backend initialization failed                |
| `ISOLATION_POLICY_MISMATCH`   | Backend cannot enforce required policy       |

## Artifacts

- `crates/franken-node/src/security/isolation_backend.rs` — Backend impl
- `tests/integration/strict_plus_isolation.rs` — Integration tests
- `fixtures/isolation/*.json` — Backend selection fixtures
- `artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv` — Runtime matrix
- `docs/specs/section_10_13/bd-1vvs_contract.md` — This specification
