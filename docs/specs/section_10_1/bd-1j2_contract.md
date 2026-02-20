# bd-1j2: Repository Split Contract CI Enforcement

## Decision Rationale

The engine split contract (`docs/ENGINE_SPLIT_CONTRACT.md`) mandates that `franken_node` consumes engine crates from `/dp/franken_engine` via path dependencies and never reintroduces local copies. This CI check enforces that contract automatically, preventing drift.

## Invariants

1. **No local engine crates**: The directories `crates/franken-engine/` and `crates/franken-extension-host/` must NOT exist in this repository.
2. **Correct path dependencies**: All `Cargo.toml` files referencing engine crates must use paths pointing to `/dp/franken_engine/crates/` (relative: `../../../franken_engine/crates/`).
3. **No engine-internal imports**: No Rust source files may directly depend on engine-internal modules outside the public API surface.
4. **Governance docs exist**: `docs/ENGINE_SPLIT_CONTRACT.md` and `docs/PRODUCT_CHARTER.md` must exist and contain required boundary language.

## Interface Boundaries

### Input
- Repository filesystem state at CI check time.

### Output
- JSON verdict with per-check pass/fail status.
- Non-zero exit code on any violation.
- Structured error messages with remediation hints.

## Failure Semantics

- **Fail-closed**: Any check error (file read failure, parse error) results in FAIL, not silent pass.
- **All-or-nothing**: Every check must pass for the overall verdict to be PASS.
- **Deterministic**: Same filesystem state always produces the same verdict.
