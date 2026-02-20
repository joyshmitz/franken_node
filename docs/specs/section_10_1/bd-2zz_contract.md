# bd-2zz: Dependency-Direction Guard

## Decision Rationale

While `check_split_contract.py` (bd-1j2) provides CI-level enforcement of the split contract, this guard adds a deeper, dependency-direction-specific check that prevents local engine crate reintroduction at the Cargo workspace level. It detects not just directory existence but also workspace member declarations, package name collisions, and dependency direction violations.

## Invariants

1. **No workspace member matches engine crate names**: `Cargo.toml` workspace `members` must not reference directories containing `franken-engine` or `franken-extension-host` as local crates.
2. **No package name collision**: No `[package]` in any local `Cargo.toml` may use names `frankenengine-engine` or `frankenengine-extension-host`.
3. **Dependency direction is outward-only**: Engine crate references must point outside this repo (to `/dp/franken_engine/`), never to local paths within this repo.
4. **No reverse dependency**: Engine crates in `/dp/franken_engine/` should not depend on franken_node crates (checked from franken_node's side by scanning for suspicious patterns).

## Interface

- **Script**: `scripts/guard_dependency_direction.py`
- **Exit 0**: All guards pass
- **Exit 1**: Violation detected
- **JSON output**: `--json` flag for machine consumption

## Integration

This guard is designed to run as:
- CI step (alongside `check_split_contract.py`)
- Pre-commit hook (fast enough for interactive use)
- Ad-hoc verification during development
