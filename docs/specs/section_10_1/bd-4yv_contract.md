# bd-4yv: Reproducibility Contract Templates

## Decision Rationale

The canonical plan requires that every major claim ships with reproducible evidence artifacts. The reproducibility contract defines three template files that together capture the environment, build manifest, and dependency lock state needed to reproduce any evidence artifact.

## Template Definitions

### `env.json` — Environment Snapshot
Captures the machine/runtime environment at execution time:
- OS, architecture, kernel version
- Rust toolchain version and edition
- Python version (for verification scripts)
- Key environment variables (sanitized)
- Timestamp and hostname

### `manifest.json` — Artifact Manifest
Captures what was produced and how:
- Artifact type and bead ID
- Commands executed with exit codes
- Input file hashes (SHA-256)
- Output file hashes (SHA-256)
- Duration and resource usage

### `repro.lock` — Dependency Lock
Captures the exact dependency state:
- Git commit hash
- Cargo.lock hash
- Key crate versions
- Engine revision pin

## Invariants

1. Templates must be valid JSON (or TOML for `repro.lock`).
2. All required fields must be present.
3. Hashes must use SHA-256.
4. Timestamps must be ISO 8601 / RFC 3339.
5. No secrets or credentials in any template.

## Validation

A validation script checks that any reproducibility pack conforms to the template schemas.
