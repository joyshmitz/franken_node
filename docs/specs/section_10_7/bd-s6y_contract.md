# bd-s6y: Canonical Trust Protocol Vector Release and Publication Gate

## Scope

This contract defines the canonical vector registry and gate behavior for
Section 10.7. It imports vector suites from Sections 10.13 and 10.14 into a
single release/publication verification pipeline.

## Required Inputs

- `vectors/canonical_manifest.toml`
- `vectors/CHANGELOG.md`
- Canonical vector sources discovered by manifest globs:
  - `vectors/fnode_trust_vectors*.json`
  - `fixtures/interop/*vectors*.json`
  - `artifacts/10.14/*_vectors.json`
  - `fuzz/corpus/migration` and `fuzz/corpus/shim`

## Event Codes

- `CVG-001`: Manifest loaded
- `CVG-002`: Source discovery completed
- `CVG-003`: Schema/shape validation completed
- `CVG-004`: Traceability metadata verified
- `CVG-005`: Changelog enforcement evaluated
- `CVG-006`: Release gate verdict emitted
- `CVG-007`: Publication gate verdict emitted
- `CVG-008`: Cross-runtime parity summary emitted

## Invariants

- `INV-CVG-DISCOVERY`: Manifest discovery is convention-based and deterministic.
- `INV-CVG-TRACEABILITY`: Every discovered vector set has a source bead ID and version.
- `INV-CVG-CHANGELOG`: Every discovered vector path appears in `vectors/CHANGELOG.md`.
- `INV-CVG-RELEASE-BLOCK`: Any failing required source blocks release.
- `INV-CVG-PUBLICATION-BLOCK`: Publication is blocked when release vector verification fails.
- `INV-CVG-REPORT`: Gate output includes per-source pass/fail + verification timestamp.
- `INV-CVG-PARITY`: Cross-runtime comparison summary is emitted where runtime metadata exists.

## Error Codes

- `ERR_CVG_MANIFEST_MISSING`
- `ERR_CVG_MANIFEST_INVALID`
- `ERR_CVG_SOURCE_DISCOVERY_EMPTY`
- `ERR_CVG_VECTOR_PARSE`
- `ERR_CVG_SCHEMA_SHAPE`
- `ERR_CVG_TRACEABILITY`
- `ERR_CVG_CHANGELOG_MISSING`
- `ERR_CVG_CHANGELOG_ENTRY`

## Output Contract

`scripts/check_canonical_vectors.py --json` emits:

- `sources[]`: each source with `status`, discovered targets, and `verified_at`.
- `vector_sets[]`: flattened per-file/per-directory verification records.
- `release_gate`: pass/fail with blockers.
- `publication_gate`: pass/fail with `blocked_publication` flag.
- `generated_at`: RFC3339 timestamp.

Exit code:

- `0` if release/publication gate verdict is PASS.
- `1` if any required source or enforcement check fails.
