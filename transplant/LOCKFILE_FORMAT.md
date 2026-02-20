# Transplant Lockfile Format Specification

## Version

v1 (2026-02-20)

## Purpose

The transplant lockfile provides tamper detection for snapshot assets transplanted from upstream repositories. It enables deterministic verification that the snapshot matches a known-good state.

## Format

```
# TRANSPLANT LOCKFILE (sha256)
# source_root: <absolute path to source repo>
# manifest: <relative path to manifest file>
# entries: <integer count of hash entries>
# generated_utc: <ISO-8601 UTC timestamp>

<sha256hex>  <relative-path>
<sha256hex>  <relative-path>
...
```

### Header Fields

| Field | Required | Description |
|-------|----------|-------------|
| `source_root` | yes | Absolute path to the upstream source repository at generation time |
| `manifest` | yes | Relative path to the file inventory (transplant_manifest.txt) |
| `entries` | yes | Exact count of hash entries (must match actual line count) |
| `generated_utc` | yes | ISO-8601 UTC timestamp of lockfile generation |

### Entry Format

Each non-comment, non-empty line is a hash entry:
- Two space-separated fields: `<sha256hex>  <relative-path>`
- `sha256hex`: lowercase hexadecimal SHA-256 digest (64 characters)
- `relative-path`: path relative to the snapshot root, using forward slashes
- Separator: two spaces (matching `sha256sum -c` format)

### Canonical Ordering

Entries are ordered by the file discovery order at generation time. For verification purposes, ordering does not affect correctness — verification is path-keyed.

### Path Normalization

- Paths use forward slashes regardless of platform
- No leading `./` prefix
- No trailing slashes
- UTF-8 encoding

## Verification Semantics

### Verification Outcomes

| Outcome | Meaning |
|---------|---------|
| `PASS` | All entries match: same files, same hashes, no extras |
| `FAIL:MISMATCH` | One or more files have different SHA-256 digests |
| `FAIL:MISSING` | One or more lockfile entries have no corresponding file |
| `FAIL:EXTRA` | Files exist in snapshot that are not in the lockfile |
| `FAIL:COUNT` | Header entry count does not match actual entry count |

### Verification Algorithm

1. Parse header; validate `entries` count matches actual entry count
2. For each entry, compute SHA-256 of the corresponding file under snapshot root
3. Compare computed digest against lockfile digest
4. Scan snapshot directory for files not present in lockfile
5. Emit structured verification report

## Downstream Consumers

- `bd-29q`: Drift detection workflow uses lockfile as baseline
- CI pipeline: Pre-merge verification gate
- `bd-3k9t`: E2E test scripts validate restore → lockfile → verify flow
