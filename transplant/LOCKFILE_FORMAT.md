# Transplant Lockfile Format Specification

## Version

v1.1 (2026-02-22)

## Purpose

The transplant lockfile provides tamper detection for snapshot assets transplanted from upstream repositories. It enables deterministic verification that the snapshot matches a known-good state.

## Format

```
# TRANSPLANT LOCKFILE (sha256)
# source_root: <absolute path to source repo>
# manifest: <manifest identifier/path>
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
| `manifest` | yes | Manifest identifier/path used to derive file inventory |
| `entries` | yes | Exact count of hash entries (must match parsed entry count) |
| `generated_utc` | yes | ISO-8601 UTC timestamp metadata |

### Deterministic Generation Rules

- Generator sorts relative paths using `LC_ALL=C sort -u`.
- Relative paths are normalized to remove leading `./` or `/`.
- Default `generated_utc` is fixed to `1970-01-01T00:00:00Z` for reproducibility.
- Override timestamp only when needed via:
  - `--generated-utc <YYYY-MM-DDTHH:MM:SSZ|now>`
  - `TRANSPLANT_LOCKFILE_GENERATED_UTC=<...>`

With the default timestamp behavior, equivalent inputs produce byte-identical lockfiles.

### Entry Format

Each non-comment, non-empty line is a hash entry:
- Two-space separator: `<sha256hex>  <relative-path>`
- `sha256hex`: lowercase hexadecimal SHA-256 digest (64 characters)
- `relative-path`: UTF-8 path relative to snapshot root

## Verification Semantics

### Verification Outcomes

| Outcome | Meaning |
|---------|---------|
| `PASS` | All entries match: same files, same hashes, no extras |
| `FAIL:PARSE` | One or more lockfile entries are malformed or duplicate |
| `FAIL:COUNT` | Header `entries` does not match parsed entry count |
| `FAIL:MISMATCH` | One or more files have different SHA-256 digests |
| `FAIL:MISSING` | One or more lockfile entries have no corresponding file |
| `FAIL:EXTRA` | Files exist in snapshot that are not in the lockfile |

### Verification Algorithm

1. Parse header; validate `entries` is present and numeric.
2. Parse each entry line using strict `<64-hex><two spaces><path>` format.
3. Reject duplicate paths and malformed lines as parse failures.
4. Compute SHA-256 for each listed file under snapshot root.
5. Detect extra files in snapshot not represented in lockfile.
6. Emit structured report including failing categories and detailed path lists.

## Downstream Consumers

- `bd-29q`: Drift detection workflow uses lockfile as baseline
- CI pipeline: pre-merge verification gate
- `bd-3k9t`: E2E test scripts validate restore → lockfile → verify flow
