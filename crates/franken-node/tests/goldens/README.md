# Golden Test Artifacts for CLI Surfaces

This directory contains golden snapshots for CLI output stability testing. Golden tests ensure that user-facing output remains consistent across changes.

## Directory Structure

- `cli/` - Main CLI help output
- `trust_card_cli/` - Trust-card subcommands  
- `fleet_cli/` - Fleet management commands
- `doctor_cli/` - Diagnostic commands
- `remotecap_cli/` - Remote capability commands
- `verify_cli/` - Verification commands  
- `registry_cli/` - Registry operations
- `incident_cli/` - Incident analysis commands
- `migrate_audit/` - Migration audit output (existing)
- `migrate_validate/` - Migration validation output (existing)

## Test Coverage

### Covered Subcommands
- **Help commands**: All `--help` output for stability  
- **Error conditions**: Missing args, invalid formats
- **migrate audit/validate**: JSON output with scrubbing (existing)
- **trust-card**: export, list, compare, diff (existing)

### Gaps Identified (requiring build completion)
These subcommands lack golden coverage and will be added when build completes:

- `trust-card show` (JSON/human output)
- `verify release` (with test bundle)
- `remotecap issue/revoke` (capability tokens)
- `fleet status --json` (cluster state)  
- `incident bundle show` (forensics)
- `doctor` (diagnostic output)
- `registry search` (extension listings)

## Scrubbing Patterns

All golden tests apply comprehensive scrubbing via `migrate_golden_helpers.rs`:

- **UUIDs**: `[0-9a-f]{8}-[0-9a-f]{4}...` → `[UUID]`
- **Timestamps**: ISO 8601 formats → `[TIMESTAMP]`  
- **File paths**: Absolute paths → `[PATH]`
- **Memory addresses**: `0x[0-9a-fA-F]+` → `[ADDR]`
- **Durations**: `\d+ms`, `\d+s` → `[DURATION]`
- **PIDs/TIDs**: `pid:\d+` → `pid:[PID]`
- **Hashes**: SHA256/etc → `[HASH]`
- **Ports**: `:\d{4,5}` → `:[PORT]`

## Running Golden Tests

```bash
# Build and run all CLI golden tests
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_golden \
  cargo test -p frankenengine-node --features test-support \
  cli_subcommand_goldens cli_error_goldens

# Update goldens (first run or after intentional changes)
UPDATE_GOLDENS=1 cargo test cli_subcommand_goldens

# Review and accept changes interactively  
cargo insta review
```

## Golden File Workflow

1. **First run**: Tests fail, create `.snap` files with actual output
2. **Review**: Use `cargo insta review` to inspect changes
3. **Accept**: Approve golden files that match expected output  
4. **Commit**: Version control tracks golden files as test fixtures
5. **Future runs**: Tests pass by comparing against committed goldens

## Non-Determinism Handling

If a subcommand produces non-deterministic output even with scrubbing:

1. **File a bead** before adding golden test
2. **Document the issue** in the bead description  
3. **Fix the source** of non-determinism (timestamps, random values, etc.)
4. **Then add golden test** once output is deterministic

## Integration with CI

Golden tests are part of the standard test suite:
- **Failures block PRs** when output changes unexpectedly
- **Review required** for intentional CLI output changes
- **Snapshot diffs** show exactly what changed in PR reviews

This ensures CLI contract stability and catches unintended breaking changes in user-facing surfaces.