# Release Rollback Bundles Policy

**Bead:** bd-3q9 | **Section:** 10.6
**Effective:** 2026-02-20

## 1. Scope

This policy governs the creation, storage, verification, and application of rollback
bundles for all franken_node releases. It ensures that every production release can
be deterministically reversed to the previous known-good state.

## 2. Bundle Generation

### 2.1 Mandatory Bundle Creation

1. Every release build MUST produce a rollback bundle alongside the release artifacts.
2. The bundle MUST be generated before the release is published.
3. Bundle generation failure MUST block release publication.
4. Emit event code `RRB-001` upon successful bundle creation.

### 2.2 Bundle Contents

Every rollback bundle MUST contain:

- **Previous binary reference**: SHA-256 hash identifying the previous version binary.
- **Configuration diff**: A reversible delta that undoes configuration schema changes
  introduced by the new release.
- **State migration reversal**: Records that undo any data format changes.
- **Health check definitions**: The ordered sequence of checks to run post-rollback.
- **Restore manifest**: JSON document listing all bundle components with checksums.
- **Compatibility proof**: Version bounds specifying valid rollback source/target pairs.

### 2.3 Bundle Integrity

- The restore manifest MUST include a SHA-256 checksum for every component.
- The bundle itself MUST have an overall integrity hash (SHA-256 of the manifest).
- Integrity validation MUST be performed before any rollback operation begins.

## 3. Rollback Procedure

### 3.1 Pre-Rollback Validation

1. Verify bundle integrity (manifest checksums, overall hash).
2. Verify compatibility proof matches current installed version.
3. Capture pre-rollback state snapshot (config checksums, schema version, policy set).

### 3.2 Rollback Execution

1. Apply state migration reversal in declared order.
2. Apply configuration diff to restore previous configuration.
3. Update binary reference to previous version.
4. Emit event code `RRB-002` at rollback initiation.

### 3.3 Post-Rollback Verification

1. Run health check sequence: binary version, config schema, state integrity, smoke tests.
2. Capture post-rollback state snapshot and compare to expected pre-upgrade state.
3. On success, emit event code `RRB-003`.
4. On failure, emit event code `RRB-004` with structured error report.

### 3.4 Idempotency

- Applying the same rollback bundle multiple times MUST produce identical state.
- Invariant `INV-RRB-IDEMPOT` enforces this requirement.
- The system MUST detect and handle already-applied rollbacks gracefully.

## 4. Dry-Run Mode

- `--dry-run` flag MUST preview all rollback actions without modifying state.
- Dry-run MUST validate bundle integrity and compatibility.
- Dry-run output MUST list each action that would be taken.

## 5. Error Handling

- `ERR-RRB-MANIFEST-INVALID`: Report manifest parse errors with line/field details.
- `ERR-RRB-CHECKSUM-MISMATCH`: Report which component failed verification.
- `ERR-RRB-HEALTH-FAILED`: Report which health check(s) failed with remediation.
- `ERR-RRB-VERSION-MISMATCH`: Report expected vs. actual version.

## 6. Storage and Retention

- Rollback bundles MUST be stored alongside release artifacts in the release directory.
- Bundles MUST be retained for at least the last 3 releases.
- Bundle naming convention: `rollback-<source>-to-<target>.bundle`.

## 7. Audit Trail

- Every bundle generation, rollback attempt, and health check result MUST produce
  a structured JSON audit log entry.
- Audit entries MUST include: timestamp, event code, bundle hash, source version,
  target version, and outcome.

## 8. Time Ceiling

- Rollback restoration MUST complete within 60 seconds for standard deployments.
- Individual health checks MUST complete within 30 seconds.
- Timeouts are treated as failures with event code `RRB-004`.
