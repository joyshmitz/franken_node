---
schema: mig-v1.0
bead_id: bd-2h2s
section: "10.15"
title: "Migration plan for existing non-asupersync control surfaces with scope burn-down tracking"
---

# bd-2h2s: Migration Plan for Non-Asupersync Control Surfaces

## Summary

Defines and enforces a complete migration plan for all non-asupersync control surfaces
in `connector/`, `conformance/`, and `supply_chain/` modules. Provides a machine-readable
burn-down CSV, gate script validation, and time-boxed exception tracking with enforced
expiry dates.

## Scope

### Migration Inventory

A complete inventory of non-asupersync control surfaces is maintained in a burn-down CSV
(`artifacts/10.15/control_surface_burndown.csv`). Each entry specifies the module path,
function name, invariant violated, target bead for migration, current status, and closure
criteria.

### Exception Management

Surfaces that cannot yet be migrated are granted time-boxed exceptions with:
- Documented justification
- Designated owner
- Hard expiry date (enforced by gate script)

### Burn-Down Tracking

A milestone schedule tracks migration progress with four milestones:
1. Foundation (completed surfaces verified)
2. In-progress closure
3. Remaining surfaces
4. Full closure

## Invariants

| ID | Statement |
|----|-----------|
| INV-MIG-INVENTORIED | Every non-asupersync control surface is inventoried in the burn-down CSV with all required columns |
| INV-MIG-STATUS-VERIFIED | Migration status values are from the allowed set: not_started, in_progress, completed, excepted |
| INV-MIG-EXPIRY-ENFORCED | No exception surface has an expired exception_expiry date relative to the current date |

## Event Codes

| Code | Description |
|------|-------------|
| MIG-001 | Burn-down CSV loaded and parsed successfully |
| MIG-002 | Migration status distribution computed |
| MIG-003 | Exception expiry validation completed |
| MIG-004 | Exception expiry violation detected (expired exception found) |
| MIG-005 | All gate checks completed; final verdict emitted |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_CSV_NOT_FOUND | Burn-down CSV file does not exist |
| ERR_CSV_MISSING_COLUMN | Required column missing from CSV |
| ERR_MIGRATION_DOC_NOT_FOUND | Migration plan document does not exist |
| ERR_INVALID_STATUS | Migration status value not in allowed set |
| ERR_EXPIRED_EXCEPTION | Exception surface has an expired expiry date |

## Acceptance Criteria

1. Migration plan document exists at `docs/migration/asupersync_control_surface_migration.md`
2. Burn-down CSV exists at `artifacts/10.15/control_surface_burndown.csv` with all required columns
3. CSV contains at least 12 inventoried control surfaces
4. All migration statuses are from the allowed set
5. No exception has an expired expiry date
6. Gate script passes all checks
7. Test suite covers gate pass, mutation detection, and self-test

## Dependencies

- **Upstream**: bd-1cwp (canonical serialization), bd-3h63 (idempotent replay), bd-145n (epoch scoping)
- **Downstream**: bd-20eg (section gate)

## Artifacts

| Artifact | Path |
|----------|------|
| Migration plan | `docs/migration/asupersync_control_surface_migration.md` |
| Burn-down CSV | `artifacts/10.15/control_surface_burndown.csv` |
| Spec contract | `docs/specs/section_10_15/bd-2h2s_contract.md` |
| Gate script | `scripts/check_control_surface_burndown.py` |
| Test suite | `tests/test_check_control_surface_burndown.py` |
| Verification evidence | `artifacts/section_10_15/bd-2h2s/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-2h2s/verification_summary.md` |
