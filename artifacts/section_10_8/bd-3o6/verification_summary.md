# bd-3o6 Verification Summary

## Bead

- **ID**: bd-3o6
- **Section**: 10.8
- **Title**: Adopt canonical structured observability + stable error taxonomy contracts across operational surfaces

## Verdict: PASS

All 30 verification checks pass.  81 Python unit tests pass.

## Deliverables

| # | Deliverable | Path | Status |
|---|-------------|------|--------|
| 1 | Spec contract | `docs/specs/section_10_8/bd-3o6_contract.md` | Created |
| 2 | Policy document | `docs/policy/structured_observability.md` | Created |
| 3 | Verification script | `scripts/check_structured_observability.py` | 30 checks, all PASS |
| 4 | Unit tests | `tests/test_check_structured_observability.py` | 81 tests, all PASS |
| 5 | Evidence JSON | `artifacts/section_10_8/bd-3o6/verification_evidence.json` | Generated |
| 6 | Summary (this file) | `artifacts/section_10_8/bd-3o6/verification_summary.md` | Generated |

## Check Categories

### Spec Contract (C01-C11, C28, C30)
- File existence, event codes SOB-001 through SOB-004, invariants INV-SOB-*
- Operational surface inventory (6 surfaces), recovery hint schema
- Backward compatibility, adoption checklist, canonical prefixes, dependencies

### Policy Document (C12-C21, C29)
- Canonical log format, error taxonomy, severity levels (Fatal/Degraded/Transient)
- Trace ID requirements, recovery hint actions (5 actions)
- Operational surface inventory, event codes, invariants
- Deprecation cycle, governance

### Upstream Dependencies (C03-C05, C22-C26)
- Telemetry namespace implementation and spec (bd-1ugy, 10.13)
- Error code registry implementation and spec (bd-novi, 10.13)
- Trace context implementation (bd-3tzl)
- SchemaRegistry, RecoveryInfo, TraceContext types verified present

### CLI Surface (C27)
- CLI supports `--json` flag for structured output

## Test Coverage

The 81 unit tests cover:
- **run_all structure** (8 tests): return type, required keys, bead_id, section, verdict, totals
- **self_test** (2 tests): return type, passes
- **individual checks** (30 tests): one per check function, all pass
- **missing file detection** (4 tests): spec, policy, telemetry_ns, error_reg
- **validate_recovery_hint** (9 tests): valid hints, invalid action, empty target, confidence boundaries
- **validate_structured_log_entry** (11 tests): valid entry, missing fields, invalid values, all surfaces
- **is_canonical_metric_name** (7 tests): all 4 valid prefixes, non-canonical, empty, partial
- **constants** (7 tests): counts for event codes, invariants, surfaces, actions, severities, prefixes, checks
- **JSON output** (2 tests): serializable, subprocess --json flag
- **safe_rel** (2 tests): root path, non-root path

## Dependencies Verified

- `crates/franken-node/src/connector/telemetry_namespace.rs` -- SchemaRegistry present
- `crates/franken-node/src/connector/error_code_registry.rs` -- RecoveryInfo present
- `crates/franken-node/src/connector/trace_context.rs` -- TraceContext present
- `docs/specs/section_10_13/bd-1ugy_contract.md` -- upstream telemetry spec exists
- `docs/specs/section_10_13/bd-novi_contract.md` -- upstream error code spec exists
- `crates/franken-node/src/cli.rs` -- `pub json: bool` present
