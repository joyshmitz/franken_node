# bd-2g6r: Cx-First Signature Policy for Control-Plane Async Entrypoints

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-2g6r |
| Section | 10.15 |
| Title | Enforce Cx-first signature policy for control-plane async entrypoints |
| Type | task |

## Purpose

Hard Runtime Invariant #1 (Section 8.5) requires every control-plane async
entrypoint to accept `&Cx` as its first parameter so that cancellation tokens,
region ownership, deadline budgets, and trace context propagate structurally.

This bead implements `tools/lints/cx_first_policy.rs` — a `syn`-based analysis
pass that scans `pub async fn` signatures in control-plane modules and rejects
any function whose first parameter is not `&Cx` (or `&mut Cx`), with an
allowlist for existing exceptions.

## Deliverables

| Artifact | Path |
|----------|------|
| Lint tool | `tools/lints/cx_first_policy.rs` |
| Allowlist | `docs/specs/cx_first_exception_allowlist.toml` |
| Policy doc | `docs/specs/cx_first_signature_policy.md` |
| Check script | `scripts/check_cx_first_policy.py` |
| Test suite | `tests/test_check_cx_first_policy.py` |
| Evidence | `artifacts/section_10_15/bd-2g6r/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-2g6r/verification_summary.md` |

## Invariants

- **INV-CX-FIRST**: Every `pub async fn` in designated control-plane modules
  must accept `&Cx` (or `&mut Cx`) as its first parameter.
- **INV-CX-ALLOWLIST-BOUNDED**: Exception allowlist entries must have expiry
  dates; expired entries cause gate failure.
- **INV-CX-DETERMINISTIC**: Analysis output is deterministic (sorted, no
  HashMap nondeterminism).

## Event Codes

| Code | Description |
|------|-------------|
| CX-001 | Cx-first policy scan started |
| CX-002 | Function passed Cx-first check |
| CX-003 | Function failed Cx-first check |
| CX-004 | Exception allowlisted |
| CX-005 | Expired exception detected |

## Gate Contract

The check script (`scripts/check_cx_first_policy.py`) must:
- Emit `--json` output with `verdict`, `checks_passed`, `checks_total` fields
- Provide a `self_test()` function returning structured results
- Exit 0 on PASS, 1 on FAIL
