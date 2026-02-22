# bd-1id0: Tri-Kernel Ownership Contract

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Publishes and enforces the tri-kernel ownership contract between
`franken_engine` (execution kernel), `asupersync` (correctness/control kernel),
and `franken_node` (product kernel). Defines explicit interface boundaries,
maps the 10 Hard Runtime Invariants (HRI-01..HRI-10) to canonical kernel
owners, and establishes a signed waiver system for temporary boundary
exceptions.

## Kernel Planes

| Kernel | Plane | Owns |
|--------|-------|------|
| franken_engine | Execution | Runtime internals, extension host sandbox, low-level remote/effect primitives |
| asupersync | Correctness/Control | Cancellation protocol, lane scheduling, epoch barriers, deterministic replay |
| franken_node | Product | User/operator surfaces, policy orchestration, evidence consumption |

## Hard Runtime Invariant Ownership

| HRI | Owner |
|-----|-------|
| HRI-01 Cx-first control APIs | asupersync |
| HRI-02 Region-owned lifecycle | asupersync |
| HRI-03 Cancellation protocol | asupersync |
| HRI-04 Two-phase effects | asupersync |
| HRI-05 Scheduler lane discipline | asupersync |
| HRI-06 Remote effects contract | asupersync |
| HRI-07 Epoch transition barriers | asupersync |
| HRI-08 Evidence-by-default | asupersync |
| HRI-09 Deterministic verification | asupersync |
| HRI-10 No ambient authority | franken_node |

## Boundary Rules

1. Product code consumes correctness via approved facade APIs only
2. Product code consumes execution via approved execution APIs only
3. Direct imports into `*_internal` modules are violations
4. Duplicate implementation across kernels is prohibited
5. Exceptions require signed waiver with explicit expiry

## Waiver Fields

| Field | Required |
|-------|----------|
| waiver_id | Yes |
| file | Yes |
| boundary | Yes |
| rationale | Yes |
| signed_by | Yes |
| signature | Yes |
| expires_at | Yes (RFC 3339) |

## Event Codes

| Code | Description |
|------|-------------|
| OWN-001 | Boundary check pass |
| OWN-002 | Boundary violation detected |
| OWN-003 | Valid waiver applied |
| OWN-004 | Waiver invalid or expired |

## Acceptance Criteria

- Architecture doc published at `docs/architecture/tri_kernel_ownership_contract.md`
- All 3 kernel planes defined with ownership responsibilities
- 10 HRI owners mapped
- Boundary violation check script with `--json` and `self_test()`
- Conformance test surface at `tests/conformance/ownership_boundary_checks.rs`
- Waiver registry at `docs/governance/ownership_boundary_waivers.json`
- Python test suite >= 10 tests, all passing
- CI gate verdict PASS

## Artifacts

- `docs/architecture/tri_kernel_ownership_contract.md`
- `docs/governance/ownership_boundary_waivers.json`
- `tests/conformance/ownership_boundary_checks.rs`
- `scripts/check_ownership_violations.py`
- `tests/test_check_ownership_violations.py`
- `docs/specs/section_10_15/bd-1id0_contract.md`
- `artifacts/section_10_15/bd-1id0/verification_evidence.json`
- `artifacts/section_10_15/bd-1id0/verification_summary.md`
