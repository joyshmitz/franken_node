# bd-13q Contract: Stable Product Error Namespace + Compatibility Policy

**Bead:** bd-13q  
**Section:** 10.10 (FCP-Inspired Hardening)  
**Status:** Active  
**Owner:** MagentaSparrow

## Purpose

Adopt the canonical 10.13 error registry as the single source of truth for
product-surface errors and enforce an append-only compatibility policy across
CLI/API/protocol/log/SDK outputs.

This contract ensures every exposed error is machine-addressable, stable across
versions, and telemetry-safe.

## Dependencies

- **Upstream:** bd-novi (10.13 stable error registry)
- **Upstream:** bd-1ugy (10.13 stable telemetry namespace)
- **Downstream:** bd-1jjq (10.10 section verification gate)

## Product Prefix Registry

The surface prefixes are fixed and registered:

- `FN-CTRL-` (control plane)
- `FN-MIG-` (migration)
- `FN-AUTH-` (authentication/authorization)
- `FN-POL-` (policy)
- `FN-ZON-` (zone/tenant)
- `FN-TOK-` (token/session framing)

## Data Structures

| Type | Purpose |
|---|---|
| `ProductError` | Canonical + surface error payload with trace/context |
| `ProductSurface` | Surface selector used for FN-* prefix assignment |
| `ErrorCompatibilityPolicy` | Append-only + category/retryable stability policy |
| `CompatibilityReport` | Added/unchanged/violations diff report |

## Invariants

- **INV-ENS-REGISTRY-SOURCE:** Canonical error codes MUST exist in the 10.13
  registry before they can be emitted on any product surface.
- **INV-ENS-APPEND-ONLY:** Published canonical codes are append-only; removals
  are compatibility violations.
- **INV-ENS-CATEGORY-STABLE:** Existing codes cannot change category
  (`TRANSIENT`, `PERMANENT`, `CONFIGURATION`).
- **INV-ENS-TELEMETRY-DIMENSION:** Error telemetry MUST include
  `error.code=<canonical_code>` and MUST NOT use free-form code strings.
- **INV-ENS-RECOVERY-HINT:** Newly added non-fatal codes require a non-empty,
  actionable recovery hint with length >= 20.

## Event Codes

| Code | Description |
|---|---|
| `ENS-001` | Product-surface namespace policy loaded |
| `ENS-002` | Compatibility report generated |
| `ENS-003` | Coverage audit generated |
| `ENS-004` | Compatibility violation detected |

## Acceptance Criteria

1. Canonical error registry is the source for all surfaced product errors.
2. All six required `FN-*` prefix families are defined and enforced.
3. Compatibility checker fails on code removals and category/retryable changes.
4. `product_error!` / builder rejects unregistered canonical codes.
5. Error telemetry dimensions always include `error.code`.
6. Coverage audit reports zero unmapped surfaced errors.
7. Verification outputs are reproducible via checker scripts.

## Verification

- Script: `scripts/check_error_namespace.py --json`
- Compatibility diff: `scripts/check_error_compat.py --json`
- Coverage gate: `scripts/check_error_coverage.py --json`
- Evidence: `artifacts/section_10_10/bd-13q/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-13q/verification_summary.md`
- Audit: `artifacts/section_10_10/bd-13q/error_audit.json`
