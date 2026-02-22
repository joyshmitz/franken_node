# bd-209w: Signed Extension Registry — Verification Summary

**Section:** 15 — Ecosystem Capture Execution
**Bead:** bd-209w
**Verdict:** PASS
**Date:** 2026-02-21

## Implementation

Implemented signed extension registry with provenance and revocation in
`crates/franken-node/src/supply_chain/extension_registry.rs`.

### Extension Lifecycle

Submitted → Active → Deprecated → Revoked (terminal, irreversible)

### Capabilities

- Extension registration with mandatory signature verification (Ed25519)
- Provenance chain validation (publisher → build system → VCS commit)
- Monotonic revocation with 5 reason types and sequence numbering
- Version lineage with compatibility markers
- Status-based listing and query
- Content hash integrity verification
- Deterministic audit log with JSONL export

### Invariants Verified

| Invariant | Description |
|---|---|
| INV-SER-SIGNED | Every extension carries a valid signature |
| INV-SER-PROVENANCE | Provenance chain required for all registrations |
| INV-SER-REVOCABLE | Revocation is monotonic and irreversible |
| INV-SER-MONOTONIC | Version sequences strictly increase within lineage |
| INV-SER-AUDITABLE | Every mutation produces an immutable audit record |
| INV-SER-DETERMINISTIC | Same inputs produce same registry state |

## Test Coverage

| Suite | Count | Status |
|---|---|---|
| Rust unit tests | 29 | Module compiles clean |
| Python verification gate | 15 | All pass |
| Python unit tests | 20 | All pass |

## Artifacts

| Artifact | Path |
|---|---|
| Implementation | `crates/franken-node/src/supply_chain/extension_registry.rs` |
| Spec contract | `docs/specs/section_15/bd-209w_contract.md` |
| Verification script | `scripts/check_signed_extension_registry.py` |
| Python tests | `tests/test_check_signed_extension_registry.py` |
| Evidence JSON | `artifacts/section_15/bd-209w/verification_evidence.json` |

## Dependencies

- **Downstream:** bd-2nre (section gate), bd-wpck (migration kit), bd-t8m (plan tracker)
