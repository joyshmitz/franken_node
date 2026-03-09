# bd-209w: Signed Extension Registry — Verification Summary

**Section:** 15 — Ecosystem Capture Execution
**Bead:** bd-209w
**Verdict:** PASS
**Date:** 2026-03-09

## Implementation

Implemented signed extension registry with provenance and revocation in
`crates/franken-node/src/supply_chain/extension_registry.rs`.

### Extension Lifecycle

Submitted → Active → Deprecated → Revoked (terminal, irreversible)

### Capabilities

- Extension registration with canonical AdmissionKernel (Ed25519 signature, provenance chain, transparency proofs)
- No shape-only admission checks (INV-SER-NO-SHAPE-CHECKS)
- Admission receipts with NegativeWitness for rejection explanations
- Provenance chain validation via canonical attestation verifier
- Monotonic revocation with 5 reason types and sequence numbering
- Version lineage with compatibility markers
- Status-based listing and query
- Content hash integrity verification
- Deterministic audit log with JSONL export (bounded at 4096 entries)

### Invariants Verified

| Invariant | Description |
|---|---|
| INV-SER-SIGNED | Every extension carries a valid Ed25519 signature |
| INV-SER-PROVENANCE | Provenance chain required for all registrations |
| INV-SER-REVOCABLE | Revocation is monotonic and irreversible |
| INV-SER-MONOTONIC | Version sequences strictly increase within lineage |
| INV-SER-AUDITABLE | Every mutation produces an immutable audit record |
| INV-SER-DETERMINISTIC | Same inputs produce same registry state |
| INV-SER-NO-SHAPE-CHECKS | No admission decision relies on field presence alone |

## Test Coverage

| Suite | Count | Status |
|---|---|---|
| Rust unit tests | 42 | All pass |
| Python verification gate | 15 | All pass |
| Python unit tests | 20 | All pass |

## Gap Closures

| Bead | Description | Status |
|------|-------------|--------|
| bd-3hdn | Canonical signed-manifest admission kernel | CLOSED |

## Artifacts

| Artifact | Path |
|---|---|
| Implementation | `crates/franken-node/src/supply_chain/extension_registry.rs` |
| Provenance module | `crates/franken-node/src/supply_chain/provenance.rs` |
| Artifact signing | `crates/franken-node/src/supply_chain/artifact_signing.rs` |
| Spec contract | `docs/specs/section_15/bd-209w_contract.md` |
| Verification script | `scripts/check_signed_extension_registry.py` |
| Python tests | `tests/test_check_signed_extension_registry.py` |
| Evidence JSON | `artifacts/section_15/bd-209w/verification_evidence.json` |

## Dependencies

- **Downstream:** bd-2nre (section gate), bd-wpck (migration kit), bd-t8m (plan tracker)
