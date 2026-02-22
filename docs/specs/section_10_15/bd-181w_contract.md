# bd-181w: Canonical Epoch-Scoped Validity Windows for Control Artifacts

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-181w |
| Section | 10.15 |
| Title | Integrate canonical epoch-scoped validity windows for control artifacts and remote contracts |
| Type | task |

## Purpose

Hard Runtime Invariant #7 (Section 8.5) requires epoch barriers: control
artifacts and remote contracts must be scoped to a validity epoch so stale
artifacts from a previous configuration epoch cannot influence decisions in the
current epoch.

This bead integrates canonical epoch-scoped validity windows (from Section
10.14, bd-3hdv and bd-2xv8) into the control-plane layer. Control artifacts
(rollout plans, fencing tokens, health-gate policies, migration checkpoints)
and remote contracts (distributed lock leases, cross-node coordination
messages) carry epoch stamps and are validated against the canonical validity
window before use.

## Deliverables

| Artifact | Path |
|----------|------|
| Adoption doc | `docs/integration/control_epoch_validity_adoption.md` |
| Fencing module | `crates/franken-node/src/connector/fencing.rs` |
| Rollout state module | `crates/franken-node/src/connector/rollout_state.rs` |
| Health gate module | `crates/franken-node/src/connector/health_gate.rs` |
| Conformance test | `tests/security/control_epoch_validity.rs` |
| Unit test | `crates/franken-node/tests/control_epoch_validity.rs` |
| Decision artifact | `artifacts/10.15/epoch_validity_decisions.json` |
| Evidence | `artifacts/section_10_15/bd-181w/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-181w/verification_summary.md` |

## Invariants

- **INV-EPOCH-SCOPE**: Every control artifact and remote contract carries an
  epoch stamp validated against the current validity window.
- **INV-EPOCH-FAIL-CLOSED**: Future-epoch artifacts are rejected fail-closed.
- **INV-EPOCH-STALENESS**: Artifacts older than `current_epoch - max_staleness`
  are rejected.
- **INV-EPOCH-LOGGED**: Accepted high-impact operations log epoch scope for
  traceability.

## Gate Contract

Verification evidence records all deliverable existence checks and targeted
compilation results. Workspace-wide baseline failures (outside bd-181w scope)
are documented but do not block the bead verdict.
