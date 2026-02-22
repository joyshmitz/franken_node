# bd-h93z: Release Gate Requiring Asupersync-Backed Conformance on High-Impact Features

---
schema_version: rlg-v1.0
bead_id: bd-h93z
section: 10.15
type: release-gate
priority: P1
---

## Overview

This contract defines a release gate that blocks shipping of high-impact features
unless they carry asupersync-backed conformance evidence. The gate validates that
every high-impact change set includes the required artifact bundle: evidence entries,
replay verification, cancellation injection report, DPOR exploration results, epoch
validity proof, and obligation leak oracle report. The gate emits a signed,
machine-readable verdict.

## Feature Classification

Features are classified into impact tiers for gate applicability:

| Tier | Label | Gate Required | Examples |
|------|-------|---------------|----------|
| T1 | Critical | Yes (all artifacts) | Epoch transitions, control-plane protocols |
| T2 | High | Yes (subset) | Connector lifecycle, federation sync |
| T3 | Standard | No | Documentation, tooling, test-only |

Only T1 and T2 features are subject to this gate. T3 features pass unconditionally.

## Required Artifact Types

For each gated feature, the following artifacts MUST be present and valid:

| Artifact Type | Description | Required For |
|---------------|-------------|-------------|
| evidence_entries | Structured JSON entries proving behavior | T1, T2 |
| replay_verification | Deterministic replay transcript confirming reproducibility | T1 |
| cancellation_injection_report | Report from cancel-injection harness | T1 |
| dpor_results | Partial-order reduction exploration summary | T1 |
| epoch_validity | Proof that epoch invariants hold across the change | T1, T2 |
| obligation_leak_oracle_report | Oracle report confirming no leaked obligations | T1 |

## Gate Contract

### Evaluation Flow

1. Enumerate changed files and classify affected features by tier.
2. For each T1/T2 feature, verify the required artifact set is present.
3. Validate each artifact against its JSON schema.
4. Compute a canonical SHA-256 digest of the artifact bundle.
5. Sign the verdict with the release gate key.
6. Emit the machine-readable verdict JSON.

### Decision Rules

- **PASS**: All required artifacts are present, schema-valid, and the bundle digest
  can be independently verified.
- **FAIL**: Any required artifact is missing, malformed, or fails schema validation.
  The gate MUST hard-fail; no manual override is possible without a waiver.

## Signing Process and Key Management

### Signing

The gate produces a deterministic canonical verdict:

1. Build a canonical JSON payload containing: `bead_id`, `gate_version`,
   `generated_at_utc`, `artifact_statuses`, `verdict`, `public_key_id`,
   `signature_algorithm`.
2. Serialize with sorted keys and compact separators (`json.dumps(sort_keys=True, separators=(',', ':'))`).
3. Compute SHA-256 of the serialized payload to produce `canonical_payload_sha256`.
4. Compute signature as SHA-256 of `"{public_key_id}:{canonical_payload_sha256}"`.

### Key Management

- Production keys are stored in a hardware security module (HSM).
- CI uses a mock key (`mock-rlg-key-001`) for testing and development.
- Key rotation follows the epoch-scoped key derivation contract (section 10.9).
- Revoked keys are listed in the revocation freshness ledger.

## Exception / Waiver Process

A waiver allows a release to proceed despite a gate failure under exceptional
circumstances.

### Waiver Requirements

| Field | Description |
|-------|-------------|
| waiver_id | Unique identifier (e.g., `WAIVER-RLG-2026-001`) |
| bead_id | Bead that triggered the failure |
| reason | Detailed justification |
| approver | Identity of the approver (must be a release owner) |
| issued_at | ISO-8601 timestamp |
| expires_at | ISO-8601 timestamp; MUST be within 14 days of `issued_at` |
| scope | List of specific artifact types being waived |

### Waiver Invariants

- A waiver MUST NOT cover more than one bead.
- A waiver MUST expire within 14 calendar days (`INV-RLG-WAIVER-EXPIRY`).
- Expired waivers are treated as absent; the gate re-fails.
- Waivers are recorded in the release gate report for audit.

## Invariants

| ID | Statement |
|----|-----------|
| INV-RLG-HARD-FAIL | A missing or invalid artifact MUST cause a hard gate failure; no silent degradation. |
| INV-RLG-SIGNED | Every gate verdict MUST carry a canonical signature verifiable by external auditors. |
| INV-RLG-WAIVER-EXPIRY | Waivers MUST expire within 14 calendar days of issuance. |
| INV-RLG-SCHEMA-VALID | Every artifact MUST validate against its declared JSON schema before the gate can PASS. |

## Event Codes

| Code | Description |
|------|-------------|
| RLG-001 | Gate evaluation started |
| RLG-002 | All required artifacts present and valid; verdict PASS |
| RLG-003 | One or more required artifacts missing; verdict FAIL |
| RLG-004 | Artifact schema validation failed |
| RLG-005 | Waiver applied; recording exception |
| RLG-006 | Waiver expired; re-evaluating as failure |
| RLG-007 | Verdict signed and emitted |

## Gate Behavior

### On PASS

- Emit `RLG-001`, `RLG-002`, `RLG-007`.
- Write signed verdict to `artifacts/10.15/release_gate_report.json`.
- CI job exits 0.

### On FAIL

- Emit `RLG-001`, `RLG-003` (and optionally `RLG-004`, `RLG-006`), `RLG-007`.
- Write signed verdict with `verdict: "FAIL"` and per-artifact failure details.
- CI job exits 1 (hard block).

### On Waiver

- Emit `RLG-001`, `RLG-005`, `RLG-007`.
- Write signed verdict with `verdict: "PASS_WITH_WAIVER"` and waiver details.
- CI job exits 0 but the waiver is prominently logged.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_15/bd-h93z_contract.md` |
| CI workflow | `.github/workflows/asupersync-integration-gate.yml` |
| Conformance doc | `docs/conformance/asupersync_release_gate.md` |
| Check script | `scripts/check_release_gate.py` |
| Test suite | `tests/test_check_release_gate.py` |
| Release gate report | `artifacts/10.15/release_gate_report.json` |
| Verification evidence | `artifacts/section_10_15/bd-h93z/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-h93z/verification_summary.md` |

## Dependencies

- **Upstream**: bd-145n (lab runtime), bd-1cwp (cancel injection), bd-25oa (DPOR), bd-1hbw (epoch barrier)
- **Downstream**: section 10.15 gate (bd-20eg)
