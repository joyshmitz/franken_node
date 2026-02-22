# VEF Coverage and Proof-Validity Metrics Integration (bd-3go4)

## Purpose

This specification defines how VEF (Verifiable Evidence Framework) coverage and proof-validity
metrics are integrated into the **claim compiler** and published on the **trust scoreboard**.
Claims that depend on VEF evidence must declare their requirements explicitly. The claim compiler
gates claims against live VEF coverage data, and the trust scoreboard publishes deterministic,
signed metric snapshots for external auditors.

**Bead:** bd-3go4 | **Section:** 10.18

## VEF Coverage Metrics

### Coverage Percentage

The coverage percentage reflects the fraction of action classes that have at least one valid,
non-stale VEF proof attached:

    coverage_pct = covered_action_classes / total_action_classes * 100

A system with 12 action classes where all 12 carry valid proofs has 100% coverage.

### Proof Freshness

Each proof carries a timestamp. A proof is considered **fresh** when its age in seconds is less
than or equal to `max_proof_age_secs` (default 3600). Stale proofs do not contribute to
coverage.

### Coverage Gaps by Action Class

A coverage gap is an action class for which no fresh, valid proof exists. Coverage gaps are
reported as a list of `(action_class_id, reason)` tuples to enable targeted remediation.

## VEF Validity Metrics

### Verification Success Rate

    success_rate = valid_proofs / total_proofs_checked * 100

Tracks the fraction of proofs that pass cryptographic verification.

### Verdict Distribution

Each proof verification yields one of:

| Verdict   | Meaning                             |
|-----------|-------------------------------------|
| `VALID`   | Proof passes all checks             |
| `INVALID` | Cryptographic verification failure  |
| `STALE`   | Proof exceeds max age               |
| `MISSING` | No proof exists for action class    |

### Degraded-Mode Fraction

    degraded_fraction = (stale_proofs + invalid_proofs) / total_proofs_checked

When degraded fraction exceeds a configurable threshold the scoreboard emits a warning event.

## Claim Compiler Integration

### Declaring VEF Evidence Requirements

Each claim in the claim compiler may declare a `vef_evidence` block:

```toml
[claim.trust-integrity]
vef_evidence.required = true
vef_evidence.min_coverage_pct = 80.0
vef_evidence.min_validity_rate = 95.0
```

When `vef_evidence.required = true`, the claim compiler queries the VEF metrics engine before
issuing a PASS verdict.

### Threshold Configuration

| Parameter             | Default | Description                                         |
|-----------------------|---------|-----------------------------------------------------|
| `min_coverage_pct`    | 80.0    | Minimum coverage percentage for claim to pass       |
| `min_validity_rate`   | 95.0    | Minimum proof verification success rate             |
| `max_proof_age_secs`  | 3600    | Maximum proof age before stale                      |

Thresholds are per-claim, allowing safety-critical claims to demand higher coverage than
informational ones.

### Gate Logic

1. Emit `VEF-CLAIM-001` (check initiated).
2. Compute coverage and validity metrics for the claim scope.
3. If `coverage_pct >= min_coverage_pct` **and** `success_rate >= min_validity_rate`:
   - Emit `VEF-CLAIM-002` (claim passed).
   - Return `PASS` verdict with evidence links.
4. Else:
   - Emit `VEF-CLAIM-003` (claim blocked).
   - Return `BLOCK` verdict with gap report.

## Scoreboard Publication Format

### Metrics

The trust scoreboard publishes a JSON snapshot with:

- `schema_version`: e.g. `"vef-claim-v1.0"`
- `bead_id`: originating bead identifier
- `section`: specification section
- `timestamp`: ISO 8601 UTC publication time
- `coverage`: object with `total_action_classes`, `covered_action_classes`,
  `coverage_percentage`, `coverage_gaps`
- `validity`: object with `total_proofs_checked`, `valid_proofs`,
  `verification_success_rate`, `degraded_mode_fraction`
- `claim_gate_results`: array of per-claim verdicts
- `scoreboard_published`: boolean
- `verdict`: overall `PASS` or `FAIL`

### Signed Evidence Links

Each scoreboard snapshot includes a `canonical_payload_sha256` over the deterministic JSON
encoding. Evidence links reference the snapshot by content hash, enabling external auditors to
independently verify scoreboard integrity.

### Deterministic Generation

Scoreboard snapshots are generated deterministically:

1. Metrics are collected at a fixed point in the pipeline.
2. JSON fields are serialized in canonical key order.
3. Floating-point values use a fixed precision (one decimal place).
4. The SHA-256 hash is computed over the canonical byte representation.

This ensures that two independent runs with the same input data produce byte-identical
snapshots.

## Event Codes

| Code            | Emitted When                                      |
|-----------------|---------------------------------------------------|
| `VEF-CLAIM-001` | Claim compiler initiates VEF evidence check       |
| `VEF-CLAIM-002` | Claim passes VEF coverage and validity gates      |
| `VEF-CLAIM-003` | Claim blocked due to insufficient coverage/validity|
| `VEF-SCORE-001` | Scoreboard snapshot published                     |

## Error Codes

| Code                          | Meaning                                  |
|-------------------------------|------------------------------------------|
| `ERR_VEF_CLAIM_INVALID_CONFIG`| Claim VEF evidence block is malformed    |
| `ERR_VEF_CLAIM_COVERAGE_LOW`  | Coverage below configured threshold      |
| `ERR_VEF_CLAIM_VALIDITY_LOW`  | Validity rate below configured threshold |
| `ERR_VEF_CLAIM_PROOF_STALE`   | All proofs for an action class are stale |
| `ERR_VEF_CLAIM_NO_EVIDENCE`   | No VEF evidence found for required claim |

## Invariants

- `INV-VEF-CLAIM-GATE`: Every claim with `vef_evidence.required = true` must pass through the
  VEF coverage gate before receiving a PASS verdict.
- `INV-VEF-CLAIM-DETERMINISTIC`: Given identical input metrics, the claim gate produces
  identical verdicts and evidence links.
- `INV-VEF-SCORE-TRACEABLE`: Every scoreboard snapshot links to verifiable evidence hashes.
- `INV-VEF-SCORE-REPRODUCIBLE`: Scoreboard generation is deterministic and reproducible from
  the same input state.

## Acceptance Criteria

1. Claims requiring VEF evidence are blocked when coverage is below the configured threshold.
2. Claims pass when both coverage and validity meet or exceed their thresholds.
3. Coverage gaps are reported with action class granularity.
4. The trust scoreboard publishes deterministic, content-addressed snapshots.
5. All event codes are emitted at the correct pipeline stages.
6. Evidence links are verifiable against the canonical payload hash.

## Test Scenarios

### Scenario 1: Full Coverage Pass

All 12 action classes have fresh, valid proofs. A claim requiring 80% coverage passes with
100% actual coverage. Events `VEF-CLAIM-001` and `VEF-CLAIM-002` are emitted.

### Scenario 2: Below-Threshold Block

Only 6 of 12 action classes are covered (50%). A claim requiring 80% coverage is blocked.
Events `VEF-CLAIM-001` and `VEF-CLAIM-003` are emitted. Error `ERR_VEF_CLAIM_COVERAGE_LOW`
is recorded.

### Scenario 3: Boundary Condition

Exactly 80% coverage (9.6 of 12 rounded to 10 classes). The claim with 80% threshold passes.
Validates that boundary comparisons use `>=`.

### Scenario 4: Evidence Link Verification

An external auditor recomputes the canonical payload hash from the published snapshot and
confirms it matches the signed evidence link.

### Scenario 5: Coverage Gap Detection

Action class `transfer-ownership` has no valid proof. The gap report lists this class with
reason `MISSING`. The claim requiring 95% coverage is blocked.
