# bd-3go4 Contract: VEF Coverage and Proof-Validity Metrics Integration

**Bead:** bd-3go4
**Section:** 10.18 (Verifiable Execution Fabric)
**Status:** Active
**Owner:** SilverMeadow

## Purpose

Integrate VEF coverage and proof-validity metrics into the claim compiler
and public trust scoreboard so that published security/compliance claims
are backed by cryptographic evidence and external observers can verify
trust posture in real-time.

## Configuration

| Field                         | Type   | Default | Description                                    |
|-------------------------------|--------|---------|------------------------------------------------|
| `min_coverage_pct`            | f64    | 0.80    | Min VEF coverage percentage to pass claim gate |
| `min_validity_rate`           | f64    | 0.95    | Min proof verification success rate            |
| `max_proof_age_secs`          | u64    | 3600    | Max age of a proof before it's stale           |
| `scoreboard_publish_interval` | u64    | 60      | Scoreboard publish interval in seconds         |

## Event Codes

| Code         | Severity | Structured Log Event                      | Description                                |
|--------------|----------|-------------------------------------------|--------------------------------------------|
| VEF-CLAIM-001 | INFO   | `vef.claim_check_initiated`               | Claim VEF evidence check started           |
| VEF-CLAIM-002 | INFO   | `vef.claim_passed`                        | Claim passed VEF gate                      |
| VEF-CLAIM-003 | WARN   | `vef.claim_blocked`                       | Claim blocked by VEF coverage gap          |
| VEF-SCORE-001 | INFO   | `vef.scoreboard_updated`                  | Scoreboard updated with VEF metrics        |
| VEF-SCORE-002 | INFO   | `vef.scoreboard_evidence_linked`          | Evidence link added to scoreboard          |
| VEF-SCORE-003 | WARN   | `vef.coverage_gap_detected`               | Coverage gap detected in action class      |

## Error Codes

| Code                          | Description                               |
|-------------------------------|-------------------------------------------|
| ERR_VEF_CLAIM_INVALID_CONFIG  | Configuration parameter out of range      |
| ERR_VEF_CLAIM_COVERAGE_LOW    | VEF coverage below required threshold     |
| ERR_VEF_CLAIM_VALIDITY_LOW    | Proof validity rate below threshold       |
| ERR_VEF_CLAIM_PROOF_STALE     | Proof age exceeds freshness limit         |
| ERR_VEF_CLAIM_NO_EVIDENCE     | No VEF evidence available for claim       |

## Invariants

- **INV-VEF-CLAIM-GATE** — A claim requiring VEF evidence is blocked if
  coverage is below `min_coverage_pct` or validity is below `min_validity_rate`.
- **INV-VEF-CLAIM-DETERMINISTIC** — Claim gate evaluation is deterministic:
  identical metrics produce identical pass/block decisions.
- **INV-VEF-SCORE-TRACEABLE** — Every scoreboard metric is traceable to
  specific proof evidence via signed evidence links.
- **INV-VEF-SCORE-REPRODUCIBLE** — Scoreboard publications are deterministic
  and reproducible from the underlying evidence.

## Types

### VefMetrics

| Field                | Type   | Description                              |
|----------------------|--------|------------------------------------------|
| `coverage_pct`       | f64    | Percentage of action classes with proofs  |
| `validity_rate`      | f64    | Proof verification success rate           |
| `proof_count`        | usize  | Total valid proofs                        |
| `gap_count`          | usize  | Number of coverage gaps                   |
| `avg_proof_age_secs` | u64    | Average proof age in seconds              |
| `degraded_time_frac` | f64    | Fraction of time in degraded mode         |

### ClaimRequirement

| Field                | Type   | Description                              |
|----------------------|--------|------------------------------------------|
| `claim_id`           | String | Unique claim identifier                  |
| `claim_text`         | String | Claim description                        |
| `min_coverage`       | f64    | Required coverage for this claim         |
| `min_validity`       | f64    | Required validity for this claim         |
| `action_classes`     | Vec    | Required action class proofs             |

### ClaimGateResult

| Field                | Type   | Description                              |
|----------------------|--------|------------------------------------------|
| `claim_id`           | String | Claim identifier                         |
| `passed`             | bool   | Whether the claim passed                 |
| `coverage`           | f64    | Actual coverage                          |
| `validity`           | f64    | Actual validity                          |
| `gaps`               | Vec    | Coverage gap descriptions                |
| `reason`             | String | Reason for pass/block                    |

### ScoreboardEntry

| Field                | Type   | Description                              |
|----------------------|--------|------------------------------------------|
| `timestamp`          | u64    | Publication timestamp                    |
| `metrics`            | VEF    | VEF coverage/validity metrics            |
| `evidence_links`     | Vec    | Links to specific proofs                 |
| `signed_digest`      | bytes  | Signed digest of the entry               |

## Acceptance Criteria

1. `VefClaimIntegration` in `crates/franken-node/src/connector/vef_claim_integration.rs`
   with claim compiler gate and scoreboard integration.
2. Claim gate correctly blocks claims when VEF coverage is below threshold.
3. Claim gate correctly passes claims when VEF coverage meets requirements.
4. Scoreboard publishes VEF metrics with signed evidence links.
5. Coverage gap reporting identifies specific action classes missing proofs.
6. Threshold configuration is policy-driven.
7. >= 30 unit tests covering all invariants.
8. Verification script `scripts/check_vef_claim_integration.py` passes.
9. Evidence artifacts in `artifacts/section_10_18/bd-3go4/`.

## Dependencies

- Section 10.18 VEF proof pipeline (metrics source).

## File Layout

```
docs/specs/section_10_18/bd-3go4_contract.md   (this file)
docs/policy/vef_claim_integration.md
crates/franken-node/src/connector/vef_claim_integration.rs
scripts/check_vef_claim_integration.py
tests/test_check_vef_claim_integration.py
artifacts/section_10_18/bd-3go4/verification_evidence.json
artifacts/section_10_18/bd-3go4/verification_summary.md
```
