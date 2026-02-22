# bd-2yvw: Sybil-Resistant Participation Controls

**Section:** 10.19 — Adversarial Trust Commons (9M)
**Status:** Implemented
**Module:** `crates/franken-node/src/federation/atc_participation_weighting.rs`

## Purpose

Implements Sybil-resistant participation weighting for the ATC federation network. Participation influence is tied to verifiable attestation, staking, and reputation evidence, preventing untrusted identity inflation.

## Core Types

| Type | Role |
|------|------|
| `AttestationEvidence` | Cryptographic attestation with issuer, level, expiry, signature |
| `AttestationLevel` | SelfSigned (0.1x) < PeerVerified (0.4x) < VerifierBacked (0.8x) < AuthorityCertified (1.0x) |
| `StakeEvidence` | Stake deposit with amount, lock duration, locked status |
| `ReputationEvidence` | Cumulative score, interaction count, tenure, accepted/rejected contributions |
| `ParticipantIdentity` | Identity with attestations, stake, reputation, cluster hint |
| `ParticipationWeight` | Computed weight with component breakdown, penalty, cap status |
| `WeightAuditRecord` | Batch audit with participant stats, cluster detections, content hash |
| `SybilCluster` | Detected cluster with member IDs, detection signal, attenuation factor |
| `WeightingConfig` | Configurable thresholds for attestation/stake/reputation weights, caps, attenuation |
| `ParticipationWeightEngine` | Engine computing weights with Sybil detection and audit logging |

## Weight Formula

```
attestation_component = strongest_attestation_level.multiplier()  // [0.1, 1.0]
stake_component       = min(ln1p(amount)/10, 1) + lock_bonus      // [0, 1]
reputation_component  = score*0.4 + tenure_ratio*0.3 + accept_ratio*0.3  // [0, 1]

raw_weight = attestation * 0.4 + stake * 0.3 + reputation * 0.3
```

## Sybil Controls

1. **Cluster detection**: Participants sharing `cluster_hint` (IP subnet, timing fingerprint) grouped; clusters >= 3 members flagged
2. **Cluster attenuation**: Detected clusters receive 90% weight reduction (configurable)
3. **New participant cap**: New participants capped at 1% of median established weight
4. **Zero-attestation rejection**: Participants without any attestation evidence receive zero weight

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-ATC-SYBIL-BOUND | 100 Sybil identities < aggregate weight of 5 honest established participants |
| INV-ATC-WEIGHT-DETERMINISM | Identical inputs produce identical weights and content hash |
| INV-ATC-NEW-NODE-CAP | New participant weight <= 1% of median established weight |
| INV-ATC-STAKE-MONOTONE | Higher stake always produces higher stake component |
| INV-ATC-ATTESTATION-REQUIRED | Zero-attestation participants receive zero weight |
| INV-ATC-AUDIT-COMPLETE | Every compute_weights call produces an audit record |
| INV-ATC-CLUSTER-ATTENUATION | Detected Sybil clusters have weight reduced by >= 90% |

## Event Codes

| Code | Meaning |
|------|---------|
| ATC-PART-001 | Weight computed |
| ATC-PART-002 | Sybil cluster detected |
| ATC-PART-003 | New participant capped |
| ATC-PART-004 | Zero-attestation rejected |
| ATC-PART-005 | Audit record emitted |
| ATC-PART-006 | Policy evaluated |
| ATC-PART-007 | Stake verified |
| ATC-PART-008 | Reputation refreshed |
| ATC-PART-ERR-001 | Weight computation failed |
| ATC-PART-ERR-002 | Invalid attestation |

## Configuration Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| attestation_weight | 0.4 | Weight factor for attestation component |
| stake_weight | 0.3 | Weight factor for stake component |
| reputation_weight | 0.3 | Weight factor for reputation component |
| new_participant_cap_fraction | 0.01 | Max weight for new participants (fraction of median) |
| established_tenure_seconds | 2,592,000 | 30 days to be "established" |
| established_interaction_count | 100 | Min interactions to be "established" |
| sybil_attenuation_factor | 0.1 | Cluster weight multiplier (90% reduction) |
| sybil_cluster_min_size | 3 | Min members to trigger Sybil detection |

## Test Coverage

- 20 Rust inline tests covering all 7 invariants plus serialization, config, edge cases
- Python verification gate checks via `scripts/check_atc_participation.py`
- Python unit tests via `tests/test_check_atc_participation.py`

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_19/bd-2yvw_contract.md` |
| Rust module | `crates/franken-node/src/federation/atc_participation_weighting.rs` |
| Module registration | `crates/franken-node/src/federation/mod.rs` |
| Main registration | `crates/franken-node/src/main.rs` (pub mod federation) |
| Check script | `scripts/check_atc_participation.py` |
| Unit tests | `tests/test_check_atc_participation.py` |
| Audit report | `artifacts/10.19/atc_weighting_audit_report.json` |
| Evidence | `artifacts/section_10_19/bd-2yvw/verification_evidence.json` |
| Summary | `artifacts/section_10_19/bd-2yvw/verification_summary.md` |
