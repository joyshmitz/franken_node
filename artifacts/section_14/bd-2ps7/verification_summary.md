# bd-2ps7: Adversarial Resilience Metrics — Verification Summary

**Section:** 14 | **Bead:** bd-2ps7 | **Date:** 2026-02-20

## Gate Result: PASS (17/17)

All checks passed:
- Source exists and module wired in mod.rs
- 5 campaign types (BruteForce, Evasion, PrivilegeEscalation, DataExfiltration, SupplyChain)
- 4 required structs (ResilienceMetric, CampaignStats, ResilienceReport, AdversarialResilienceMetrics)
- Detection + block rate tracking
- Weighted resilience scoring (40% detection + 40% block + 20% response)
- Threshold gating with MIN_RESILIENCE_SCORE
- Flagged campaigns for below-threshold results
- 12/12 event codes (ARM-001..ARM-010, ARM-ERR-001, ARM-ERR-002)
- 6/6 invariants (INV-ARM-CLASSIFIED/DETERMINISTIC/SCORED/GATED/VERSIONED/AUDITABLE)
- JSONL audit export with ArmAuditRecord
- Schema version arm-v1.0
- Spec contract aligned
- Test coverage met

## Test Results
- **Gate script:** 17/17 PASS
- **Python tests:** 25/25 PASS
- **Rust tests:** 22+ in-module tests
