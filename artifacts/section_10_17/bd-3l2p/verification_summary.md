# bd-3l2p Verification Summary

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-3l2p |
| Section | 10.17 |
| Title | Intent-aware remote effects firewall for extension-originated traffic |
| Verdict | PASS |

## Implementation Overview

The intent-aware remote effects firewall (`intent_firewall.rs`) classifies every
outbound remote effect from extensions by intent category, applies traffic policy
rules, and issues deterministic decision receipts for audit and replay.

### Intent Categories (10 total)

- **Non-risky**: data_fetch, data_mutation, webhook_dispatch, analytics_export,
  service_discovery, health_check, config_sync
- **Risky** (default deny): exfiltration, credential_forward, side_channel

### Verdict Pathways (5 total)

- **Allow**: Traffic is permitted
- **Challenge**: Interactive challenge required before proceeding
- **Simulate**: Sandboxed evaluation before real execution
- **Deny**: Traffic is blocked
- **Quarantine**: Traffic is held for later review (capacity-bounded)

## Invariants Verified

| Invariant | Status |
|-----------|--------|
| INV-FW-FAIL-CLOSED | PASS - Unclassifiable traffic denied with receipt |
| INV-FW-RECEIPT-EVERY-DECISION | PASS - Every decision produces a receipt |
| INV-FW-RISKY-DEFAULT-DENY | PASS - Risky categories denied by default |
| INV-FW-DETERMINISTIC | PASS - BTreeMap ordering ensures determinism |
| INV-FW-EXTENSION-SCOPED | PASS - Node-internal traffic bypasses firewall |

## Test Coverage

- 28 Rust unit tests covering all verdict pathways, error variants, invariant
  enforcement, and deterministic replay
- 14 Python test methods across 4 test classes (self-test, checks, CLI, regression)
- Check script supports `--json` and `--self-test` flags

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec contract | `docs/specs/section_10_17/bd-3l2p_contract.md` | Present |
| Rust module | `crates/franken-node/src/security/intent_firewall.rs` | Present |
| Check script | `scripts/check_effects_firewall.py` | Present |
| Test suite | `tests/test_check_effects_firewall.py` | Present |
| Evidence | `artifacts/section_10_17/bd-3l2p/verification_evidence.json` | PASS |
| Summary | `artifacts/section_10_17/bd-3l2p/verification_summary.md` | Present |
