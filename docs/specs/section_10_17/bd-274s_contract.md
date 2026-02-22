# bd-274s: Bayesian Adversary Graph and Automated Quarantine Controller

## Section
10.17 -- Radical Expansion Execution Track

## Summary

Implements a Bayesian adversary graph that tracks entities (publishers,
extensions, maintainers, dependencies) with risk posteriors updated
deterministically from evidence events, and an automated quarantine
controller that maps risk levels to control actions via policy thresholds.

## Acceptance Criteria

1. Risk posterior updates are deterministic: identical evidence sequences
   produce bit-identical posteriors across all nodes.
2. Policy thresholds trigger reproducible control actions:
   - Throttle at >= 0.3
   - Isolate at >= 0.5
   - Revoke at >= 0.7
   - Quarantine at >= 0.9
3. Every evidence entry is signed (HMAC-SHA256) before storage.
4. Evidence log sequence numbers are strictly monotonically increasing.
5. Structured event codes ADV-001 through ADV-008 are used.

## Deliverables

| Artifact | Path |
|----------|------|
| Adversary graph module | `crates/franken-node/src/security/adversary_graph.rs` |
| Quarantine controller module | `crates/franken-node/src/security/quarantine_controller.rs` |
| Spec contract | `docs/specs/section_10_17/bd-274s_contract.md` |
| Check script | `scripts/check_adversary_graph.py` |
| Unit test suite | `tests/test_check_adversary_graph.py` |
| State snapshot artifact | `artifacts/10.17/adversary_graph_state.json` |
| Verification evidence | `artifacts/section_10_17/bd-274s/verification_evidence.json` |
| Verification summary | `artifacts/section_10_17/bd-274s/verification_summary.md` |

## Event Codes

| Code | Meaning |
|------|---------|
| ADV-001 | Node added to adversary graph |
| ADV-002 | Trust edge added between nodes |
| ADV-003 | Evidence ingested and posterior updated |
| ADV-004 | Risk posterior crossed a policy threshold |
| ADV-005 | Quarantine action triggered by controller |
| ADV-006 | Node removed from adversary graph |
| ADV-007 | Evidence replay completed for determinism check |
| ADV-008 | Signed evidence entry appended to log |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_ADV_NODE_NOT_FOUND | Node not found in the adversary graph |
| ERR_ADV_DUPLICATE_NODE | Duplicate node ID insertion attempted |
| ERR_ADV_DANGLING_EDGE | Edge references a non-existent node |
| ERR_ADV_INVALID_EVIDENCE_WEIGHT | Evidence weight not in [0, 1] |
| ERR_QC_INVALID_KEY | Signing key is empty or invalid |
| ERR_QC_SEQUENCE_VIOLATION | Evidence log sequence invariant violated |

## Invariants

| Tag | Description |
|-----|-------------|
| INV-ADV-DETERMINISTIC | Identical evidence produces identical posteriors |
| INV-ADV-PRIOR-BOUNDED | Initial prior risk is in (0, 1) |
| INV-ADV-MONOTONE-EVIDENCE | Evidence count is monotonically non-decreasing |
| INV-QC-SIGNED-LOG | Every evidence entry is signed before storage |
| INV-QC-THRESHOLD-REPRODUCIBLE | Identical posteriors produce identical actions |
| INV-QC-SEQUENCE-MONOTONIC | Sequence numbers are strictly increasing |

## Bayesian Model

Uses a Beta-Bernoulli conjugate model:
- Prior: alpha=1.0, beta=9.0 (initial risk = 0.1)
- Each evidence event with adverse_weight w increments alpha by w and beta by (1-w)
- Posterior risk = alpha / (alpha + beta)
- Deterministic: no RNG, no floating-point non-determinism (addition only)

## Dependencies

- bd-1nl1 (proof-carrying speculative execution governance framework)
