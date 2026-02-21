# bd-2a4l: Externally Verifiable Trust/Security Claims

**Section:** 13 | **Type:** Success Criterion | **Priority:** P1

## Overview

All trust and security claims made by franken_node must be externally
verifiable and reproducible by independent parties. No claim relies solely
on internal attestation — every assertion about security posture,
compatibility coverage, or trust properties is backed by reproducible
evidence that third parties can audit without access to internal systems.

## Verifiability Dimensions

### VD-01: Reproducible Evidence Bundles

Every trust/security claim is accompanied by a self-contained evidence
bundle that includes: the claim statement, the verification procedure,
input data, expected output, and actual output. Bundles are content-
addressed (SHA-256) so tampering is detectable.

### VD-02: Independent Reproduction

Evidence bundles contain sufficient context for an external party to
reproduce the verification from scratch using only public tooling. No
proprietary runtime, internal API, or privileged access is required.

### VD-03: Deterministic Verification

Given identical inputs, verification procedures produce bit-identical
outputs. Non-determinism (timestamps, PIDs, random seeds) is stripped
or pinned before comparison.

### VD-04: Claim-to-Evidence Traceability

Every claim in documentation, marketing, or release notes links to a
specific evidence bundle by content hash. Orphaned claims (no evidence)
and stale claims (evidence older than release) are flagged by CI.

### VD-05: Adversarial Perturbation Testing

Verification procedures are tested under adversarial perturbations:
corrupted inputs, truncated evidence, tampered hashes, replayed old
bundles. The system must reject invalid evidence with clear error codes.

## Quantitative Targets

| Target | Threshold |
|--------|-----------|
| Claim coverage | 100% of public trust/security claims have evidence bundles |
| Reproduction success rate | >= 95% first-attempt reproduction by external party |
| Evidence freshness | All evidence < 30 days old at release time |
| Hash verification | 100% of bundles pass SHA-256 integrity check |
| Adversarial rejection | 100% of tampered bundles are rejected |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| EVC-001 | info | Evidence bundle generated and verified |
| EVC-002 | error | Claim found without corresponding evidence bundle |
| EVC-003 | warning | Evidence bundle approaching staleness threshold |
| EVC-004 | error | Evidence integrity check failed (hash mismatch or tamper detected) |

## Invariants

| ID | Statement |
|----|-----------|
| INV-EVC-COVERAGE | Every public trust/security claim has a linked evidence bundle |
| INV-EVC-REPRODUCE | Evidence bundles are reproducible without internal access |
| INV-EVC-DETERMINISM | Verification procedures produce deterministic outputs |
| INV-EVC-INTEGRITY | Evidence bundles pass content-addressed integrity checks |

## Acceptance Criteria

1. All public trust/security claims enumerated in a machine-readable claim registry.
2. Each claim links to a content-addressed evidence bundle under `artifacts/`.
3. Evidence bundles contain: claim statement, procedure, inputs, expected output, actual output.
4. An external-reproduction test validates that bundles can be verified with public tools only.
5. Determinism test: run verification twice, assert bit-identical outputs.
6. Adversarial test: inject corrupted/tampered evidence, assert rejection with EVC-004.
7. CI gate: orphaned claims and stale evidence (> 30 days) fail the build.
8. Verification script `scripts/check_verifiable_claims.py` with `--json` flag.
9. Unit tests in `tests/test_check_verifiable_claims.py`.

## Dependencies

- bd-1w78: Continuous lockstep validation (provides compatibility evidence bundles).
