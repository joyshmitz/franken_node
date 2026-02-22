# Claim-Language Policy

**Section:** 10.15 | **Bead:** bd-33kj | **Status:** Active

## Purpose

This policy defines a formal mapping from every public trust and replay claim that
franken_node makes to the specific asupersync-backed invariant(s) that provide the
evidence for those claims. No marketing, documentation, or API-surface claim may exist
without a verified backing invariant and a machine-readable evidence artifact path.

## Rules

1. **No Claim Without Backing Invariant.** Every public claim MUST reference at least
   one asupersync-backed invariant identifier (e.g., `INV-EP-MONOTONIC`). A claim that
   cannot cite a specific invariant is classified as unbacked (CLM-002) and must be
   either substantiated or retired.

2. **Claims Must Cite Evidence Artifact Path.** Each claim entry MUST include an
   `evidence_artifact` path pointing to a verification evidence JSON file under
   `artifacts/`. The evidence file MUST contain a `"verdict": "PASS"` field.

3. **Staleness Window.** Evidence older than 90 days triggers a CLM-003 (evidence stale)
   event. Stale claims are not considered verified until re-validated.

4. **Retirement Protocol.** Retired claims emit CLM-004 and are moved to the
   Retired Claims section. They MUST NOT appear in external documentation.

5. **Claim Text Immutability.** Once a claim is registered and verified, its claim text
   MUST NOT be modified without re-verification. Textual changes reset the claim to
   pending status.

## Event Codes

| Code    | Name             | Description                                          |
|---------|------------------|------------------------------------------------------|
| CLM-001 | Claim Verified   | Claim has a backing invariant and passing evidence    |
| CLM-002 | Claim Unbacked   | Claim lacks a backing invariant reference             |
| CLM-003 | Evidence Stale   | Evidence artifact is older than the staleness window  |
| CLM-004 | Claim Retired    | Claim has been retired and removed from active set    |

## Claim-Invariant Mapping Table

| Claim ID  | Claim Text                                       | Category    | Backing Invariant(s)                                 | Evidence Artifact                                              |
|-----------|--------------------------------------------------|-------------|------------------------------------------------------|----------------------------------------------------------------|
| CLM-DR-01 | Deterministic replay of trust-native executions  | replay      | INV-EP-MONOTONIC, INV-EP-DRAIN-BARRIER               | artifacts/section_10_15/bd-33kj/verification_evidence.json     |
| CLM-TR-01 | Trust-native execution with epoch-scoped keys    | trust       | INV-EP-FAIL-CLOSED, INV-EP-SPLIT-BRAIN-GUARD         | artifacts/section_10_15/bd-33kj/verification_evidence.json     |
| CLM-CR-01 | Compromise reduction via evidence-by-default     | security    | INV-EP-IMMUTABLE-CREATION-EPOCH, INV-EP-AUDIT-HISTORY | artifacts/section_10_15/bd-33kj/verification_evidence.json     |
| CLM-IC-01 | Immutable creation epoch for artifact provenance | integrity   | INV-EP-IMMUTABLE-CREATION-EPOCH                      | artifacts/section_10_15/bd-33kj/verification_evidence.json     |
| CLM-FC-01 | Fail-closed on epoch unavailability              | resilience  | INV-EP-FAIL-CLOSED                                   | artifacts/section_10_15/bd-33kj/verification_evidence.json     |

## Invariant Definitions

The backing invariants referenced above are defined and enforced by the asupersync
correctness/control kernel:

| Invariant ID                  | Statement                                                    |
|-------------------------------|--------------------------------------------------------------|
| INV-EP-MONOTONIC              | Epoch transitions are strictly monotonically increasing      |
| INV-EP-DRAIN-BARRIER          | All in-flight operations drain before epoch advance          |
| INV-EP-FAIL-CLOSED            | Unavailable epoch source returns error, never stale data     |
| INV-EP-SPLIT-BRAIN-GUARD      | Bounded lag guard prevents split-brain across replicas       |
| INV-EP-IMMUTABLE-CREATION-EPOCH | Artifact creation epoch is set once and never mutated      |
| INV-EP-AUDIT-HISTORY          | All epoch transitions are recorded with full metadata        |

## Verification

Run the claim-language policy check:

```bash
python3 scripts/check_claim_language_policy.py --json
```

Self-test:

```bash
python3 scripts/check_claim_language_policy.py --self-test
```

## Retired Claims

_No claims have been retired._
