# bd-33kj: Claim-Language Policy for Trust/Replay Claims

**Section:** 10.15 | **Type:** policy | **Priority:** P1

## Overview

Defines a claim-language policy that creates a formal, machine-verifiable mapping
from every public trust and replay claim that franken_node makes to the specific
asupersync-backed invariants that provide backing evidence. Ensures no marketing,
documentation, or API-surface claim exists without verified invariant support.

## Policy Scope

### Claim Categories

| Category   | Description                                      |
|------------|--------------------------------------------------|
| replay     | Claims about deterministic replay capabilities   |
| trust      | Claims about trust-native execution properties   |
| security   | Claims about compromise reduction / evidence     |
| integrity  | Claims about artifact provenance / immutability  |
| resilience | Claims about fail-closed behavior under faults   |

### Claim-Invariant Mappings

| Claim ID  | Claim Text                                       | Backing Invariant(s)                          |
|-----------|--------------------------------------------------|-----------------------------------------------|
| CLM-DR-01 | Deterministic replay of trust-native executions  | INV-EP-MONOTONIC, INV-EP-DRAIN-BARRIER        |
| CLM-TR-01 | Trust-native execution with epoch-scoped keys    | INV-EP-FAIL-CLOSED, INV-EP-SPLIT-BRAIN-GUARD  |
| CLM-CR-01 | Compromise reduction via evidence-by-default     | INV-EP-IMMUTABLE-CREATION-EPOCH, INV-EP-AUDIT-HISTORY |
| CLM-IC-01 | Immutable creation epoch for artifact provenance | INV-EP-IMMUTABLE-CREATION-EPOCH               |
| CLM-FC-01 | Fail-closed on epoch unavailability              | INV-EP-FAIL-CLOSED                            |

### Rules

1. No claim without backing invariant
2. Claims must cite evidence artifact path with `"verdict": "PASS"`
3. Evidence staleness window: 90 days
4. Retired claims emit CLM-004 and leave active set
5. Claim text changes reset status to pending

## Event Codes

| Code    | Description                                          |
|---------|------------------------------------------------------|
| CLM-001 | Claim verified -- backing invariant and passing evidence found |
| CLM-002 | Claim unbacked -- no invariant reference             |
| CLM-003 | Evidence stale -- artifact exceeds staleness window  |
| CLM-004 | Claim retired -- removed from active set             |

## Invariants

| ID                            | Statement                                            |
|-------------------------------|------------------------------------------------------|
| INV-CLP-NO-UNBACKED          | Every active claim has at least one backing invariant |
| INV-CLP-EVIDENCE-REQUIRED    | Every claim maps to an evidence artifact path         |
| INV-CLP-STALENESS-ENFORCED   | Stale evidence triggers CLM-003 event                |
| INV-CLP-RETIREMENT-CLEAN     | Retired claims do not appear in active documentation |

## Acceptance Criteria

1. Policy document exists at `docs/policy/claim_language_policy.md`
2. Policy contains claim-invariant mapping table with >= 5 mappings
3. Policy defines all 4 event codes (CLM-001 through CLM-004)
4. Policy states "No Claim Without Backing Invariant" rule
5. Policy states "Claims Must Cite Evidence Artifact Path" rule
6. Policy references asupersync-backed invariants (INV-EP-*)
7. Check script passes all checks
8. Python test suite >= 10 tests, all passing
9. Verification evidence verdict is PASS

## Dependencies

- **Upstream:** bd-2gr (epoch integration, 10.11), bd-1id0 (tri-kernel ownership, 10.15)
- **Downstream:** Section 10.15 gate

## Artifacts

| Artifact | Path |
|----------|------|
| Policy document | `docs/policy/claim_language_policy.md` |
| Spec contract | `docs/specs/section_10_15/bd-33kj_contract.md` |
| Check script | `scripts/check_claim_language_policy.py` |
| Test suite | `tests/test_check_claim_language_policy.py` |
| Evidence | `artifacts/section_10_15/bd-33kj/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-33kj/verification_summary.md` |
