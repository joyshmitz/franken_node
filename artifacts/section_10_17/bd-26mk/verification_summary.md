# bd-26mk Verification Summary

## Bead
- **ID**: bd-26mk
- **Section**: 10.17 -- Radical Expansion Execution Track
- **Title**: Security Staking and Slashing Framework for Publisher Trust Governance

## Objective

Implement a deterministic staking and slashing framework that governs publisher
trust. High-risk capabilities enforce stake policy gates; validated malicious
behaviour triggers a deterministic slashing workflow with appeal/audit trail
artifacts.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-26mk_contract.md` |
| Rust module | `crates/franken-node/src/security/staking_governance.rs` |
| Check script | `scripts/check_staking_slashing.py` |
| Test suite | `tests/test_check_staking_slashing.py` |
| Evidence | `artifacts/section_10_17/bd-26mk/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-26mk/verification_summary.md` |

## Implementation

The `staking_governance` module provides:

- **12 core types**: StakeId, StakeRecord, StakeState, StakePolicy, SlashEvent,
  AppealRecord, AppealOutcome, RiskTier, TrustGovernanceState, SlashEvidence,
  StakingAuditEntry, CapabilityStakeGate
- **7 event codes** (STAKE-001 through STAKE-007)
- **7 error codes** (ERR_STAKE_INSUFFICIENT through ERR_STAKE_DUPLICATE_APPEAL)
- **6 invariants** (INV-STAKE-MINIMUM through INV-STAKE-WITHDRAWAL-SAFE)
- **13 public methods** on TrustGovernanceState
- **28 inline #[test] unit tests** covering all operations and invariants
- **BTreeMap** for deterministic ordering throughout
- **Schema version**: staking-v1.0

## Stake Lifecycle

```
deposit_stake() -> ACTIVE
  -> slash()       -> SLASHED -> appeal() -> UNDER_APPEAL
  -> withdraw()    -> WITHDRAWN            -> resolve(upheld) -> SLASHED
  -> (expired)     -> EXPIRED              -> resolve(reversed) -> ACTIVE
```

## Risk Tier Policy

| Tier | Min Stake | Slash % | Cooldown | Appeal Window |
|------|-----------|---------|----------|---------------|
| Critical | 1000 | 100% | 72h | 48h |
| High | 500 | 50% | 48h | 36h |
| Medium | 100 | 25% | 24h | 24h |
| Low | 10 | 10% | 12h | 12h |

## Invariant Coverage

- **INV-STAKE-MINIMUM**: Enforced in `deposit_stake()` -- rejects below-minimum deposits
- **INV-STAKE-SLASH-DETERMINISTIC**: Same evidence + policy = same slash amount
- **INV-STAKE-APPEAL-WINDOW**: Appeals rejected after configured deadline
- **INV-STAKE-AUDIT-COMPLETE**: Every state transition emits a StakingAuditEntry
- **INV-STAKE-NO-DOUBLE-SLASH**: Evidence hash tracking prevents duplicate slashing
- **INV-STAKE-WITHDRAWAL-SAFE**: Withdrawal blocked when pending obligations exist

## Verdict

**PASS** -- All acceptance criteria satisfied.
