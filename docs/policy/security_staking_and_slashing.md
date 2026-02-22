# Security Staking and Slashing Framework

**Bead**: bd-26mk
**Section**: 10.17
**Status**: Active

## Purpose

This policy defines the security staking and slashing framework that governs
publisher trust in the franken_node ecosystem. High-risk capabilities enforce
stake policy gates; validated malicious behavior triggers a deterministic
slashing workflow with appeal/audit trail artifacts.

## Scope

All publishers who register capabilities at risk tier `medium`, `high`, or
`critical` must hold a minimum stake deposit before capability activation is
permitted.

## Stake Requirements

| Risk Tier  | Minimum Stake (bps) | Description                     |
|------------|--------------------:|----------------------------------|
| `low`      |                   0 | No stake required                |
| `medium`   |                 500 | Basic skin-in-the-game           |
| `high`     |               2,000 | Significant stake                |
| `critical` |               5,000 | Maximum assurance stake          |

## Event Codes

| Code                     | Meaning                                      |
|--------------------------|----------------------------------------------|
| STAKE_DEPOSIT_RECEIVED   | Publisher deposited stake into the system     |
| STAKE_GATE_EVALUATED     | Stake gate evaluated for capability access    |
| SLASH_INITIATED          | Slashing process started from evidence        |
| SLASH_EXECUTED           | Stake successfully slashed                    |
| APPEAL_FILED             | Publisher filed an appeal against a slash     |

## Error Codes

| Code                       | Meaning                                    |
|----------------------------|--------------------------------------------|
| ERR_STAKE_INSUFFICIENT     | Stake below required minimum for tier      |
| ERR_STAKE_GATE_DENIED      | No deposit found for publisher             |
| ERR_SLASH_EVIDENCE_INVALID | Evidence hash does not match expected      |
| ERR_SLASH_ALREADY_EXECUTED | Slash already processed for this evidence  |
| ERR_APPEAL_EXPIRED         | Appeal filed after the deadline            |
| ERR_STAKE_WITHDRAWAL_LOCKED | Withdrawal blocked during lock period     |

## Invariants

| ID                       | Rule                                                        |
|--------------------------|-------------------------------------------------------------|
| INV-STAKE-GATE-REQUIRED  | High-risk capability activation requires minimum stake      |
| INV-SLASH-DETERMINISTIC  | Slashing decisions are computed deterministically from evidence |
| INV-SLASH-AUDIT-TRAIL    | Every slash event produces an immutable audit trail entry   |
| INV-APPEAL-WINDOW        | Slashed publishers have a bounded appeal window             |

## Slashing Workflow

1. **Evidence submission**: A validator submits `SlashEvidence` with a
   deterministic `evidence_hash` derived from the evidence identity, publisher,
   and violation type.
2. **Hash verification**: The engine recomputes the expected hash and rejects
   evidence with mismatched hashes (`ERR_SLASH_EVIDENCE_INVALID`).
3. **Deduplication**: If the evidence has already been processed, the slash is
   rejected (`ERR_SLASH_ALREADY_EXECUTED`).
4. **Stake reduction**: The publisher's staked amount is reduced by
   `slash_rate_bps` (default 10 %).
5. **Audit recording**: An immutable `AuditTrailEntry` is emitted with the
   `SLASH_EXECUTED` event code.

## Appeal Process

1. Publishers may file an `Appeal` referencing the slash evidence ID.
2. Appeals must be filed before `appeal_deadline_epoch_ms` (default 7 days
   after slash execution).
3. If accepted, the slashed amount is restored to the publisher's stake.
4. Late appeals are rejected with `ERR_APPEAL_EXPIRED`.

## Configuration

```toml
[staking]
appeal_window_ms = 604800000   # 7 days
slash_rate_bps = 1000          # 10%
minimum_lock_ms = 86400000     # 1 day
```

## Implementation

- `crates/franken-node/src/registry/staking_governance.rs`
- `tests/integration/staking_slashing_flows.rs`
- `scripts/check_staking_governance.py`
