# Signal Poisoning and Sybil Defense Policy

## Purpose
This policy establishes the risk controls and operational requirements for
defending the franken_node trust graph against signal poisoning and Sybil
attacks.

## Scope
All trust signal aggregation, reputation scoring, and identity verification
within the franken_node ecosystem.

## Risk Classification
**Priority:** P1 (Critical)
**Likelihood:** High -- trust graphs are known targets for Sybil and poisoning
attacks in decentralised systems.
**Impact:** Critical -- corrupted trust decisions can promote malicious
extensions and suppress legitimate ones.

## Control Requirements

### 1. Robust Aggregation
- Trust signal aggregation MUST use trimmed-mean or median rather than simple
  arithmetic mean.
- The trim percentage for trimmed-mean MUST be at least 20% (10% from each
  tail).
- Injecting up to 20% poisoned signals MUST NOT shift the aggregate by more
  than 5% from the true value.

### 2. Stake-Weighted Signals
- Each trust signal MUST be weighted by the contributor's verified stake
  (reputation score and history length).
- A newly-created node (0 verified history) MUST receive <= 1% of the weight
  assigned to an established node (100+ verified history entries).
- Stake weight MUST be monotonically non-decreasing with verified history
  length.

### 3. Sybil Detection and Attenuation
- The system MUST detect clusters of identities exhibiting coordinated
  behaviour (timing, signal value, target overlap).
- 100 Sybil identities MUST have less aggregate influence than 5 established
  honest nodes.
- Detected Sybil clusters MUST be flagged with event code SPS-003 and their
  signals attenuated.

### 4. Adversarial CI Gate
- The CI pipeline MUST include an adversarial test suite with >= 10 distinct
  attack scenarios.
- Attack scenarios MUST cover: signal poisoning, Sybil endorsement, coordinated
  campaigns, stake manipulation, and convergence recovery.
- All adversarial scenarios MUST pass before any trust-system change is merged.

## Escalation
- Any detected Sybil cluster MUST trigger an alert to the security operations
  team within 60 seconds.
- A poisoned signal that shifts aggregate by > 3% MUST trigger a warning; > 5%
  MUST trigger an automatic rollback of the aggregation round.

## Evidence Requirements
- All trust aggregation rounds MUST be logged with event codes SPS-001 through
  SPS-004.
- Adversarial test results MUST be persisted as CI artifacts.
- Sybil detection decisions MUST include explainable rationale in the audit
  trail.

## Review Cadence
This policy MUST be reviewed quarterly or after any trust-system security
incident, whichever comes first.
