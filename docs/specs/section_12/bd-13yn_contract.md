# bd-13yn: Risk Control -- Signal Poisoning and Sybil Defense

## Section
12 -- Risk Control

## Bead ID
bd-13yn

## Risk
**Signal Poisoning and Sybil Attacks** -- Malicious nodes inject false
reputation/trust signals or create multiple fake identities to manipulate the
trust graph.

## Impact
- Corrupted trust decisions causing malicious extensions to gain undeserved
  trust.
- Legitimate extensions being suppressed by adversarial signal injection.
- Erosion of the trust graph's integrity when Sybil identities amplify false
  signals.

## Countermeasures

### 1. Robust Aggregation (INV-SPS-AGGREGATION)
Trust signal aggregation uses **trimmed-mean** or **median** (not simple
average) to resist outlier injection. Injecting 20% poisoned signals must shift
the aggregate by <= 5% from the true value.

### 2. Stake Weighting (INV-SPS-STAKE)
Trust signals are weighted by the contributor's own stake/reputation, making
Sybil attacks expensive. A newly-created node's signal has <= 1% weight
compared to an established node's signal.

### 3. Sybil Resistance (INV-SPS-SYBIL)
Creating 100 fake identities has less influence than 5 established honest
nodes. The system detects and attenuates coordinated Sybil behaviour.

### 4. Adversarial Test Suite (INV-SPS-ADVERSARIAL)
CI includes adversarial test suites with >= 10 attack scenarios that simulate
poisoning and Sybil scenarios. The trust system must maintain correct rankings
throughout all scenarios.

## Thresholds

| Metric                              | Threshold |
|--------------------------------------|-----------|
| Poisoned signal shift (20% attack)   | <= 5%     |
| New node signal weight vs established | <= 1%     |
| 100 Sybil vs 5 honest influence      | < 1.0x    |
| Adversarial test scenarios            | >= 10     |

## Event Codes

| Code    | Name                  | Description                                              |
|---------|-----------------------|----------------------------------------------------------|
| SPS-001 | Robust Aggregation    | Trust aggregation computed using trimmed-mean or median.  |
| SPS-002 | Stake Weighted        | Trust signal weighted by contributor stake/reputation.    |
| SPS-003 | Sybil Detected        | Coordinated Sybil behaviour detected and attenuated.     |
| SPS-004 | Adversarial Gate Pass | Adversarial test suite scenario passed.                  |

## Error Codes

| Code                        | Description                                          |
|-----------------------------|------------------------------------------------------|
| ERR_SPS_POISONED_SIGNAL     | A signal was identified as poisoned/adversarial.     |
| ERR_SPS_SYBIL_DETECTED      | Sybil identity cluster detected.                     |
| ERR_SPS_INSUFFICIENT_STAKE  | Signal contributor has insufficient stake/reputation. |
| ERR_SPS_AGGREGATION_FAILED  | Trust aggregation failed due to insufficient data.   |

## Invariants

| ID                     | Statement                                                                    |
|------------------------|------------------------------------------------------------------------------|
| INV-SPS-AGGREGATION    | Robust aggregation resists 20% poisoned signals within 5% shift.             |
| INV-SPS-STAKE          | Stake weighting ensures new nodes have <= 1% weight vs established nodes.    |
| INV-SPS-SYBIL          | 100 Sybil identities have less influence than 5 established honest nodes.    |
| INV-SPS-ADVERSARIAL    | Adversarial test suite with >= 10 scenarios passes in CI.                    |

## Acceptance Criteria
1. Robust aggregation: injecting 20% poisoned signals shifts the aggregate by
   <= 5% from the true value.
2. Stake weighting: a newly-created node's signal has <= 1% weight vs an
   established node's signal.
3. Sybil resistance: creating 100 fake identities has less influence than 5
   established honest nodes.
4. Adversarial test suite with >= 10 attack scenarios passes in CI.

## Test Scenarios

### Scenario A -- Poisoned Signal Injection
Inject 20% maximally-adversarial signals; verify trust ranking of honest nodes
changes by <= 1 position.

### Scenario B -- Sybil Endorsement
Create 100 Sybil identities all endorsing a malicious extension; verify it does
not enter the top-50% trust tier.

### Scenario C -- Coordinated Signal Poisoning Campaign
Simulate a coordinated signal poisoning campaign over 10 rounds; verify trust
system converges back to correct rankings within 3 rounds after attack stops.

### Scenario D -- Stake Monotonicity
Verify that stake-weighting function is monotonically increasing with verified
history length.
