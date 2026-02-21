# Risk Policy: Signal Poisoning and Sybil Attacks

**Bead:** bd-13yn
**Section:** 12 -- Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Risk Description

The **Signal Poisoning and Sybil** risk arises when adversaries manipulate
the franken_node trust graph through two complementary attack vectors:

- **Signal Poisoning:** Injection of false trust signals to manipulate
  extension ratings, compatibility verdicts, or risk scores. Adversaries
  craft signals designed to shift aggregated trust metrics, promoting
  malicious extensions or suppressing legitimate ones.

- **Sybil Attacks:** Creation of multiple fake identities to accumulate
  unearned trust or overwhelm voting and consensus mechanisms. Sybil
  identities amplify poisoned signals and can dominate trust decisions
  when insufficient diversity controls are in place.

Root causes:
- Trust aggregation using simple arithmetic mean, vulnerable to outlier
  injection.
- No stake or reputation weighting on trust signals, allowing zero-cost
  signal generation.
- Absence of identity clustering detection, permitting coordinated fake
  identity campaigns.
- Insufficient source diversity requirements for trust-affecting decisions.

## 2. Impact

| Dimension | Rating | Detail |
|-----------|--------|--------|
| Security | Critical | Corrupted trust decisions may promote malicious extensions. |
| Integrity | Critical | Trust graph integrity is undermined by adversarial signals. |
| Availability | High | Legitimate extensions suppressed by adversarial campaigns. |
| Remediation | Medium | Robust aggregation and detection enable recovery. |

## 3. Likelihood

| Factor | Assessment |
|--------|------------|
| Trust graph exposure | High -- trust graphs are known Sybil targets. |
| Signal injection cost | Low -- without stake weighting, signals are free. |
| Coordination feasibility | Medium -- botnets can generate coordinated signals. |
| Overall likelihood | **High** |

## 4. Countermeasure Details

### 4.1 Robust Aggregation (INV-SPS-AGGREGATION)

Trust signal aggregation MUST use **trimmed-mean** or **median** rather
than simple arithmetic mean:

- The trim percentage for trimmed-mean MUST be at least 20% (10% from
  each tail).
- Injecting up to 20% poisoned signals MUST NOT shift the aggregate by
  more than 5% from the true value.
- Event code **SPS-001** is emitted on every successful robust aggregation.
- Aggregation method selection is logged in the audit trail.

### 4.2 Stake-Weighted Signals (INV-SPS-STAKE)

Each trust signal MUST be weighted by the contributor's verified stake
(reputation score and history length):

- A newly-created node (0 verified history) MUST receive <= 1% of the
  weight assigned to an established node (100+ verified history entries).
- Stake weight MUST be monotonically non-decreasing with verified history
  length.
- Event code **SPS-002** is emitted on every stake-weighted signal
  evaluation.
- Insufficient-stake signals are logged with **ERR_SPS_INSUFFICIENT_STAKE**.

### 4.3 Sybil Detection and Attenuation (INV-SPS-SYBIL)

The system MUST detect clusters of identities exhibiting coordinated
behaviour:

- Detection criteria: timing correlation, signal value similarity, target
  overlap, and source IP/network clustering.
- 100 Sybil identities MUST have less aggregate influence than 5
  established honest nodes.
- Detected Sybil clusters MUST be flagged with event code **SPS-003** and
  their signals attenuated.
- Sybil detection latency MUST be <= 60 seconds.
- Detection decisions MUST include explainable rationale in the audit trail.

### 4.4 Adversarial Test Suite (INV-SPS-ADVERSARIAL)

The CI pipeline MUST include an adversarial test suite:

- Minimum 10 distinct attack scenarios covering: signal poisoning, Sybil
  endorsement, coordinated campaigns, stake manipulation, and convergence
  recovery.
- All adversarial scenarios MUST pass before any trust-system change is
  merged.
- Event code **SPS-004** is emitted on adversarial test suite passage.
- Test results are persisted as CI artifacts.

## 5. Thresholds

| Metric | Threshold |
|--------|-----------|
| Poisoned signal shift (20% attack) | <= 5% |
| New node signal weight vs established | <= 1% |
| 100 Sybil vs 5 honest influence | < 1.0x |
| Adversarial test scenarios | >= 10 |
| Sybil detection latency | <= 60 seconds |
| Signal provenance verification | 100% coverage |
| Identity binding coverage | 100% of trust-relevant identities |
| Anomaly detection false positive rate | <= 5% |

## 6. Escalation Procedures

When signal poisoning or Sybil attacks are detected:

1. **Immediate** (within 60 seconds):
   - Security operations team notified via dashboard alert.
   - Affected trust aggregation round flagged for review.
   - Event **SPS-003** emitted for Sybil detection.

2. **5-minute escalation**:
   - If poisoned signal shifts aggregate by > 3%, warning alert raised.
   - If shift > 5%, automatic rollback of the aggregation round.

3. **1-hour escalation**:
   - Multiple Sybil cluster detections trigger engineering lead notification.
   - Trust-system security review meeting scheduled within 4 hours.

4. **Post-incident**:
   - Root cause analysis required within 24 hours.
   - Adversarial test suite updated with new attack patterns discovered.

## 7. Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires:
1. **Aggregation resilience log** -- Results of robust aggregation under
   adversarial signal injection tests.
2. **Stake weight distribution** -- Weight distribution across signal
   contributors showing new-vs-established ratio.
3. **Sybil detection log** -- All SPS-003 events with detection rationale
   and attenuation actions.
4. **Adversarial test results** -- Full CI artifact output from adversarial
   test suite.
5. **Invariant status** -- Confirmation that INV-SPS-AGGREGATION,
   INV-SPS-STAKE, INV-SPS-SYBIL, and INV-SPS-ADVERSARIAL are satisfied.
6. **Escalation log** -- Record of any escalations since last review.

Reviews are conducted quarterly or after any trust-system security
incident, whichever comes first.
