# Policy: Operator Intelligence Recommendation Engine

**Bead:** bd-y0v
**Section:** 10.12 (Frontier Programs — Operator Intelligence)
**Status:** Active

## Overview

The operator intelligence recommendation engine produces expected-loss-scored
recommendations for operators managing high-trust extension ecosystems. Every
recommendation includes a quantified risk estimate, a concrete action plan,
and a cryptographic rollback proof guaranteeing the action can be undone.

## Expected-Loss Scoring

Risk estimates combine four input dimensions:
- **Compatibility pass rate** (weight 30): from Section 10.2 compatibility core.
- **Migration success rate** (weight 25): from Section 10.3 migration system.
- **Trust artifact validity** (weight 20): from Section 10.4/10.13 trust fabric.
- **Error rate** (weight 15): current operational error rate.
- **Active alerts** (weight up to 10): current alert count.

The scoring model is deterministic: identical inputs produce identical scores.

## Rollback Proofs

Every executed recommendation generates a rollback proof containing:
1. Content-addressed pre-action state snapshot.
2. Deterministic action command sequence.
3. Expected post-action state hash.
4. Rollback command sequence that restores pre-action state.

Proofs are independently verifiable without access to the running system.

## Deterministic Replay

Every executed recommendation produces a replay artifact containing:
- Full input context (serialized operator context).
- The recommendation chosen and action executed.
- Observed outcome.
- Embedded rollback proof.

Replay artifacts are machine-parseable and re-executable for deterministic
reproduction of outcomes.

## Audit Trail

Every recommendation generated — whether accepted or rejected — is recorded
in the audit trail with:
- Timestamp
- Recommendation ID and action description
- Expected-loss score
- Context fingerprint (deterministic hash of operator context)
- Acceptance status

## Risk Budget

The cumulative expected-loss of accepted recommendations is tracked against
a configurable risk budget. Acceptance is rejected if it would exceed the
budget, preventing unbounded risk accumulation.

## Degraded Mode

When input data sources are unavailable (historical data, compatibility
scores, trust state):
1. The engine enters degraded mode and emits a warning event.
2. Confidence intervals are widened by the degraded penalty multiplier.
3. Recommendations carry explicit data-quality warnings.
4. The engine never silently degrades accuracy.

## Configuration

| Parameter                    | Default | Description                          |
|------------------------------|---------|--------------------------------------|
| max_recommendations          | 10      | Max recommendations per query        |
| confidence_threshold         | 0.5     | Min confidence to emit recommendation|
| risk_budget                  | 100.0   | Max cumulative expected-loss         |
| degraded_confidence_penalty  | 0.5     | Confidence multiplier in degraded    |
