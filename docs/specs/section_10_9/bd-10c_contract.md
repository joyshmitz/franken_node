# bd-10c: Trust Economics Dashboard with Attacker-ROI Deltas

**Section:** 10.9 — Moonshot Disruption Track
**Status:** Implemented
**Module:** `crates/franken-node/src/tools/trust_economics_dashboard.rs`

## Purpose

Quantifies franken_node's security value in economic terms: attacker cost amplification, privilege-risk pricing, and trust policy tuning recommendations with decision-theoretic expected-loss calculations and Bayesian posterior updates.

## Attack Categories (5)

| Category | ID | Description |
|----------|---|-------------|
| Credential Exfiltration | credential_exfiltration | Cost to steal credentials/tokens |
| Privilege Escalation | privilege_escalation | Cost to gain higher privileges |
| Supply-Chain Compromise | supply_chain_compromise | Cost to inject malicious dependencies |
| Policy Evasion | policy_evasion | Cost to bypass security policies |
| Data Exfiltration | data_exfiltration | Cost to extract sensitive data |

## Platforms Compared (3)

| Platform | ID | Description |
|----------|---|-------------|
| Node.js | node_js | Baseline (no hardening) |
| Bun | bun | Default security |
| franken_node | franken_node | Full trust verification |

## Privilege Levels (4)

| Level | ID | Risk Profile |
|-------|----|-------------|
| Unrestricted | unrestricted | Full access, highest risk |
| Standard | standard | Default permissions, moderate risk |
| Restricted | restricted | Limited permissions, lower risk |
| Quarantined | quarantined | Minimal permissions, lowest risk |

## Optimization Objectives (4)

| Objective | Strategy |
|-----------|----------|
| MinimizeExpectedLoss | Maximize defense coverage |
| MaximizeAttackerCost | Maximum hardening |
| MinimizeOperationalOverhead | Reduce operational burden |
| BalancedOptimization | Balance all three |

## Gate Behavior

- Each attack category computes amplification factors (franken_node cost / baseline cost)
- Target: >= 10x compromise reduction per Section 3 category targets
- Policy recommendations include expected impact and confidence intervals
- Model version embedded in every report for reproducibility
- SHA-256 content hash ensures report integrity

## Economic Model

- Expected-loss calculations: `frequency * (1 - effectiveness) * cost * 365`
- Bayesian posterior updates from adversarial campaign data
- Attack cost aggregation: `time*50 + compute*10 + tooling*200 + detection*500`
- Model version: `ted-v1.0`

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-TED-QUANTIFIED | All metrics are numeric with documented units |
| INV-TED-DETERMINISTIC | Same inputs produce same dashboard output |
| INV-TED-VERSIONED | Economic model version in every report |
| INV-TED-CONFIDENCE | Confidence intervals on all estimates |
| INV-TED-GATED | Recommendations blocked when data staleness exceeds threshold |
| INV-TED-COMPARATIVE | Three-way comparison always present |

## Event Codes

| Code | Meaning |
|------|---------|
| TED-001 | Model loaded |
| TED-002 | Amplification computed |
| TED-003 | Pricing computed |
| TED-004 | Recommendation generated |
| TED-005 | Posterior updated |
| TED-006 | Report generated |
| TED-007 | Regression detected |
| TED-008 | Data stale |
| TED-009 | Confidence computed |
| TED-010 | Model version changed |
| TED-ERR-001 | Computation error |
| TED-ERR-002 | Invalid configuration |

## Test Coverage

- 25 Rust inline tests covering amplification, pricing, recommendations, model updates, and audit logging
- Python verification gate checks
- Python unit tests
