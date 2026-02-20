# Canonical Capability Ownership Registry

## Purpose

This registry defines which execution track canonically owns each capability/protocol family. All other tracks that reference the same capability are constrained to integration, adoption, policy, or release gating roles. Duplicate implementation of the same protocol semantics in parallel tracks is explicitly off-charter.

## Governance Rules

1. Each capability has exactly one canonical implementation owner.
2. Non-owner tracks may integrate, adopt, gate, or policy-wrap the capability but must not re-implement its core semantics.
3. The duplicate-implementation CI gate (`bd-2yhs`) enforces this registry at build time.
4. Changes to ownership require explicit governance review.

## Registry

| ID | Capability Domain | Canonical Owner | Integration/Adoption Tracks | Notes |
|----|-------------------|-----------------|----------------------------|-------|
| CAP-001 | Remote registry, idempotency, saga semantics | 10.14 | 10.15 (policy-gated integration) | FrankenSQLite deep-mined track owns protocol semantics |
| CAP-002 | Epoch validity + transition barriers | 10.14 | 10.15 (control workflow integration) | Epoch lifecycle owned by evidence/correctness track |
| CAP-003 | Evidence ledger + replay validator | 10.14 | 10.15 (mandatory adoption, release gating) | Core evidence infrastructure |
| CAP-004 | Fault harness, cancellation injection, DPOR exploration | 10.14 | 10.15 (control-plane enforcement gate) | Canonical harness for deterministic testing |
| CAP-005 | Verifier SDK, replay capsules, claim compiler, trust scoreboard | 10.17 | 10.9 (ecosystem distribution), 10.12 (adoption) | Radical expansion track owns verification tooling |
| CAP-006a | Semantic oracle L1 (product layer) | 10.2 | — | Compatibility core owns product-level oracle |
| CAP-006b | Semantic oracle L2 (engine boundary) | 10.17 | — | Radical expansion owns engine-boundary oracle |
| CAP-007 | Authenticated control channel + anti-replay framing | 10.13 | 10.10 (adoption), 10.15 (policy rollout) | FCP deep-mined track owns protocol |
| CAP-008 | Revocation freshness semantics | 10.13 | 10.4 (ecosystem adoption), 10.10 (policy adoption) | Core revocation enforcement |
| CAP-009 | Stable error taxonomy + recovery contract | 10.13 | 10.8 (operations adoption), 10.10 (product-surface adoption) | Canonical error definitions |
| CAP-010 | Trust protocol vectors, golden fixtures | 10.13 + 10.14 | 10.7 (release gates), 10.10 (publication gates) | Dual-track canonical generation |
| CAP-011 | Verifiable execution fabric (policy-constraint compiler, receipt commitments, proof generation/verification) | 10.18 | 10.17 (verifier/claim surfaces), 10.15 (control-plane gates) | VEF frontier program |
| CAP-012 | Adversarial trust commons federation (privacy-preserving signal sharing, global priors, incentive weighting) | 10.19 | 10.17 (adversary graph/reputation), 10.15 + 10.4 (trust controls) | ATC frontier program |
| CAP-013 | Dependency graph immune system (topological risk model, contagion simulator, preemptive barrier planner) | 10.20 | 10.17 (adversary/economic scoring), 10.15 (containment), 10.19 (federated enrichment) | DGIS frontier program |
| CAP-014 | Behavioral phenotype evolution tracker (longitudinal genome modeling, drift/regime-shift detection, hazard scoring) | 10.21 | 10.17 (adversary/trust scoring), 10.20 (topological prioritization), 10.19 (federated temporal intelligence), 10.2 + 10.15 (migration-control gating) | BPET frontier program |
| CAP-015 | Spec-first Node/Bun compatibility extraction, fixture-oracle baselining | 10.2 | 10.3 (migration automation), 10.7 (release verification) | Compatibility core owns extraction |

## Oracle Delivery Close Condition

The dual-layer oracle is only complete when all three components are green:
- **L1 product oracle** (owned by 10.2)
- **L2 engine-boundary oracle** (owned by 10.17)
- **Release policy linkage** (owned by 10.2)

## Track Role Summary

| Track | Primary Role |
|-------|-------------|
| 10.0 | Strategic initiative tracking (rollup) |
| 10.1 | Charter + split governance |
| 10.2 | Compatibility core, spec-first extraction, L1 oracle |
| 10.3 | Migration system |
| 10.4 | Extension ecosystem + registry |
| 10.5 | Security + policy product surfaces |
| 10.6 | Performance + packaging |
| 10.7 | Conformance + verification |
| 10.8 | Operational readiness |
| 10.9 | Moonshot disruption |
| 10.10 | FCP-inspired hardening + interop integration |
| 10.11 | FrankenSQLite-inspired runtime systems integration |
| 10.12 | Frontier programs execution |
| 10.13 | FCP deep-mined: control channels, revocation, error taxonomy, trust vectors |
| 10.14 | FrankenSQLite deep-mined: evidence ledgers, epochs, remote effects, fault harness |
| 10.15 | Asupersync-first integration: control-plane adoption |
| 10.16 | Adjacent substrate integration |
| 10.17 | Radical expansion: verifier SDK, L2 oracle, adversary scoring |
| 10.18 | VEF: verifiable execution fabric |
| 10.19 | ATC: adversarial trust commons |
| 10.20 | DGIS: dependency graph immune system |
| 10.21 | BPET: behavioral phenotype evolution tracker |
