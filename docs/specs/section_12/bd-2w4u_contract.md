# bd-2w4u Contract: Hardening Performance Regression Risk Control

## Goal

Prevent hardening-induced performance regressions by enforcing machine-verifiable profile gates, p99/throughput thresholds, runtime profile switching safety, and CI regression blocking.

## Quantified Invariants

- `INV-HPR-PROFILES`: At least three hardening profiles exist: `strict`, `balanced`, `permissive`, each with documented performance tradeoffs.
- `INV-HPR-P99-GATE`: Under the `balanced` profile, p99 latency overhead remains `<= 15%` versus unhardened baseline.
- `INV-HPR-THROUGHPUT-GATE`: Under the `balanced` profile, throughput remains `>= 85%` of unhardened baseline.
- `INV-HPR-RUNTIME-SWITCH`: Profile switching is runtime-configurable with `requires_restart = false` and zero request failures.
- `INV-HPR-CI-REGRESSION`: Continuous benchmark runs block merges when key-metric regression exceeds `5%`.

## Determinism Requirements

- Re-running verification on identical benchmark report input yields identical aggregate metrics and verdict.
- Order of profile entries does not change aggregate gate outcomes.
- Adversarial perturbation that increases balanced p99 beyond threshold deterministically flips gate result to fail.

## Required Scenarios

1. Scenario A: `strict` profile benchmark documents overhead versus baseline (informational, not merge-gating).
2. Scenario B: `balanced` profile satisfies both p99 (`<= 15%`) and throughput (`>= 85%`) gates.
3. Scenario C: Introduced `20%` latency regression causes CI merge block.
4. Scenario D: Runtime profile switch under load succeeds with no request failures and no restart.

## Structured Event Codes

- `HPR-001`: Hardening benchmark cohort evaluation started.
- `HPR-002`: Profile metrics captured.
- `HPR-003`: Balanced profile gate evaluation completed.
- `HPR-004`: Regression-blocking decision emitted.
- `HPR-005`: Runtime profile switch validation completed.

All events must include stable `trace_id` and benchmark context.

## Machine-Readable Artifacts

- `artifacts/12/hardening_perf_regression_report.json`
- `artifacts/section_12/bd-2w4u/verification_evidence.json`
- `artifacts/section_12/bd-2w4u/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): profile-governed tuning verified by existence and documented tradeoffs for strict/balanced/permissive.
- Countermeasure (b): p99 gate verified by recomputed balanced overhead `<= 15%`.
- Countermeasure (c): continuous benchmarking verified by CI runs where regressions `> 5%` are blocked.
- Throughput guardrail verified by recomputed balanced retention `>= 85%`.
- Runtime switching verified by no-restart/no-failure under-load switch event.
