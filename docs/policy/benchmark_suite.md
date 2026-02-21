# Benchmark Suite Policy

## Scope

Governs the product-level benchmark suite for franken_node (bd-k4s, Section 10.6).

## Principles

1. **Benchmarks measure realistic conditions.** All benchmarks run with security
   enforcement active (sandbox enabled, trust verification on). Benchmarks under
   artificial bypass conditions are labeled "unsandboxed baseline" and never used
   for public claims.

2. **Determinism over speed.** Benchmark harness uses fixed seeds, pinned runtime
   versions, and controlled warmup cycles. Results must show < 5% coefficient of
   variation across repeated runs on identical hardware.

3. **Scores are formula-versioned.** Every published score references the scoring
   formula version used to compute it. Score changes due to formula updates are
   clearly attributed in the report changelog.

4. **Provenance is mandatory.** Every result bundle includes: harness version,
   runtime versions, hardware profile, raw measurements, computed scores, and a
   SHA-256 provenance hash for integrity verification.

5. **Regression gates block releases.** If any benchmark dimension regresses
   beyond the configured threshold, the CI gate fails and the release is blocked
   until the regression is addressed or the threshold is explicitly overridden
   with rationale.

## Benchmark Dimensions

| Dimension | Ideal | Threshold | Unit |
|-----------|-------|-----------|------|
| cold_start_latency | 100ms | 500ms | ms |
| p99_request_latency | 1ms | 10ms | ms |
| extension_overhead_ratio | 1.0x | 1.5x | ratio |
| migration_scanner_throughput | 1000 fixtures/s | 200 fixtures/s | fixtures/s |
| lockstep_harness_throughput | 500 fixtures/s | 100 fixtures/s | fixtures/s |
| quarantine_propagation_latency | 100ms | 2000ms | ms |
| trust_card_materialization | 10ms | 200ms | ms |

## Scoring Formula

```
score = clamp(100 * (1 - (measured - ideal) / (threshold - ideal)), 0, 100)
```

Version: `sf-v1`

## CI Integration

- Smoke suite runs on every release candidate.
- Full suite runs on main branch merges.
- Regression threshold: 10% degradation from last passing baseline.
- Artifact output: `artifacts/section_10_6/bd-k4s/` directory.
