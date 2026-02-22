# bd-ka0n: Performance Under Hardening Metrics — Spec Contract

**Section:** 14 — Benchmark + Standardization
**Bead:** bd-ka0n
**Status:** CLOSED

## Purpose

Instrument p50/p95/p99 latency, cold-start overhead, and security hardening
overhead metric family for release-gated performance enforcement.

## Acceptance Criteria

1. Five operation categories: Startup, Request, Migration, Verification, Shutdown.
2. Latency percentile tracking (p50, p95, p99) with ordering invariant.
3. Hardening overhead computation as ratio of hardened/baseline p99.
4. Cold-start vs warm-start overhead ratio.
5. Budget-gated enforcement per category.
6. At least 12 event codes and 6 invariants.
7. At least 24 Rust unit tests.

## Invariants

| ID | Description |
|---|---|
| INV-PHM-PERCENTILE | p50/p95/p99 always correctly ordered |
| INV-PHM-DETERMINISTIC | Same inputs produce same report output |
| INV-PHM-OVERHEAD | Hardening overhead is ratio of hardened/baseline |
| INV-PHM-GATED | Operations exceeding latency budget flagged |
| INV-PHM-VERSIONED | Metric version embedded in every report |
| INV-PHM-AUDITABLE | Every submission produces audit record |

## Implementation

| Artifact | Path |
|---|---|
| Rust module | `crates/franken-node/src/tools/performance_hardening_metrics.rs` |
| Verification script | `scripts/check_performance_hardening_metrics.py` |
| Unit tests | `tests/test_check_performance_hardening_metrics.py` |
