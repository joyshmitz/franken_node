# bd-38m: Optimize Lockstep Harness Throughput and Memory Profile

## Bead: bd-38m | Section: 10.6

## Purpose

Optimize the lockstep harness to support streaming fixture ingestion,
bounded memory usage, warm runtime pool reuse, and deterministic streaming
normalization. The goal is to sustain high-volume fixture workloads (5000+
fixtures) within a 512MB peak memory ceiling while achieving at least a 20%
throughput improvement over the baseline bulk-loading approach.

## Optimization Phases

| Phase | Description |
|-------|-------------|
| Startup | Warm runtime pool initialization, pre-allocated buffers |
| Fixture Loading | Streaming fixture ingestion with back-pressure control |
| Result Comparison | Streaming normalization producing byte-identical output to bulk |
| Memory Management | Memory ceiling enforcement with spill-to-disk overflow |

## Event Codes

| Code | Trigger |
|------|---------|
| OLH-001 | Streaming fixture ingestion begins for a batch. |
| OLH-002 | Throughput measurement checkpoint recorded. |
| OLH-003 | Memory ceiling exceeded; spill-to-disk activated. |
| OLH-004 | Warm runtime pool reuse event (pool hit or miss). |

## Invariants

| ID | Statement |
|----|-----------|
| INV-OLH-STREAMING | Streaming fixture ingestion must not exceed 512MB peak resident memory for 5000 fixtures. |
| INV-OLH-THROUGHPUT | Streaming mode must achieve at least 20% throughput improvement over baseline bulk loading. |
| INV-OLH-NORMALIZATION | Streaming normalization output must be byte-identical to bulk normalization output for the same input. |
| INV-OLH-SPILLTODISK | When the in-memory buffer exceeds the configured memory ceiling, the harness must spill intermediate results to disk without data loss. |

## Quantitative Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Peak memory (5000 fixtures) | < 512MB | RSS measurement via `/proc/self/statm` or platform equivalent |
| Throughput improvement | >= 20% | Wall-clock fixtures/sec streaming vs. bulk baseline |
| Normalization fidelity | byte-identical | SHA-256 digest comparison of streaming vs. bulk output |
| Spill-to-disk recovery | 0 data loss | All spilled records recovered and included in final output |

## Streaming Normalization Rules

Streaming normalization applies the following canonicalization transformations
to fixture output before comparison:

1. **Timestamp stripping** -- Remove or replace variable timestamps with a
   canonical placeholder (`<TIMESTAMP>`).
2. **PID masking** -- Replace process identifiers with a stable sentinel
   (`<PID>`).
3. **Path canonicalization** -- Normalize filesystem paths to use forward
   slashes and strip platform-specific prefixes.

These rules ensure that streaming normalization is deterministic and produces
byte-identical output to the equivalent bulk normalization pass.

## Memory Ceiling and Spill-to-Disk

The harness enforces a configurable memory ceiling (default 512MB). When the
in-memory working set approaches this ceiling:

1. Intermediate results are serialized to a temporary spill directory.
2. The spill directory is cleaned up after the run completes.
3. Spilled records are transparently re-read during the comparison phase.
4. The ceiling is configurable via `memory_ceiling_mb` in the harness config.

## Warm Runtime Pool

The harness maintains a warm pool of pre-initialized runtime instances to
avoid cold-start overhead on repeated fixture runs:

- Pool size is configurable (default: 4 instances).
- Pool hits emit OLH-004 with `pool_hit: true`.
- Pool misses trigger lazy initialization and emit OLH-004 with `pool_hit: false`.
- Pool instances are recycled between batches without full teardown.

## Benchmark Methodology

Throughput benchmarks compare streaming mode against bulk-loading baseline:

1. Load the same fixture corpus in both modes.
2. Measure wall-clock time and peak RSS for each mode.
3. Compute fixtures/sec and memory delta.
4. Assert streaming mode meets the 20% throughput improvement target.
5. Assert peak memory stays below the 512MB ceiling.

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_6/bd-38m_contract.md` |
| Optimization policy | `docs/policy/lockstep_harness_optimization.md` |
| Verification script | `scripts/check_harness_throughput.py` |
| Python verification tests | `tests/test_check_harness_throughput.py` |
| Verification evidence | `artifacts/section_10_6/bd-38m/verification_evidence.json` |
| Verification summary | `artifacts/section_10_6/bd-38m/verification_summary.md` |
