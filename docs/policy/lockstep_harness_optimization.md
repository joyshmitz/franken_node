# Policy: Lockstep Harness Optimization

**Bead:** bd-38m
**Section:** 10.6 -- Lockstep Harness Throughput and Memory
**Effective:** 2026-02-20

## 1. Overview

This policy governs the optimization of the lockstep harness to support
streaming fixture ingestion, bounded memory usage, and warm runtime pool
reuse. The harness is the central execution engine for compatibility
verification and must sustain high-volume workloads without unbounded
resource consumption.

## 2. Optimization Phases

### 2.1 Startup Phase

During startup the harness initializes a warm runtime pool of pre-allocated
runtime instances. This eliminates cold-start overhead on the first fixture
batch. The pool size is configurable (default: 4 instances) and each instance
is initialized with the minimum required state for fixture execution.

Startup emits event code OLH-004 for each pool slot initialized.

### 2.2 Fixture Loading Phase

Fixtures are ingested via a streaming pipeline rather than bulk-loading the
entire corpus into memory. The streaming loader reads fixtures one at a time,
applies back-pressure when the in-memory buffer approaches the configured
memory ceiling, and spills intermediate results to disk when necessary.

Key properties:
- Streaming fixture ingestion begins with event OLH-001.
- Peak resident memory must not exceed 512MB for a corpus of 5000 fixtures
  (INV-OLH-STREAMING).
- Back-pressure is applied when the buffer reaches 80% of the memory ceiling.

### 2.3 Result Comparison Phase

After fixture execution, results are compared using streaming normalization.
The normalization pipeline applies three canonicalization rules in order:

1. **Timestamp stripping** -- Variable timestamps (ISO 8601, Unix epoch, and
   common log formats) are replaced with the placeholder `<TIMESTAMP>`.
2. **PID masking** -- Process identifiers matching `/\bpid[=: ]\d+/i` or
   bare numeric PIDs in known positions are replaced with `<PID>`.
3. **Path canonicalization** -- Backslashes are converted to forward slashes,
   drive letters are stripped, and platform-specific temp-directory prefixes
   are replaced with `<TMPDIR>`.

These rules guarantee that streaming normalization produces byte-identical
output to the equivalent bulk normalization pass (INV-OLH-NORMALIZATION).
Fidelity is verified by comparing SHA-256 digests of both outputs.

### 2.4 Memory Management Phase

The harness enforces a configurable memory ceiling (default 512MB). The
memory management strategy operates as follows:

- Continuously monitor working-set size via platform RSS queries.
- When RSS approaches 80% of the ceiling, activate back-pressure.
- When RSS exceeds the ceiling, spill the oldest intermediate results to a
  temporary directory on disk (event OLH-003).
- Spilled data is transparently re-read during the comparison phase.
- On run completion, the spill directory is cleaned up.
- No data loss is permitted during spill-to-disk (INV-OLH-SPILLTODISK).

The memory ceiling is configurable via the `memory_ceiling_mb` parameter in
the harness configuration.

## 3. Streaming Normalization Rules

| Rule | Pattern | Replacement |
|------|---------|-------------|
| Timestamp stripping | ISO 8601, Unix epoch, common log timestamps | `<TIMESTAMP>` |
| PID masking | Process identifiers in known formats | `<PID>` |
| Path canonicalization | Platform-specific path prefixes and separators | Normalized forward-slash paths |

All three rules are applied in sequence. The output of streaming
normalization must be byte-identical to the output of bulk normalization
on the same input corpus. This invariant is verified via SHA-256 digest
comparison.

## 4. Warm Runtime Pool Reuse

### 4.1 Pool Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `pool_size` | 4 | Number of pre-initialized runtime instances |
| `recycle_after` | 100 | Number of fixtures before recycling an instance |
| `max_idle_sec` | 300 | Maximum idle time before an instance is torn down |

### 4.2 Pool Hit/Miss Events

Every pool access emits event OLH-004 with a `pool_hit` boolean field:
- `pool_hit: true` -- An existing warm instance was reused.
- `pool_hit: false` -- A new instance was lazily initialized.

Pool hit rate is tracked as a rolling average and included in benchmark
reports.

## 5. Benchmark Methodology

### 5.1 Measurement Protocol

1. Select a reproducible fixture corpus (minimum 1000 fixtures for
   meaningful measurement, target 5000 for ceiling verification).
2. Run the corpus in **bulk mode** (baseline): load all fixtures, execute,
   compare. Record wall-clock time and peak RSS.
3. Run the same corpus in **streaming mode**: stream fixtures, execute with
   warm pool, compare with streaming normalization. Record wall-clock time
   and peak RSS.
4. Compute throughput as fixtures/sec for each mode.
5. Compute improvement percentage: `(streaming - bulk) / bulk * 100`.

### 5.2 Pass Criteria

| Metric | Criterion |
|--------|-----------|
| Throughput improvement | >= 20% (INV-OLH-THROUGHPUT) |
| Peak memory (streaming, 5000 fixtures) | < 512MB (INV-OLH-STREAMING) |
| Normalization fidelity | Byte-identical SHA-256 digests (INV-OLH-NORMALIZATION) |
| Spill-to-disk data integrity | 0 records lost (INV-OLH-SPILLTODISK) |

### 5.3 Throughput Checkpoint Events

During benchmark runs, event OLH-002 is emitted at configurable intervals
(default: every 500 fixtures) with the current throughput measurement. This
allows trend analysis within a single run.

## 6. Event Lifecycle

| Event | When Emitted |
|-------|--------------|
| OLH-001 | Streaming fixture ingestion begins for a batch. |
| OLH-002 | Throughput measurement checkpoint recorded. |
| OLH-003 | Memory ceiling exceeded; spill-to-disk activated. |
| OLH-004 | Warm runtime pool access (hit or miss). |

## 7. Revision History

| Date | Change |
|------|--------|
| 2026-02-20 | Initial policy created for bd-38m. |
