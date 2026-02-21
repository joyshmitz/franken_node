# Scanner Throughput Optimization Policy

**Bead:** bd-2q5
**Section:** 10.6 -- Migration Scanner Performance
**Last updated:** 2026-02-20

## 1. Overview

This policy governs the performance optimization strategies applied to the
migration scanner when operating on large monorepos. The scanner must maintain
correctness guarantees (determinism, completeness) while delivering measurable
throughput improvements through incremental scanning, parallel processing, and
cache reuse.

## 2. Optimization Strategies

### 2.1 Incremental Scanning (Hash-Based)

The scanner computes a SHA-256 content hash for every file it encounters. These
hashes are persisted in the scan cache. On subsequent runs, the scanner compares
the current file hash against the cached hash:

- **Match**: The file is skipped (cache hit). No re-analysis is performed.
- **Mismatch or missing**: The file is fully scanned and its new hash is written
  to the cache.

**Correctness guarantee**: A SHA-256 collision is astronomically unlikely
(probability < 2^-128). The hash is computed over the full file content, not a
partial sample.

**Edge cases**:
- Files deleted between runs: stale cache entries are harmless (they are simply
  unused) and will be evicted by TTL.
- Files renamed: treated as a new file (different key in the cache map).
- Empty files: hashed as SHA-256 of the empty byte string.

### 2.2 Parallel File Processing (Deterministic Batching)

Files are partitioned into worker batches using a deterministic algorithm:

1. Collect all file paths to scan.
2. Sort lexicographically (locale-independent, byte-order).
3. Assign to batches via round-robin: file `i` goes to worker `i % N`.

This guarantees that:
- The same file list always produces the same batch assignment.
- No filesystem ordering dependency exists.
- Each worker receives a roughly equal share of the work.

**Worker count**: Controlled by `--workers N` (default: `min(available_cpus, 4)`).
The cap at 4 is a deliberate design choice: beyond 4 workers, I/O contention on
typical SSDs begins to dominate, yielding diminishing returns.

### 2.3 Cache Reuse Across Runs

The scan cache is stored at `.franken_node/scan_cache.json` relative to the
project root. The cache format includes:

- **`version`**: Format version string (currently `"1.0"`). If the scanner
  encounters a cache with an unknown version, it discards the cache and performs
  a full scan.
- **`created_at`**: ISO 8601 timestamp of cache creation.
- **`ttl_seconds`**: Time-to-live in seconds (default: 604800 = 7 days).
- **`entries`**: Map from relative file path to `{hash, scanned_at, size_bytes}`.

**TTL expiration**: Before using cached entries, the scanner evicts any entry
whose `scanned_at` timestamp is older than `now - ttl_seconds`. This prevents
indefinite staleness.

**`--clear-cache` flag**: Forces deletion of the cache file before scanning.
Emits event code `OMS-004` when the cache is purged.

## 3. CLI Flags

| Flag             | Type   | Default                   | Description                        |
|------------------|--------|---------------------------|------------------------------------|
| `--workers`      | int    | min(available_cpus, 4)    | Number of parallel scanner workers |
| `--clear-cache`  | bool   | false                     | Purge scan cache before scanning   |
| `--cache-ttl`    | int    | 604800                    | Cache TTL in seconds               |
| `--cache-path`   | string | .franken_node/scan_cache.json | Path to the scan cache file    |

## 4. Benchmark Methodology

### 4.1 Metrics

All benchmarks report the following metrics:

| Metric            | Unit          | Description                                         |
|-------------------|---------------|-----------------------------------------------------|
| wall_clock_ms     | milliseconds  | Total wall-clock time from scan start to completion |
| files_per_second  | files/second  | Number of files processed per second of wall-clock  |
| cache_hit_ratio   | ratio (0-1)   | Cache hit ratio: fraction of files skipped          |
| peak_memory_mb    | megabytes     | Peak memory (resident set size) during the scan     |

### 4.2 Synthetic Monorepo Fixture

Benchmarks use a synthetic monorepo fixture consisting of:

- **10,000+ files** distributed across a realistic directory hierarchy
- File sizes ranging from 100 bytes to 50 KB (weighted toward 1-5 KB)
- A mix of file types: `.rs`, `.js`, `.ts`, `.json`, `.toml`, `.md`
- Deterministic generation from a fixed seed for reproducibility

The fixture generator is idempotent: running it twice with the same seed
produces byte-identical output.

### 4.3 Benchmark Scenarios

| Scenario              | Description                                        | Target                          |
|-----------------------|----------------------------------------------------|---------------------------------|
| Full scan (cold)      | No cache, single worker                            | Baseline measurement            |
| Full scan (parallel)  | No cache, 4 workers                                | >= 3.0x speedup vs cold         |
| Incremental (1%)      | 1% of files changed since last scan                | < 10% of full scan wall-clock   |
| Incremental (0%)      | No changes since last scan                         | cache_hit_ratio = 1.0           |
| Cache expired         | All entries past TTL                                | Equivalent to full scan         |

### 4.4 Reporting

Benchmark results are emitted as structured JSON and optionally as a human-readable
table. The CI pipeline captures benchmark results in
`artifacts/section_10_6/bd-2q5/benchmark_results.json`.

## 5. Event Codes

| Code    | Trigger                                          |
|---------|--------------------------------------------------|
| OMS-001 | Scan started                                     |
| OMS-002 | Scan cache loaded from disk                      |
| OMS-003 | Scan completed (includes summary metrics)        |
| OMS-004 | Cache invalidated (TTL expiration or --clear-cache) |

## 6. Invariants

| ID              | Statement                                                                              |
|-----------------|----------------------------------------------------------------------------------------|
| INV-OMS-HASH    | Every cached file entry includes SHA-256 content hash and timestamp.                   |
| INV-OMS-BATCH   | Deterministic batch assignment: lexicographic sort + round-robin partitioning.          |
| INV-OMS-TTL     | Cache entries older than TTL are evicted before use.                                   |
| INV-OMS-SCALE   | Near-linear throughput scaling from 1 to 4 workers (>= 3.0x at 4 workers).            |

## 7. Failure Modes and Mitigations

| Failure Mode              | Mitigation                                                  |
|---------------------------|-------------------------------------------------------------|
| Corrupt cache file        | Detect via JSON parse failure; delete and re-scan.          |
| Unknown cache version     | Discard cache; emit OMS-004; perform full scan.             |
| Worker panic              | Catch at join boundary; mark batch as failed; re-scan batch on main thread. |
| Disk full during cache write | Write to temp file first; atomic rename. Fail gracefully if rename fails. |
| Clock skew (TTL calc)     | Use monotonic clock for duration; wall clock only for display timestamps.  |
