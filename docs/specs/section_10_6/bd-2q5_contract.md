# bd-2q5: Optimize Migration Scanner Throughput for Large Monorepos

## Bead: bd-2q5 | Section: 10.6

## Purpose

Optimizes the migration scanner to handle large monorepos (10k+ files) efficiently
through incremental scanning with content hash caching, parallel file processing
with deterministic batching, and persistent scan cache reuse across runs. The scanner
must deliver near-linear speedup to 4 workers, cache-based re-scan performance within
10% of full-scan time when only 1% of files have changed, and deterministic batch
assignment regardless of filesystem ordering.

## Acceptance Criteria

1. Incremental scanning via content hash cache: files whose SHA-256 hash has not
   changed since last scan are skipped entirely.
2. Parallel file processing with near-linear throughput scaling to 4 workers.
3. Deterministic batching: given the same file list, batch assignment is identical
   regardless of filesystem enumeration order.
4. Persistent scan cache stored at `.franken_node/scan_cache.json` with format
   versioning and TTL-based expiration (default 7 days).
5. CLI flag `--clear-cache` forces a full re-scan by purging the cache file.
6. CLI flag `--workers N` controls parallelism (default: available CPUs, capped at 4).
7. Re-scanning a 10k-file monorepo with only 1% changes completes in less than 10%
   of the full-scan wall-clock time.
8. Benchmark methodology documented: wall-clock time, files/second throughput,
   cache hit ratio, and peak memory usage.

## Event Codes

| Code    | When Emitted                                                        |
|---------|---------------------------------------------------------------------|
| OMS-001 | Scan started: emitted at the beginning of every scan invocation.    |
| OMS-002 | Cache loaded: emitted when an existing scan cache is read from disk.|
| OMS-003 | Scan completed: emitted with summary metrics (files scanned, skipped, duration). |
| OMS-004 | Cache invalidated: emitted when TTL expiration or `--clear-cache` purges entries. |

## Invariants

| ID              | Statement                                                                              |
|-----------------|----------------------------------------------------------------------------------------|
| INV-OMS-HASH    | Every file entry in the scan cache includes a SHA-256 content hash and a timestamp.    |
| INV-OMS-BATCH   | Batch assignment is deterministic: sorting the file list lexicographically and partitioning by round-robin yields identical batches on every invocation. |
| INV-OMS-TTL     | Cache entries older than the configured TTL (default 7 days) are evicted before use.   |
| INV-OMS-SCALE   | Throughput scales near-linearly from 1 to 4 workers (>= 3.0x speedup at 4 workers).   |

## Quantitative Targets

| Metric                              | Target                                    |
|--------------------------------------|------------------------------------------|
| Incremental re-scan (1% changed)     | < 10% of full-scan wall-clock time       |
| Parallel speedup (4 workers)         | >= 3.0x vs single-threaded baseline      |
| Cache hit ratio (0% changes)         | 100%                                     |
| Cache hit ratio (1% changes)         | >= 99%                                   |
| Peak memory (10k files)              | < 200 MB                                 |
| Scan cache format version            | "1.0"                                    |
| Default TTL                          | 7 days (604800 seconds)                  |

## Optimization Strategies

1. **Incremental scanning**: Compute SHA-256 hash of each file; compare against
   cached hash. Skip files whose hash matches. Only re-scan files with changed
   or missing hashes.

2. **Parallel file processing**: Partition the sorted file list into deterministic
   batches via round-robin assignment. Process batches concurrently using a
   configurable worker pool (default: min(available_cpus, 4)).

3. **Cache reuse across runs**: Persist the scan cache to
   `.franken_node/scan_cache.json`. On subsequent runs, load the cache, evict
   stale entries (TTL expired), and use remaining entries to skip unchanged files.

## Cache Format

```json
{
  "version": "1.0",
  "created_at": "2026-02-20T12:00:00Z",
  "ttl_seconds": 604800,
  "entries": {
    "src/lib.rs": {
      "hash": "sha256:abcdef...",
      "scanned_at": "2026-02-20T12:00:00Z",
      "size_bytes": 4096
    }
  }
}
```

## Dependencies

- Upstream: bd-2f43 (migration pathways), bd-1koz (section gate)
- Downstream: bd-20a (section rollup)
