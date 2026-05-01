//! Benchmark comparing CuckooFilter vs BTreeSet for capability revocation checking.
//!
//! This benchmark demonstrates the performance improvement from using cuckoo filters
//! for O(1) revocation checking instead of O(log n) BTreeSet lookups.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use frankenengine_node::security::cuckoo_filter::CuckooFilter;
use std::collections::BTreeSet;
use std::time::Duration;

/// Baseline revocation checker using BTreeSet (current implementation)
struct BTreeRevocationChecker {
    revoked_tokens: BTreeSet<String>,
}

impl BTreeRevocationChecker {
    fn new() -> Self {
        Self {
            revoked_tokens: BTreeSet::new(),
        }
    }

    fn insert(&mut self, token_id: String) -> bool {
        self.revoked_tokens.insert(token_id)
    }

    fn contains(&self, token_id: &str) -> bool {
        self.revoked_tokens.contains(token_id)
    }

    fn len(&self) -> usize {
        self.revoked_tokens.len()
    }
}

fn benchmark_revocation_checking(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_checking");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Test different dataset sizes to show scalability improvement
    for &size in &[1_000, 10_000, 100_000, 500_000] {
        // Generate test data
        let revoked_tokens: Vec<String> = (0..size)
            .map(|i| format!("revoked_token_{:08}", i))
            .collect();

        // Generate mixed query set (50% hits, 50% misses)
        let test_queries: Vec<String> = (0..1000)
            .map(|i| {
                if i % 2 == 0 {
                    // 50% hits - query existing tokens
                    format!("revoked_token_{:08}", (i * size / 2000) % size)
                } else {
                    // 50% misses - query non-existent tokens
                    format!("not_revoked_token_{:08}", i)
                }
            })
            .collect();

        // Setup CuckooFilter
        let mut cuckoo_filter = CuckooFilter::new(size);
        for token in &revoked_tokens {
            cuckoo_filter.insert(token);
        }

        // Setup BTreeSet baseline
        let mut btree_checker = BTreeRevocationChecker::new();
        for token in revoked_tokens {
            btree_checker.insert(token);
        }

        // Benchmark CuckooFilter lookup
        group.bench_with_input(
            BenchmarkId::new("cuckoo_filter_lookup", size),
            &size,
            |b, _| {
                let mut query_idx = 0;
                b.iter(|| {
                    let query = &test_queries[query_idx % test_queries.len()];
                    query_idx = (query_idx + 1) % test_queries.len();
                    black_box(cuckoo_filter.contains(query))
                })
            },
        );

        // Benchmark BTreeSet lookup
        group.bench_with_input(BenchmarkId::new("btree_lookup", size), &size, |b, _| {
            let mut query_idx = 0;
            b.iter(|| {
                let query = &test_queries[query_idx % test_queries.len()];
                query_idx = (query_idx + 1) % test_queries.len();
                black_box(btree_checker.contains(query))
            })
        });

        // Report memory usage
        let cuckoo_memory = cuckoo_filter.memory_usage();
        let btree_memory = std::mem::size_of::<BTreeRevocationChecker>()
            + btree_checker.len() * (std::mem::size_of::<String>() + 24); // approx node overhead

        println!(
            "Size {}: CuckooFilter {}KB, BTreeSet {}KB, ratio {:.1}x",
            size,
            cuckoo_memory / 1024,
            btree_memory / 1024,
            btree_memory as f64 / cuckoo_memory as f64
        );
    }

    group.finish();
}

fn benchmark_insertion_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_insertion");
    group.measurement_time(Duration::from_secs(5));

    for &size in &[10_000, 50_000] {
        let tokens: Vec<String> = (0..size).map(|i| format!("token_{:08}", i)).collect();

        // Benchmark CuckooFilter insertion
        group.bench_with_input(
            BenchmarkId::new("cuckoo_filter_insert", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut filter = CuckooFilter::new(size);
                    for token in &tokens {
                        black_box(filter.insert(token));
                    }
                })
            },
        );

        // Benchmark BTreeSet insertion
        group.bench_with_input(BenchmarkId::new("btree_insert", size), &size, |b, _| {
            b.iter(|| {
                let mut checker = BTreeRevocationChecker::new();
                for token in &tokens {
                    black_box(checker.insert(token.clone()));
                }
            })
        });
    }

    group.finish();
}

fn benchmark_deletion_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("revocation_deletion");
    group.measurement_time(Duration::from_secs(5));

    let size = 10_000;
    let tokens: Vec<String> = (0..size).map(|i| format!("token_{:08}", i)).collect();

    // Setup pre-filled CuckooFilter
    let mut cuckoo_filter = CuckooFilter::new(size);
    for token in &tokens {
        cuckoo_filter.insert(token);
    }

    // Benchmark CuckooFilter deletion
    group.bench_function("cuckoo_filter_delete", |b| {
        b.iter(|| {
            let mut filter = cuckoo_filter.clone();
            for (i, token) in tokens.iter().enumerate() {
                if i % 10 == 0 {
                    // Delete every 10th token
                    black_box(filter.remove(token));
                }
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_revocation_checking,
    benchmark_insertion_performance,
    benchmark_deletion_performance
);
criterion_main!(benches);
