//! Benchmark for replay bundle gzip serialization optimization.
//!
//! Profiles the hotspot in `gzip_size_bytes()` function to measure:
//! - Allocation overhead from creating new GzEncoder per call
//! - Vec allocation overhead for compression output buffer
//! - Compression speed on realistic replay bundle data

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use frankenengine_node::tools::replay_bundle::{generate_replay_bundle, RawEvent, EventType};
use std::time::SystemTime;

/// Generate realistic replay bundle data for benchmarking
fn generate_realistic_bundle_data(event_count: usize) -> Vec<u8> {
    let mut events = Vec::new();

    for i in 0..event_count {
        let event = RawEvent::new(
            format!("2026-04-22T{:02}:{:02}:{:02}Z", (i / 3600) % 24, (i / 60) % 60, i % 60),
            EventType::ExternalSignal,
            serde_json::json!({
                "scan_id": format!("scan-{:08x}", i * 0x1234),
                "findings": (0..i % 10).map(|j| format!("finding-{}", j)).collect::<Vec<_>>(),
                "metadata": {
                    "scanner_version": "2.1.0",
                    "scan_duration_ms": 1500 + (i % 1000),
                    "files_scanned": 100 + (i % 50),
                }
            }),
        );
        events.push(event);
    }

    let bundle = generate_replay_bundle("benchmark-incident", &events)
        .expect("bundle generation should succeed");

    serde_json::to_vec(&bundle).expect("JSON serialization should succeed")
}

/// Current implementation baseline - creates new GzEncoder per call
#[cfg(feature = "compression")]
fn gzip_size_bytes_current(bytes: &[u8]) -> Result<u64, std::io::Error> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

/// Optimized implementation with pre-allocated buffer reuse
#[cfg(feature = "compression")]
fn gzip_size_bytes_optimized(bytes: &[u8], reusable_buffer: &mut Vec<u8>) -> Result<u64, std::io::Error> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    reusable_buffer.clear();
    let mut encoder = GzEncoder::new(reusable_buffer, Compression::default());
    encoder.write_all(bytes)?;
    let compressed = encoder.finish()?;
    Ok(u64::try_from(compressed.len()).unwrap_or(u64::MAX))
}

fn bench_gzip_compression(c: &mut Criterion) {
    // Generate test data of various sizes
    let small_data = generate_realistic_bundle_data(10);
    let medium_data = generate_realistic_bundle_data(100);
    let large_data = generate_realistic_bundle_data(1000);

    let test_cases = vec![
        ("small_10_events", small_data),
        ("medium_100_events", medium_data),
        ("large_1000_events", large_data),
    ];

    let mut group = c.benchmark_group("replay_bundle_gzip");

    #[cfg(feature = "compression")]
    {
        for (name, data) in &test_cases {
            // Baseline: current implementation
            group.bench_with_input(
                BenchmarkId::new("current", name),
                data,
                |b, data| {
                    b.iter(|| {
                        black_box(gzip_size_bytes_current(black_box(data)))
                    })
                }
            );

            // Optimized: reused buffer
            group.bench_with_input(
                BenchmarkId::new("optimized_reuse_buffer", name),
                data,
                |b, data| {
                    let mut reusable_buffer = Vec::new();
                    b.iter(|| {
                        black_box(gzip_size_bytes_optimized(black_box(data), &mut reusable_buffer))
                    })
                }
            );
        }
    }

    #[cfg(not(feature = "compression"))]
    {
        // Fallback when compression feature is disabled
        for (name, data) in &test_cases {
            group.bench_with_input(
                BenchmarkId::new("no_compression_fallback", name),
                data,
                |b, data| {
                    b.iter(|| {
                        black_box(u64::try_from(data.len()).unwrap_or(u64::MAX))
                    })
                }
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_gzip_compression);
criterion_main!(benches);