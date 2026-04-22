//! Benchmark for trust card canonical encoding optimization.
//!
//! Profiles the hotspot in canonical JSON encoding to measure:
//! - BTreeSet allocation overhead for key sorting
//! - Recursive clone overhead in value canonicalization
//! - JSON serialization performance with large nested objects

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Current implementation - creates BTreeSet and clones keys
fn canonicalize_value_current(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: BTreeSet<String> = BTreeSet::new();
            for key in map.keys() {
                keys.insert(key.clone());
            }
            let mut out = serde_json::Map::new();
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_current(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value_current).collect()),
        _ => value,
    }
}

/// Optimized implementation - avoids BTreeSet allocation and reduces cloning
fn canonicalize_value_optimized(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable(); // In-place sort, no BTreeSet allocation

            let mut out = Map::with_capacity(keys.len()); // Pre-allocate capacity
            for key in keys {
                if let Some(val) = map.get(&key) {
                    out.insert(key, canonicalize_value_optimized(val.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value_optimized).collect()),
        _ => value,
    }
}

/// Generate nested JSON object for benchmarking
fn generate_nested_trust_card(depth: usize, width: usize) -> Value {
    fn build_object(current_depth: usize, max_depth: usize, width: usize) -> Value {
        let mut map = Map::new();

        for i in 0..width {
            let key = format!("field_{:03}", i);
            let value = if current_depth < max_depth {
                build_object(current_depth + 1, max_depth, width)
            } else {
                serde_json::json!({
                    "extension_id": format!("npm:@acme/plugin-{}", i),
                    "version": "1.0.0",
                    "hash": format!("{:064x}", i),
                    "timestamp": "2026-04-22T10:00:00Z",
                    "metadata": {
                        "size": 12345 + i,
                        "dependencies": (0..i%5).map(|j| format!("dep-{}", j)).collect::<Vec<_>>(),
                    }
                })
            };
            map.insert(key, value);
        }

        Value::Object(map)
    }

    build_object(0, depth, width)
}

fn bench_canonical_encoding(c: &mut Criterion) {
    // Generate test data of various complexities
    let simple = generate_nested_trust_card(1, 5);
    let medium = generate_nested_trust_card(3, 8);
    let complex = generate_nested_trust_card(4, 12);

    let test_cases = vec![
        ("simple_1x5", simple),
        ("medium_3x8", medium),
        ("complex_4x12", complex),
    ];

    let mut group = c.benchmark_group("trust_card_canonical");

    for (name, data) in &test_cases {
        // Baseline: current implementation
        group.bench_with_input(
            BenchmarkId::new("current", name),
            data,
            |b, data| {
                b.iter(|| {
                    black_box(canonicalize_value_current(black_box(data.clone())))
                })
            }
        );

        // Optimized: reduced allocation
        group.bench_with_input(
            BenchmarkId::new("optimized", name),
            data,
            |b, data| {
                b.iter(|| {
                    black_box(canonicalize_value_optimized(black_box(data.clone())))
                })
            }
        );

        // Additional optimization: test serialization too
        group.bench_with_input(
            BenchmarkId::new("serialize_current", name),
            data,
            |b, data| {
                b.iter(|| {
                    let canonical = canonicalize_value_current(data.clone());
                    black_box(serde_json::to_string(&canonical).unwrap())
                })
            }
        );

        group.bench_with_input(
            BenchmarkId::new("serialize_optimized", name),
            data,
            |b, data| {
                b.iter(|| {
                    let canonical = canonicalize_value_optimized(data.clone());
                    black_box(serde_json::to_string(&canonical).unwrap())
                })
            }
        );
    }

    group.finish();
}

criterion_group!(benches, bench_canonical_encoding);
criterion_main!(benches);