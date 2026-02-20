//! Integration tests for bd-2eun: Quarantine-by-default store.

use frankenengine_node::connector::quarantine_store::*;

fn config() -> QuarantineConfig {
    QuarantineConfig {
        max_objects: 10,
        max_bytes: 1000,
        ttl_seconds: 60,
    }
}

#[test]
fn inv_qds_default() {
    let mut store = QuarantineStore::new(config()).unwrap();
    // Any unknown object goes to quarantine
    store.ingest("unknown-obj-1", 50, "peer-x", 1000).unwrap();
    store.ingest("unknown-obj-2", 50, "peer-y", 1001).unwrap();
    assert!(store.contains("unknown-obj-1"), "INV-QDS-DEFAULT: unknown objects must enter quarantine");
    assert!(store.contains("unknown-obj-2"), "INV-QDS-DEFAULT: unknown objects must enter quarantine");
}

#[test]
fn inv_qds_bounded() {
    let cfg = QuarantineConfig {
        max_objects: 3,
        max_bytes: 300,
        ttl_seconds: 600,
    };
    let mut store = QuarantineStore::new(cfg).unwrap();
    for i in 0..5 {
        store.ingest(&format!("obj{i}"), 80, "peer1", 1000 + i as u64).unwrap();
    }
    let stats = store.stats(1010);
    assert!(stats.object_count <= 3, "INV-QDS-BOUNDED: object count must not exceed quota");
    assert!(stats.total_bytes <= 300, "INV-QDS-BOUNDED: total bytes must not exceed quota");
}

#[test]
fn inv_qds_ttl() {
    let mut store = QuarantineStore::new(config()).unwrap();
    store.ingest("old-obj", 50, "peer1", 1000).unwrap();
    // After TTL, ingest triggers eviction
    let evictions = store.ingest("new-obj", 50, "peer1", 1070).unwrap();
    assert!(evictions.iter().any(|e| e.object_id == "old-obj"), "INV-QDS-TTL: expired objects must be evicted");
    assert!(!store.contains("old-obj"), "INV-QDS-TTL: expired objects must not remain");
}

#[test]
fn inv_qds_excluded() {
    let mut store = QuarantineStore::new(config()).unwrap();
    store.ingest("qobj1", 50, "peer1", 1000).unwrap();
    store.ingest("qobj2", 50, "peer1", 1001).unwrap();
    let quarantined = store.quarantined_ids();
    // These IDs must be excluded from primary gossip state
    assert!(quarantined.contains(&"qobj1".to_string()), "INV-QDS-EXCLUDED: must report quarantined IDs");
    assert!(quarantined.contains(&"qobj2".to_string()), "INV-QDS-EXCLUDED: must report quarantined IDs");
    // Sorted for deterministic gossip exclusion
    assert_eq!(quarantined, vec!["qobj1", "qobj2"], "INV-QDS-EXCLUDED: IDs must be sorted");
}
