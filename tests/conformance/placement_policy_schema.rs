//! Conformance tests for bd-8vby: Device profile registry and placement policy.

use frankenengine_node::connector::device_profile::*;

fn prof(id: &str, caps: &[&str], region: &str, tier: &str, registered: u64) -> DeviceProfile {
    DeviceProfile {
        device_id: id.into(),
        capabilities: caps.iter().map(|c| c.to_string()).collect(),
        region: region.into(),
        tier: tier.into(),
        registered_at: registered,
        schema_version: 1,
    }
}

fn constraint(caps: &[&str], region: &str, min_tier: &str) -> PlacementConstraint {
    PlacementConstraint {
        required_capabilities: caps.iter().map(|c| c.to_string()).collect(),
        preferred_region: region.into(),
        min_tier: min_tier.into(),
        max_latency_ms: 100,
    }
}

#[test]
fn inv_dpr_schema_rejects_invalid() {
    let mut reg = DeviceProfileRegistry::new();
    let bad = DeviceProfile {
        device_id: "".into(),
        capabilities: vec![],
        region: "".into(),
        tier: "".into(),
        registered_at: 0,
        schema_version: 0,
    };
    let err = reg.register(bad).unwrap_err();
    assert_eq!(err.code(), "DPR_SCHEMA_INVALID", "INV-DPR-SCHEMA violated");
}

#[test]
fn inv_dpr_freshness_excludes_stale() {
    let mut reg = DeviceProfileRegistry::new();
    reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
    let policy = PlacementPolicy {
        constraints: vec![constraint(&["gpu"], "", "")],
        freshness_max_age_secs: 50,
        trace_id: "tr".into(),
    };
    // now=200, registered=100 → age=100 > 50
    let err = reg.evaluate_placement(&policy, 200, "ts").unwrap_err();
    assert_eq!(err.code(), "DPR_NO_MATCH", "INV-DPR-FRESHNESS violated");
}

#[test]
fn inv_dpr_deterministic() {
    let mut reg = DeviceProfileRegistry::new();
    reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
    reg.register(prof("d2", &["gpu"], "eu", "Standard", 100)).unwrap();
    reg.register(prof("d3", &["gpu"], "ap", "Standard", 100)).unwrap();
    let policy = PlacementPolicy {
        constraints: vec![constraint(&["gpu"], "us", "")],
        freshness_max_age_secs: 3600,
        trace_id: "tr".into(),
    };
    let r1 = reg.evaluate_placement(&policy, 200, "ts").unwrap();
    let r2 = reg.evaluate_placement(&policy, 200, "ts").unwrap();
    let ids1: Vec<&str> = r1.matched.iter().map(|m| m.device_id.as_str()).collect();
    let ids2: Vec<&str> = r2.matched.iter().map(|m| m.device_id.as_str()).collect();
    assert_eq!(ids1, ids2, "INV-DPR-DETERMINISTIC violated");
}

#[test]
fn inv_dpr_reject_invalid_constraint() {
    let reg = DeviceProfileRegistry::new();
    let policy = PlacementPolicy {
        constraints: vec![],
        freshness_max_age_secs: 3600,
        trace_id: "tr".into(),
    };
    let err = reg.evaluate_placement(&policy, 200, "ts").unwrap_err();
    assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT", "INV-DPR-REJECT-INVALID violated");
}
