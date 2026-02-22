//! Integration tests for adaptive multi-rail isolation mesh (bd-gad3).

use frankenengine_node::security::isolation_rail_router::*;

fn untrusted_workload(id: &str) -> Workload {
    Workload {
        id: id.to_string(),
        trust_profile: TrustProfile::Untrusted,
        latency_sensitive: false,
        latency_budget_us: 10_000,
    }
}

fn latency_sensitive_workload(id: &str, budget_us: u64) -> Workload {
    Workload {
        id: id.to_string(),
        trust_profile: TrustProfile::Verified,
        latency_sensitive: true,
        latency_budget_us: budget_us,
    }
}

// --- Assignment ---

#[test]
fn assign_and_retrieve_placement() {
    let mut router = RailRouter::default_router();
    let wl = untrusted_workload("wl-int-1");
    let p = router.assign_workload(&wl).unwrap();
    assert_eq!(p.rail, IsolationRail::Standard);
    let retrieved = router.get_placement("wl-int-1").unwrap();
    assert_eq!(retrieved.rail, IsolationRail::Standard);
}

#[test]
fn trust_profiles_map_to_correct_rails() {
    let mut router = RailRouter::default_router();
    let profiles = [
        ("w-untrusted", TrustProfile::Untrusted, IsolationRail::Standard),
        ("w-verified", TrustProfile::Verified, IsolationRail::Elevated),
        ("w-ha", TrustProfile::HighAssurance, IsolationRail::HighAssurance),
        ("w-crit", TrustProfile::PlatformCritical, IsolationRail::Critical),
    ];
    for (id, trust, expected_rail) in &profiles {
        let wl = Workload {
            id: id.to_string(),
            trust_profile: *trust,
            latency_sensitive: false,
            latency_budget_us: 10_000,
        };
        let p = router.assign_workload(&wl).unwrap();
        assert_eq!(p.rail, *expected_rail, "profile {:?} should map to {}", trust, expected_rail);
    }
}

// --- Hot elevation end-to-end ---

#[test]
fn full_elevation_chain_standard_to_critical() {
    let mut router = RailRouter::default_router();
    let wl = untrusted_workload("wl-chain");
    router.assign_workload(&wl).unwrap();

    let p1 = router.hot_elevate("wl-chain", IsolationRail::Elevated).unwrap();
    assert_eq!(p1.rail, IsolationRail::Elevated);
    assert_eq!(p1.elevation_count, 1);

    let p2 = router.hot_elevate("wl-chain", IsolationRail::HighAssurance).unwrap();
    assert_eq!(p2.rail, IsolationRail::HighAssurance);
    assert_eq!(p2.elevation_count, 2);

    let p3 = router.hot_elevate("wl-chain", IsolationRail::Critical).unwrap();
    assert_eq!(p3.rail, IsolationRail::Critical);
    assert_eq!(p3.elevation_count, 3);
}

#[test]
fn elevation_denied_on_downgrade_attempt() {
    let mut router = RailRouter::default_router();
    let wl = Workload {
        id: "wl-nodown".to_string(),
        trust_profile: TrustProfile::HighAssurance,
        latency_sensitive: false,
        latency_budget_us: 10_000,
    };
    router.assign_workload(&wl).unwrap();
    let err = router.hot_elevate("wl-nodown", IsolationRail::Standard).unwrap_err();
    assert!(matches!(err, RailRouterError::ElevationDenied { .. }));
    // Workload remains on its original rail (fail-safe)
    assert_eq!(router.get_placement("wl-nodown").unwrap().rail, IsolationRail::HighAssurance);
}

#[test]
fn policy_continuity_verified_on_elevation() {
    let mut router = RailRouter::default_router();
    let wl = untrusted_workload("wl-policy");
    router.assign_workload(&wl).unwrap();
    router.hot_elevate("wl-policy", IsolationRail::Critical).unwrap();

    let policy_events: Vec<_> = router
        .events()
        .iter()
        .filter(|e| e.event_code == ISOLATION_POLICY_PRESERVED)
        .collect();
    assert_eq!(policy_events.len(), 1);
}

// --- Budget enforcement ---

#[test]
fn latency_budget_enforcement() {
    let mut router = RailRouter::default_router();
    let wl = latency_sensitive_workload("wl-budget", 1_000);
    router.assign_workload(&wl).unwrap();

    // Within budget
    let p = router.record_latency("wl-budget", 500).unwrap();
    assert_eq!(p.remaining_budget_us(), 500);

    // Exceeds budget
    let err = router.record_latency("wl-budget", 600).unwrap_err();
    assert!(matches!(err, RailRouterError::BudgetExceeded { .. }));
}

// --- Event audit trail ---

#[test]
fn event_trail_captures_full_lifecycle() {
    let mut router = RailRouter::default_router();
    let wl = untrusted_workload("wl-trail");
    router.assign_workload(&wl).unwrap();
    router.hot_elevate("wl-trail", IsolationRail::Elevated).unwrap();
    router.record_latency("wl-trail", 100).unwrap();

    let codes: Vec<&str> = router.events().iter().map(|e| e.event_code.as_str()).collect();
    assert_eq!(codes, vec![
        ISOLATION_RAIL_ASSIGNED,
        ISOLATION_ELEVATION_START,
        ISOLATION_POLICY_PRESERVED,
        ISOLATION_ELEVATION_COMPLETE,
        ISOLATION_BUDGET_CHECK,
    ]);
}

// --- Mesh profile report ---

#[test]
fn mesh_profile_report_reflects_state() {
    let mut router = RailRouter::default_router();
    let wl = untrusted_workload("wl-rpt");
    router.assign_workload(&wl).unwrap();
    let report = router.mesh_profile_report();
    assert_eq!(report.total_rails, 4);
    assert_eq!(report.total_workloads, 1);
    assert!(report.policy_continuity_enforced);
    assert!(report.hot_elevation_only_stricter);
    assert!(report.budget_bound_enforced);
    assert!(report.fail_safe_on_error);
}

// --- Default mesh policy continuity ---

#[test]
fn default_mesh_policies_are_monotonically_inclusive() {
    let config = MeshConfig::default_mesh();
    let rails = &config.available_rails;
    for i in 0..rails.len() - 1 {
        let current = &config.rail_policies[&rails[i]];
        let next = &config.rail_policies[&rails[i + 1]];
        assert!(
            current.is_subset_of(next).is_ok(),
            "policy continuity broken: {} -> {}",
            rails[i],
            rails[i + 1]
        );
    }
}
