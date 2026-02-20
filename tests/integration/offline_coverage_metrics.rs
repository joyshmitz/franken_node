//! Integration tests for bd-29w6: Offline coverage tracker and SLO dashboards.

use frankenengine_node::connector::offline_coverage::*;

fn ev(id: &str, available: bool, ts: u64, scope: &str) -> CoverageEvent {
    CoverageEvent {
        artifact_id: id.into(),
        available,
        timestamp: ts,
        scope: scope.into(),
    }
}

fn slo(name: &str, threshold: f64) -> SloTarget {
    SloTarget {
        metric_name: name.into(),
        threshold,
        breach_action: "alert".into(),
    }
}

#[test]
fn inv_oct_continuous() {
    let mut t = OfflineCoverageTracker::new();
    t.record_event(ev("a1", true, 100, "prod")).unwrap();
    let m1 = t.compute_metrics("prod").unwrap();
    assert!((m1.coverage_ratio - 1.0).abs() < 1e-10);

    t.record_event(ev("a2", false, 101, "prod")).unwrap();
    let m2 = t.compute_metrics("prod").unwrap();
    assert!((m2.coverage_ratio - 0.5).abs() < 1e-10, "INV-OCT-CONTINUOUS: metrics must update on each event");
}

#[test]
fn inv_oct_slo_breach() {
    let mut t = OfflineCoverageTracker::new();
    t.record_event(ev("a1", false, 100, "prod")).unwrap();
    t.record_event(ev("a2", false, 101, "prod")).unwrap();
    let alerts = t.check_slos(&[slo("coverage", 0.5)], "prod", 200, "tr").unwrap();
    assert!(!alerts.is_empty(), "INV-OCT-SLO-BREACH: must alert on breach");
    assert_eq!(alerts[0].slo_name, "coverage");
}

#[test]
fn inv_oct_traceable() {
    let mut t = OfflineCoverageTracker::new();
    t.record_event(ev("a1", true, 100, "prod")).unwrap();
    t.record_event(ev("a2", false, 101, "prod")).unwrap();
    let snap = t.dashboard_snapshot("trace-abc", "2026-01-01");
    assert_eq!(snap.trace_id, "trace-abc");
    assert_eq!(snap.event_count, 2, "INV-OCT-TRACEABLE: event count must be reported");
}

#[test]
fn inv_oct_deterministic() {
    let mut t = OfflineCoverageTracker::new();
    t.record_event(ev("a1", true, 100, "prod")).unwrap();
    t.record_event(ev("a2", false, 101, "prod")).unwrap();
    let m1 = t.compute_metrics("prod").unwrap();
    let m2 = t.compute_metrics("prod").unwrap();
    assert!((m1.coverage_ratio - m2.coverage_ratio).abs() < 1e-10, "INV-OCT-DETERMINISTIC violated");
    assert_eq!(m1.repair_debt_count, m2.repair_debt_count);
}
