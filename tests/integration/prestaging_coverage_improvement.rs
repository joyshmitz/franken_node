//! Integration tests for bd-2t5u: Predictive pre-staging engine.

use frankenengine_node::connector::prestage_engine::*;

fn cand(id: &str, size: u64, prob: f64) -> ArtifactCandidate {
    ArtifactCandidate {
        artifact_id: id.into(),
        size_bytes: size,
        predicted_probability: prob,
    }
}

fn config() -> PrestageConfig {
    PrestageConfig {
        max_bytes: 1000,
        probability_threshold: 0.5,
        max_artifacts_per_cycle: 10,
    }
}

#[test]
fn inv_pse_budget() {
    let candidates = vec![
        cand("a1", 400, 0.9),
        cand("a2", 400, 0.8),
        cand("a3", 400, 0.7),
    ];
    let (_, report) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
    assert!(report.budget_used <= config().max_bytes, "INV-PSE-BUDGET violated");
}

#[test]
fn inv_pse_coverage() {
    let candidates = vec![
        cand("a1", 100, 0.9),
        cand("a2", 100, 0.8),
        cand("a3", 100, 0.3), // below threshold
    ];
    let (_, report) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
    assert!(report.staged_count > 0, "INV-PSE-COVERAGE: must improve over baseline");
}

#[test]
fn inv_pse_deterministic() {
    let candidates = vec![
        cand("a1", 100, 0.7),
        cand("a2", 100, 0.9),
        cand("a3", 100, 0.8),
    ];
    let (d1, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
    let (d2, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
    for (a, b) in d1.iter().zip(d2.iter()) {
        assert_eq!(a.artifact_id, b.artifact_id, "INV-PSE-DETERMINISTIC violated");
        assert_eq!(a.staged, b.staged);
    }
}

#[test]
fn inv_pse_quality() {
    let candidates = vec![
        cand("a1", 100, 0.9),
        cand("a2", 100, 0.8),
        cand("a3", 100, 0.3),
    ];
    let (decisions, _) = evaluate_candidates(&candidates, &config(), "tr", "ts").unwrap();
    let actual_needed = vec!["a1".to_string(), "a3".to_string()];
    let q = measure_quality(&decisions, &actual_needed);
    assert!(q.precision >= 0.0 && q.precision <= 1.0);
    assert!(q.recall >= 0.0 && q.recall <= 1.0);
    assert!(q.f1_score >= 0.0, "INV-PSE-QUALITY: metrics must be reported");
}
