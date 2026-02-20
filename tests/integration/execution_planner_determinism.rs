//! Integration tests for bd-jxgt: Execution planner scorer determinism.

use frankenengine_node::connector::execution_scorer::*;

fn cand(id: &str, latency: f64, risk: f64, cap: f64) -> CandidateInput {
    CandidateInput {
        device_id: id.into(),
        estimated_latency_ms: latency,
        risk_score: risk,
        capability_match_ratio: cap,
    }
}

#[test]
fn inv_eps_deterministic() {
    let candidates = vec![
        cand("d1", 100.0, 0.2, 0.9),
        cand("d2", 200.0, 0.5, 0.8),
        cand("d3", 50.0, 0.1, 0.7),
        cand("d4", 300.0, 0.8, 0.3),
    ];
    let w = ScoringWeights::default_weights();
    let r1 = score_candidates(&candidates, &w, "tr", "ts").unwrap();
    let r2 = score_candidates(&candidates, &w, "tr", "ts").unwrap();
    for (a, b) in r1.candidates.iter().zip(r2.candidates.iter()) {
        assert_eq!(a.device_id, b.device_id, "INV-EPS-DETERMINISTIC violated");
        assert_eq!(a.rank, b.rank);
        assert!((a.total_score - b.total_score).abs() < 1e-10);
    }
}

#[test]
fn inv_eps_tiebreak() {
    let candidates = vec![
        cand("z-device", 100.0, 0.5, 0.5),
        cand("a-device", 100.0, 0.5, 0.5),
        cand("m-device", 100.0, 0.5, 0.5),
    ];
    let w = ScoringWeights::default_weights();
    let d = score_candidates(&candidates, &w, "tr", "ts").unwrap();
    assert_eq!(d.candidates[0].device_id, "a-device", "INV-EPS-TIEBREAK: lexicographic first");
    assert_eq!(d.candidates[1].device_id, "m-device");
    assert_eq!(d.candidates[2].device_id, "z-device");
}

#[test]
fn inv_eps_explainable() {
    let candidates = vec![cand("d1", 200.0, 0.3, 0.8)];
    let w = ScoringWeights::default_weights();
    let d = score_candidates(&candidates, &w, "tr", "ts").unwrap();
    let c = &d.candidates[0];
    let sum = c.factors.latency_component + c.factors.risk_component + c.factors.capability_component;
    assert!((sum - c.total_score).abs() < 1e-10, "INV-EPS-EXPLAINABLE: factors must sum to total");
}

#[test]
fn inv_eps_reject_invalid() {
    let w = ScoringWeights {
        latency_weight: -1.0,
        risk_weight: 0.5,
        capability_weight: 0.5,
    };
    let err = score_candidates(&[cand("d1", 100.0, 0.5, 0.5)], &w, "tr", "ts").unwrap_err();
    assert_eq!(err.code(), "EPS_INVALID_WEIGHTS", "INV-EPS-REJECT-INVALID violated");
}
