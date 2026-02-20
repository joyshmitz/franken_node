//! Conformance tests for bd-2vs4: Lease coordinator selection and quorum.

use frankenengine_node::connector::lease_coordinator::*;

fn cands() -> Vec<CoordinatorCandidate> {
    vec![
        CoordinatorCandidate { node_id: "n1".into(), weight: 10 },
        CoordinatorCandidate { node_id: "n2".into(), weight: 5 },
        CoordinatorCandidate { node_id: "n3".into(), weight: 8 },
    ]
}

fn qcfg() -> QuorumConfig { QuorumConfig::default_config() }

fn sig(id: &str, hash: &str) -> QuorumSignature {
    QuorumSignature { signer_id: id.into(), signature: compute_test_signature(id, hash) }
}

#[test]
fn inv_lc_deterministic() {
    let s1 = select_coordinator(&cands(), "l1", "tr").unwrap();
    let s2 = select_coordinator(&cands(), "l1", "tr").unwrap();
    assert_eq!(s1.selected, s2.selected, "INV-LC-DETERMINISTIC violated");
}

#[test]
fn inv_lc_quorum_tier_standard() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(v.passed, "INV-LC-QUORUM-TIER: Standard with 1 sig should pass");
}

#[test]
fn inv_lc_quorum_tier_risky_needs_two() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    assert!(!v.passed, "INV-LC-QUORUM-TIER: Risky with 1 sig should fail");
}

#[test]
fn inv_lc_verify_classified_below_quorum() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Dangerous", &sigs, &known, "h", "tr", "ts");
    assert!(v.failures.iter().any(|f| f.code() == "LC_BELOW_QUORUM"));
}

#[test]
fn inv_lc_verify_classified_invalid_sig() {
    let known = vec!["s1".to_string()];
    let sigs = vec![QuorumSignature { signer_id: "s1".into(), signature: "bad".into() }];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(v.failures.iter().any(|f| f.code() == "LC_INVALID_SIGNATURE"));
}

#[test]
fn inv_lc_verify_classified_unknown_signer() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h"), sig("unknown", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(v.failures.iter().any(|f| f.code() == "LC_UNKNOWN_SIGNER"));
}

#[test]
fn inv_lc_replay() {
    let known = vec!["s1".to_string(), "s2".to_string()];
    let sigs = vec![sig("s1", "h"), sig("s2", "h")];
    let v1 = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    let v2 = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    assert_eq!(v1.passed, v2.passed, "INV-LC-REPLAY violated");
    assert_eq!(v1.received, v2.received);
}
