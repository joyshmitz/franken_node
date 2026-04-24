use std::collections::BTreeMap;

use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use frankenengine_node::api::service::build_endpoint_catalog;
use frankenengine_node::api::verifier_routes::{
    AtcVerificationRequest, get_atc_metric_snapshot, get_atc_proof_chain, get_atc_report,
    verify_atc_computation,
};

fn test_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "test-atc-verifier".to_string(),
        method: AuthMethod::BearerToken,
        roles: vec!["verifier".to_string()],
    }
}

fn test_trace() -> TraceContext {
    TraceContext {
        trace_id: "atc-verifier-api-routes-test".to_string(),
        span_id: "0000000000000007".to_string(),
        trace_flags: 1,
    }
}

#[test]
fn atc_verifier_contract_routes_are_in_endpoint_catalog() {
    let catalog = build_endpoint_catalog();

    for (method, path, hook) in [
        (
            "GET",
            "/api/v1/atc/verifier/metrics/{metric_id}",
            "atc.verifier.metrics.read",
        ),
        (
            "POST",
            "/api/v1/atc/verifier/computations/{computation_id}/verify",
            "atc.verifier.computations.verify",
        ),
        (
            "GET",
            "/api/v1/atc/verifier/computations/{computation_id}/proof-chain",
            "atc.verifier.proof_chain.read",
        ),
        (
            "GET",
            "/api/v1/atc/verifier/reports/{computation_id}",
            "atc.verifier.reports.read",
        ),
    ] {
        let route = catalog
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("missing ATC verifier route {method} {path}"));
        assert_eq!(route.policy_hook, hook);
        assert_eq!(route.auth_method, "BearerToken");
        assert_eq!(route.lifecycle, "stable");
    }
}

#[test]
fn atc_metric_snapshot_is_aggregate_only_and_signed() {
    let identity = test_identity();
    let trace = test_trace();

    let snapshot = get_atc_metric_snapshot(&identity, &trace, "ecosystem_risk_index")
        .expect("ATC metric snapshot")
        .data;

    assert_eq!(snapshot.metric_id, "ecosystem_risk_index");
    assert_eq!(snapshot.data_visibility, "aggregate_only");
    assert!(!snapshot.raw_participant_data_included);
    assert!(
        snapshot
            .provenance
            .dataset_commitment_hash
            .starts_with("sha256:")
    );
    assert!(snapshot.provenance.signature.starts_with("sha256:"));
}

#[test]
fn atc_proof_chain_and_report_share_terminal_root() {
    let identity = test_identity();
    let trace = test_trace();
    let computation_id = "atc-comp-route-test-001";

    let proof_chain = get_atc_proof_chain(&identity, &trace, computation_id)
        .expect("ATC proof chain")
        .data;
    let report = get_atc_report(&identity, &trace, computation_id)
        .expect("ATC report")
        .data;

    assert_eq!(proof_chain.root_hash, report.proof_chain_root_hash);
    assert_eq!(
        proof_chain
            .artifacts
            .last()
            .expect("terminal artifact")
            .artifact_hash,
        proof_chain.root_hash
    );
    for idx in 1..proof_chain.artifacts.len() {
        assert_eq!(
            proof_chain.artifacts[idx].parent_hash.as_deref(),
            Some(proof_chain.artifacts[idx - 1].artifact_hash.as_str())
        );
    }
}

#[test]
fn atc_verify_digest_is_deterministic_for_matching_roots() {
    let identity = test_identity();
    let trace = test_trace();
    let computation_id = "atc-comp-route-test-002";
    let report = get_atc_report(&identity, &trace, computation_id)
        .expect("ATC report")
        .data;
    let request = AtcVerificationRequest {
        metric_snapshot_root_hash: Some(report.metric_snapshot_root_hash),
        proof_chain_root_hash: Some(report.proof_chain_root_hash),
        verifier_parameters: BTreeMap::from([("mode".to_string(), "full".to_string())]),
    };

    let first = verify_atc_computation(&identity, &trace, computation_id, &request)
        .expect("first verification")
        .data;
    let second = verify_atc_computation(&identity, &trace, computation_id, &request)
        .expect("second verification")
        .data;

    assert_eq!(first.decision, "pass");
    assert!(first.deterministic);
    assert_eq!(first.result_digest, second.result_digest);
}

#[test]
fn atc_verify_fails_closed_for_mismatched_proof_root() {
    let identity = test_identity();
    let trace = test_trace();
    let request = AtcVerificationRequest {
        metric_snapshot_root_hash: None,
        proof_chain_root_hash: Some(format!("sha256:{}", "0".repeat(64))),
        verifier_parameters: BTreeMap::new(),
    };

    let result = verify_atc_computation(&identity, &trace, "atc-comp-route-test-003", &request)
        .expect("ATC verification")
        .data;

    assert_eq!(result.decision, "fail");
    assert!(result.deterministic);
    assert_eq!(result.data_visibility, "aggregate_only");
}
