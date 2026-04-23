use chrono::{Duration, TimeZone, Utc};
use frankenengine_node::api::fleet_quarantine::{
    DecisionReceipt, DecisionReceiptPayload, FLEET_RECEIPT_SIGNING_MATERIAL_MISSING,
    FLEET_ROLLBACK_UNVERIFIED, FleetControlError, FleetControlManager, QuarantineScope,
    canonical_decision_receipt_payload_hash, sign_decision_receipt,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};

const SIGNING_KEY_BYTES: [u8; 32] = [91_u8; 32];

fn admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-rollback-boundary-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn trace_context(phase: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("fleet-rollback-boundary-{phase}"),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn activated_manager() -> FleetControlManager {
    let mut manager = FleetControlManager::with_decision_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES),
        "fleet-rollback-boundary-test",
        "fleet-rollback-boundary",
    );
    manager.activate();
    manager
}

fn rollback_receipt(
    incident_id: &str,
    zone_id: &str,
    issued_at: chrono::DateTime<Utc>,
) -> DecisionReceipt {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES);
    let operation_id = format!("rollback-{incident_id}");
    let issued_at = issued_at.to_rfc3339();
    let decision_payload =
        DecisionReceiptPayload::rollback(incident_id, zone_id, "test convergence rollback receipt");
    let payload_hash = canonical_decision_receipt_payload_hash(
        &operation_id,
        "fleet-rollback-boundary-admin",
        zone_id,
        &issued_at,
        &decision_payload,
    );
    let mut receipt = DecisionReceipt {
        operation_id: operation_id.clone(),
        receipt_id: format!("rcpt-{operation_id}"),
        issuer: "fleet-rollback-boundary-admin".to_string(),
        issued_at,
        zone_id: zone_id.to_string(),
        payload_hash,
        decision_payload,
        signature: None,
    };
    receipt.signature = Some(sign_decision_receipt(
        &receipt,
        &signing_key,
        "fleet-rollback-boundary-test",
        "fleet-rollback-boundary",
    ));
    receipt
}

fn quarantined_incident(manager: &mut FleetControlManager) -> (String, QuarantineScope) {
    let scope = QuarantineScope {
        zone_id: "zone-rollback-boundary".to_string(),
        tenant_id: Some("tenant-rollback-boundary".to_string()),
        affected_nodes: 3,
        reason: "rollback boundary regression".to_string(),
    };
    let result = manager
        .quarantine(
            "ext-rollback-boundary",
            &scope,
            &admin_identity(),
            &trace_context("quarantine"),
        )
        .expect("quarantine should create incident");
    (format!("inc-{}", result.operation_id), scope)
}

#[test]
fn quarantine_missing_decision_signing_material_fails_before_state_mutation() {
    let mut manager = FleetControlManager::without_decision_signing_material_for_tests();
    manager.activate();
    let scope = QuarantineScope {
        zone_id: "zone-missing-signing-quarantine".to_string(),
        tenant_id: Some("tenant-missing-signing".to_string()),
        affected_nodes: 3,
        reason: "missing signing material regression".to_string(),
    };

    let err = manager
        .quarantine(
            "ext-missing-signing",
            &scope,
            &admin_identity(),
            &trace_context("missing-signing-quarantine"),
        )
        .expect_err("quarantine must fail without decision signing material");

    assert_eq!(err.error_code(), FLEET_RECEIPT_SIGNING_MATERIAL_MISSING);
    assert_eq!(manager.incident_count(), 0);
    assert!(manager.active_incidents().is_empty());
    assert!(manager.events().is_empty());
    assert!(manager.zones().is_empty());

    let status = manager
        .status(&scope.zone_id)
        .expect("status remains readable after fail-closed quarantine");
    assert_eq!(status.active_quarantines, 0);
    assert!(status.pending_convergences.is_empty());
}

#[test]
fn release_missing_decision_signing_material_fails_before_state_mutation() {
    let mut manager = activated_manager();
    let (incident_id, scope) = quarantined_incident(&mut manager);
    manager.register_rollback_receipt(
        &incident_id,
        rollback_receipt(&incident_id, &scope.zone_id, Utc::now()),
    );

    let incidents_before = manager
        .active_incidents()
        .iter()
        .map(|incident| incident.incident_id.clone())
        .collect::<Vec<_>>();
    let status_before = manager
        .status(&scope.zone_id)
        .expect("status before missing-signing release");
    let events_before = manager.events().to_vec();
    let incident_count_before = manager.incident_count();

    manager.clear_decision_signing_material_for_tests();
    let err = manager
        .release(
            &incident_id,
            &admin_identity(),
            &trace_context("missing-signing-release"),
        )
        .expect_err("release must fail without decision signing material");

    assert_eq!(err.error_code(), FLEET_RECEIPT_SIGNING_MATERIAL_MISSING);
    assert_eq!(manager.incident_count(), incident_count_before);
    assert_eq!(
        manager
            .active_incidents()
            .iter()
            .map(|incident| incident.incident_id.clone())
            .collect::<Vec<_>>(),
        incidents_before
    );
    assert_eq!(
        manager
            .status(&scope.zone_id)
            .expect("status after missing-signing release"),
        status_before
    );
    assert_eq!(manager.events(), events_before.as_slice());
}

#[test]
fn rollback_receipt_exact_ttl_boundary_fails_closed() {
    let mut manager = activated_manager();
    let (incident_id, scope) = quarantined_incident(&mut manager);
    let issued_at = Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap();

    manager.register_rollback_receipt(
        &incident_id,
        rollback_receipt(&incident_id, &scope.zone_id, issued_at),
    );

    manager
        .verify_convergence_rollback_receipt_at_for_tests(
            &incident_id,
            issued_at + Duration::hours(24) - Duration::milliseconds(1),
        )
        .expect("rollback receipt should remain valid just before TTL");

    let err = manager
        .verify_convergence_rollback_receipt_at_for_tests(
            &incident_id,
            issued_at + Duration::hours(24),
        )
        .expect_err("rollback receipt must fail closed at exact TTL boundary");

    match err {
        FleetControlError::RollbackUnverified { code, detail, .. } => {
            assert_eq!(code, FLEET_ROLLBACK_UNVERIFIED);
            assert!(detail.contains("at least 24 hours old"));
        }
        other => panic!("expected rollback-unverified stale receipt, got {other:?}"),
    }
}
