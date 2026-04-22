//! Full fleet quarantine E2E coverage with real in-process state.

use frankenengine_node::api::fleet_quarantine::{
    FLEET_QUARANTINE_INITIATED, FLEET_RECONCILE_COMPLETED, FLEET_RELEASED, FleetControlManager,
    QuarantineScope,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};
use serde_json::{Value, json};

const SUITE: &str = "fleet_quarantine_e2e_full";
const ZONE_ID: &str = "zone-e2e-full";
const EXTENSION_ID: &str = "ext-e2e-quarantine";

struct JsonlTestLog {
    test_name: &'static str,
    lines: Vec<String>,
}

impl JsonlTestLog {
    fn new(test_name: &'static str) -> Self {
        Self {
            test_name,
            lines: Vec::new(),
        }
    }

    fn emit(&mut self, phase: &str, event: &str, data: Value) {
        let record = json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": SUITE,
            "test": self.test_name,
            "phase": phase,
            "event": event,
            "data": data,
        });
        let line = serde_json::to_string(&record).expect("jsonl record should serialize");
        eprintln!("{line}");
        self.lines.push(line);
    }

    fn assert_json_eq(&mut self, field: &str, expected: Value, actual: Value) {
        let matched = expected == actual;
        self.emit(
            "assert",
            "assertion",
            json!({
                "field": field,
                "expected": expected,
                "actual": actual,
                "match": matched,
            }),
        );
        assert!(matched, "{field} mismatch");
    }

    fn assert_jsonl_is_well_formed(&self) {
        assert!(!self.lines.is_empty(), "expected JSONL assertions");
        let parsed: Vec<Value> = self
            .lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("log line must be JSON"))
            .collect();
        assert!(
            parsed.iter().any(|entry| entry["event"] == "assertion"),
            "expected at least one assertion log"
        );
        assert!(
            parsed
                .iter()
                .any(|entry| entry["event"] == "state_snapshot"),
            "expected at least one state snapshot log"
        );
        assert!(
            parsed
                .iter()
                .filter(|entry| entry["event"] == "assertion")
                .all(|entry| entry["data"]["match"] == true),
            "every logged assertion should match"
        );
    }
}

fn activated_manager() -> FleetControlManager {
    let mut manager = FleetControlManager::with_decision_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]),
        "fleet-quarantine-e2e-full",
        "fleet-quarantine-e2e",
    );
    manager.activate();
    manager
}

fn admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-e2e-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn trace(operation: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("fleet-e2e-{operation}-{}", uuid::Uuid::now_v7()),
        span_id: "000000000000e2e0".to_string(),
        trace_flags: 1,
    }
}

fn fixture_scope() -> QuarantineScope {
    QuarantineScope {
        zone_id: ZONE_ID.to_string(),
        tenant_id: Some("tenant-e2e".to_string()),
        affected_nodes: 7,
        reason: "full e2e quarantine-release-reconcile fixture".to_string(),
    }
}

fn log_state_snapshot(
    log: &mut JsonlTestLog,
    manager: &FleetControlManager,
    label: &str,
    zones: &[&str],
) {
    let zone_statuses: Vec<Value> = zones
        .iter()
        .map(|zone_id| {
            let status = manager.status(zone_id).expect("zone status should load");
            json!({
                "zone_id": status.zone_id,
                "active_quarantines": status.active_quarantines,
                "active_revocations": status.active_revocations,
                "healthy_nodes": status.healthy_nodes,
                "total_nodes": status.total_nodes,
                "activated": status.activated,
                "pending_convergences": status.pending_convergences.len(),
            })
        })
        .collect();
    let active_incidents: Vec<Value> = manager
        .active_incidents()
        .into_iter()
        .map(|incident| {
            json!({
                "incident_id": &incident.incident_id,
                "extension_id": &incident.extension_id,
                "zone_id": &incident.zone_id,
                "action_type": &incident.action_type,
                "status": incident.status,
            })
        })
        .collect();
    let events: Vec<Value> = manager
        .events()
        .iter()
        .map(|event| {
            json!({
                "event_code": &event.event_code,
                "event_name": &event.event_name,
                "trace_id": &event.trace_id,
                "zone_id": &event.zone_id,
                "extension_id": &event.extension_id,
                "metadata": &event.metadata,
            })
        })
        .collect();

    log.emit(
        "assert",
        "state_snapshot",
        json!({
            "label": label,
            "incident_count": manager.incident_count(),
            "active_incidents": active_incidents,
            "zones": zone_statuses,
            "events": events,
        }),
    );
}

#[test]
fn quarantine_release_reconcile_sequence_preserves_real_state_with_jsonl_assertions() {
    let mut log = JsonlTestLog::new(
        "quarantine_release_reconcile_sequence_preserves_real_state_with_jsonl_assertions",
    );
    let mut manager = activated_manager();
    let identity = admin_identity();
    let scope = fixture_scope();
    let zones = [ZONE_ID];

    log.emit("setup", "test_start", json!({ "zone_id": ZONE_ID }));
    log_state_snapshot(&mut log, &manager, "initial", &zones);
    log.assert_json_eq(
        "initial incident count",
        json!(0),
        json!(manager.incident_count()),
    );

    log.emit(
        "act",
        "quarantine_start",
        json!({ "extension_id": EXTENSION_ID }),
    );
    let quarantine = manager
        .quarantine(EXTENSION_ID, &scope, &identity, &trace("quarantine"))
        .expect("quarantine should succeed against real manager state");
    let incident_id = format!("inc-{}", quarantine.operation_id);
    log_state_snapshot(&mut log, &manager, "after_quarantine", &zones);
    let quarantined_status = manager.status(ZONE_ID).expect("quarantined status");
    log.assert_json_eq("quarantine success", json!(true), json!(quarantine.success));
    log.assert_json_eq(
        "quarantine event code",
        json!(FLEET_QUARANTINE_INITIATED),
        json!(&quarantine.event_code),
    );
    log.assert_json_eq(
        "quarantine receipt signature verifies",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&quarantine.receipt)),
    );
    log.assert_json_eq(
        "active quarantine count after quarantine",
        json!(1),
        json!(quarantined_status.active_quarantines),
    );
    log.assert_json_eq(
        "incident count after quarantine",
        json!(1),
        json!(manager.incident_count()),
    );

    log.emit(
        "act",
        "release_start",
        json!({ "incident_id": incident_id }),
    );
    let release = manager
        .release(&incident_id, &identity, &trace("release"))
        .expect("release should succeed against real manager state");
    log_state_snapshot(&mut log, &manager, "after_release", &zones);
    let released_status = manager.status(ZONE_ID).expect("released status");
    log.assert_json_eq("release success", json!(true), json!(release.success));
    log.assert_json_eq(
        "release event code",
        json!(FLEET_RELEASED),
        json!(&release.event_code),
    );
    log.assert_json_eq(
        "release receipt signature verifies",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&release.receipt)),
    );
    log.assert_json_eq(
        "active quarantine count after release",
        json!(0),
        json!(released_status.active_quarantines),
    );
    log.assert_json_eq(
        "incident count after release",
        json!(0),
        json!(manager.incident_count()),
    );

    log.emit("act", "reconcile_start", json!({ "zone_id": ZONE_ID }));
    let reconcile = manager
        .reconcile(&identity, &trace("reconcile"))
        .expect("reconcile should succeed against real manager state");
    log_state_snapshot(&mut log, &manager, "after_reconcile", &zones);
    let reconciled_status = manager.status(ZONE_ID).expect("reconciled status");
    log.assert_json_eq("reconcile success", json!(true), json!(reconcile.success));
    log.assert_json_eq(
        "reconcile event code",
        json!(FLEET_RECONCILE_COMPLETED),
        json!(&reconcile.event_code),
    );
    log.assert_json_eq(
        "reconcile receipt signature verifies",
        json!(true),
        json!(manager.verify_decision_receipt_signature(&reconcile.receipt)),
    );
    log.assert_json_eq(
        "active quarantine count after reconcile",
        json!(0),
        json!(reconciled_status.active_quarantines),
    );
    log.assert_json_eq(
        "incident count after reconcile",
        json!(0),
        json!(manager.incident_count()),
    );
    log.assert_json_eq(
        "fleet event sequence",
        json!([
            FLEET_QUARANTINE_INITIATED,
            FLEET_RELEASED,
            FLEET_RECONCILE_COMPLETED
        ]),
        json!(
            manager
                .events()
                .iter()
                .map(|event| event.event_code.as_str())
                .collect::<Vec<_>>()
        ),
    );

    log.emit("assert", "test_end", json!({ "result": "pass" }));
    log.assert_jsonl_is_well_formed();
}
