use std::path::PathBuf;
use std::process::{Command, Output};

use chrono::{TimeDelta, Utc};
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction, FleetActionRecord, FleetTargetKind, FleetTransport,
    NodeHealth, NodeStatus,
};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/franken-node")
}

fn run_cli(args: &[&str]) -> Output {
    let fleet_state = tempdir().expect("tempdir");
    run_cli_with_fleet_state(args, &fleet_state.path().join("fleet-state"))
}

fn run_cli_with_fleet_state(args: &[&str], fleet_state_dir: &std::path::Path) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .env("FRANKEN_NODE_FLEET_STATE_DIR", fleet_state_dir)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn seed_transport(fleet_state_dir: &std::path::Path) -> FileFleetTransport {
    let mut transport = FileFleetTransport::new(fleet_state_dir);
    transport.initialize().expect("initialize fleet transport");
    transport
}

#[test]
fn fleet_status_reports_zone_state() {
    let output = run_cli(&["fleet", "status", "--zone", "zone-1", "--verbose"]);
    assert!(
        output.status.success(),
        "fleet status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fleet status: zone=zone-1"));
    assert!(stdout.contains("activated=true"));
    assert!(stdout.contains("pending_convergences=0"));
    assert!(stdout.contains("healthy_nodes=0/0"));
}

#[test]
fn fleet_reconcile_executes_and_reports_operation() {
    let output = run_cli(&["fleet", "reconcile"]);
    assert!(
        output.status.success(),
        "fleet reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fleet action: type=reconcile"));
    assert!(stdout.contains("success=true"));
    assert!(stdout.contains("event_code=FLEET-005"));
}

#[test]
fn fleet_release_nonexistent_incident_reports_error() {
    let output = run_cli(&["fleet", "release", "--incident", "inc-demo-123"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incident `inc-demo-123` not found") || !output.status.success(),
        "fleet release should fail for nonexistent incident, stderr: {stderr}",
    );
}

#[test]
fn fleet_status_uses_transport_shared_state_counts() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-status".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-status-1".to_string(),
                target_id: "sha256:status".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "status verification".to_string(),
                quarantine_version: 4,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-fresh".to_string(),
            last_seen: now,
            quarantine_version: 4,
            health: NodeHealth::Healthy,
        })
        .expect("write fresh node");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-stale".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 1,
            health: NodeHealth::Degraded,
        })
        .expect("write stale node");

    let output = run_cli_with_fleet_state(
        &["fleet", "status", "--zone", "zone-1", "--json"],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet status --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet status json");
    assert_eq!(payload["status"]["zone_id"], "zone-1");
    assert_eq!(payload["status"]["active_quarantines"], 1);
    assert_eq!(payload["status"]["healthy_nodes"], 1);
    assert_eq!(payload["status"]["total_nodes"], 2);
    assert_eq!(
        payload["status"]["pending_convergences"][0]["progress_pct"],
        50
    );
    assert_eq!(
        payload["status"]["pending_convergences"][0]["phase"],
        "TimedOut"
    );
}

#[test]
fn fleet_release_publishes_release_action_to_transport() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-release".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-release-1".to_string(),
                target_id: "sha256:release".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "release verification".to_string(),
                quarantine_version: 7,
            },
        })
        .expect("publish quarantine");

    let output = run_cli_with_fleet_state(
        &["fleet", "release", "--incident", "inc-release-1", "--json"],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet release json");
    assert_eq!(payload["action"]["action_type"], "release");
    assert_eq!(payload["action"]["event_code"], "FLEET-004");

    let actions = transport.list_actions().expect("list actions");
    assert!(matches!(
        &actions.last().expect("release action").action,
        FleetAction::Release {
            zone_id,
            incident_id,
            reason: Some(reason),
        } if zone_id == "zone-1"
            && incident_id == "inc-release-1"
            && reason == "manual release via fleet CLI"
    ));
}

#[test]
fn fleet_reconcile_republishes_pending_quarantines_for_stale_nodes() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-reconcile".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-reconcile-1".to_string(),
                target_id: "sha256:reconcile".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "reconcile verification".to_string(),
                quarantine_version: 5,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-stale".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 2,
            health: NodeHealth::Degraded,
        })
        .expect("write stale node");

    let output = run_cli_with_fleet_state(&["fleet", "reconcile", "--json"], &fleet_state_dir);
    assert!(
        output.status.success(),
        "fleet reconcile --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet reconcile json");
    assert_eq!(payload["action"]["action_type"], "reconcile");
    assert_eq!(payload["action"]["event_code"], "FLEET-005");

    let actions = transport.list_actions().expect("list actions");
    assert_eq!(actions.len(), 2);
    assert!(matches!(
        &actions.last().expect("republished action").action,
        FleetAction::Quarantine {
            zone_id,
            incident_id,
            target_id,
            target_kind: FleetTargetKind::Artifact,
            reason,
            quarantine_version,
        } if zone_id == "zone-1"
            && incident_id == "inc-reconcile-1"
            && target_id == "sha256:reconcile"
            && reason == "reconcile verification"
            && *quarantine_version == 5
    ));
}

#[test]
fn fleet_status_json_includes_full_shared_state() {
    let output = run_cli(&["fleet", "status", "--json"]);
    assert!(
        output.status.success(),
        "fleet status --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet status json");
    assert_eq!(payload["status"]["zone_id"], "all");
    assert_eq!(
        payload["state"]["schema_version"],
        "franken-node/fleet-transport-state/v1"
    );
    assert!(payload["state"]["actions"].is_array());
    assert!(payload["state"]["nodes"].is_array());
}
