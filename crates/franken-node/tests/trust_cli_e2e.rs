use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

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
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn parse_json_stdout(output: &Output, context: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstdout:\n{stdout}"))
}

#[test]
fn trust_card_displays_known_extension_details() {
    let output = run_cli(&["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        output.status.success(),
        "trust card failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("publisher: Acme Security"));
    assert!(stdout.contains("risk: Low"));
}

#[test]
fn trust_list_filters_critical_revoked_cards() {
    let output = run_cli(&["trust", "list", "--risk", "critical", "--revoked", "true"]);
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
    assert!(stdout.contains("revoked:publisher key compromised"));
    assert!(!stdout.contains("npm:@acme/auth-guard"));
}

#[test]
fn trust_list_filters_low_active_cards() {
    let output = run_cli(&["trust", "list", "--risk", "low", "--revoked", "false"]);
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_list_rejects_unknown_risk_value() {
    let output = run_cli(&["trust", "list", "--risk", "severe"]);
    assert!(
        !output.status.success(),
        "expected failure for unknown risk, got status {}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --risk `severe`"));
}

#[test]
fn trust_revoke_marks_target_as_revoked() {
    let output = run_cli(&["trust", "revoke", "npm:@acme/auth-guard"]);
    assert!(
        output.status.success(),
        "trust revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("revocation: revoked (manual revoke via franken-node trust revoke)"));
    assert!(stdout.contains("quarantine: true"));
}

#[test]
fn trust_revoke_fails_for_unknown_extension() {
    let output = run_cli(&["trust", "revoke", "npm:@does-not/exist"]);
    assert!(
        !output.status.success(),
        "trust revoke should fail for unknown extension"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trust card not found"));
}

#[test]
fn trust_quarantine_supports_sha256_artifact_scope() {
    let output = run_cli(&["trust", "quarantine", "--artifact", "sha256:deadbeef"]);
    assert!(
        output.status.success(),
        "trust quarantine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("quarantine applied: artifact=sha256:deadbeef"));
    assert!(stdout.contains("affected_cards=2"));
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_sync_reports_summary_counts() {
    let output = run_cli(&["trust", "sync", "--force"]);
    assert!(
        output.status.success(),
        "trust sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("trust sync completed: force=true"));
    assert!(stdout.contains("cards=2"));
    assert!(stdout.contains("revoked=1"));
    assert!(stdout.contains("quarantined=1"));
}

#[test]
fn trust_card_export_requires_json_flag() {
    let output = run_cli(&["trust-card", "export", "npm:@acme/auth-guard"]);
    assert!(
        !output.status.success(),
        "trust-card export without --json should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`trust-card export` requires `--json`"));
}

#[test]
fn trust_card_export_emits_known_card_json() {
    let output = run_cli(&["trust-card", "export", "npm:@acme/auth-guard", "--json"]);
    assert!(
        output.status.success(),
        "trust-card export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output, "trust-card export");
    assert_eq!(payload["extension"]["extension_id"], "npm:@acme/auth-guard");
    assert_eq!(payload["extension"]["version"], "1.4.2");
    assert_eq!(payload["publisher"]["display_name"], "Acme Security");
    assert_eq!(payload["user_facing_risk_assessment"]["level"], "low");
}

#[test]
fn trust_card_list_filters_by_publisher() {
    let output = run_cli(&["trust-card", "list", "--publisher", "pub-acme"]);
    assert!(
        output.status.success(),
        "trust-card list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension | publisher | cert | reputation | status"));
    assert!(stdout.contains("npm:@acme/auth-guard | pub-acme | Gold | 920bp (Improving) | active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_card_list_rejects_zero_page() {
    let output = run_cli(&["trust-card", "list", "--page", "0"]);
    assert!(
        !output.status.success(),
        "trust-card list with page 0 should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid pagination: page=0, per_page=20"));
}

#[test]
fn trust_card_compare_reports_expected_differences() {
    let output = run_cli(&[
        "trust-card",
        "compare",
        "npm:@acme/auth-guard",
        "npm:@beta/telemetry-bridge",
    ]);
    assert!(
        output.status.success(),
        "trust-card compare failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("compare npm:@acme/auth-guard vs npm:@beta/telemetry-bridge:"));
    assert!(stdout.contains("- certification_level: gold -> bronze"));
    assert!(stdout.contains("- extension_version: 1.4.2 -> 0.9.1"));
    assert!(stdout.contains("- active_quarantine: false -> true"));
}

#[test]
fn trust_card_diff_reports_version_history_changes() {
    let output = run_cli(&["trust-card", "diff", "npm:@beta/telemetry-bridge", "1", "2"]);
    assert!(
        output.status.success(),
        "trust-card diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compare npm:@beta/telemetry-bridge@1 vs npm:@beta/telemetry-bridge@2:")
    );
    assert!(stdout.contains("- certification_level: silver -> bronze"));
    assert!(stdout.contains("- reputation_score_basis_points: 680 -> 410"));
    assert!(stdout.contains("- revocation_status: active -> revoked"));
}
