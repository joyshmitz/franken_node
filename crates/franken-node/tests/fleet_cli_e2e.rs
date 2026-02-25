use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_frankenengine-node")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_franken-node"))
    {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/frankenengine-node")
}

fn run_cli(args: &[&str]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "frankenengine-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
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
    assert!(stdout.contains("activated=false"));
    assert!(stdout.contains("pending_convergences=0"));
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
fn fleet_release_executes_and_reports_operation() {
    let output = run_cli(&["fleet", "release", "--incident", "inc-demo-123"]);
    assert!(
        output.status.success(),
        "fleet release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fleet action: type=release"));
    assert!(stdout.contains("success=true"));
    assert!(stdout.contains("event_code=FLEET-004"));
}
