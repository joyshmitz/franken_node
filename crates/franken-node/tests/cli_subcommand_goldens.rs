//! Golden tests for CLI subcommands lacking coverage.
//!
//! This test suite ensures CLI output stability for subcommands that
//! previously lacked golden pinning. Each test captures stdout/stderr
//! with comprehensive scrubbing for non-deterministic values.
//!
//! Note: These tests will fail on first run to create golden snapshots.
//! Run with UPDATE_GOLDENS=1 or `cargo insta review` to accept initial outputs.

use assert_cmd::Command;
use insta::assert_snapshot;
use std::fs;
use tempfile::TempDir;

#[path = "cli_golden_helpers.rs"]
mod cli_golden_helpers;

use cli_golden_helpers::{pretty_json_stdout, with_scrubbed_snapshot_settings};

/// Helper to run CLI commands that may fail gracefully.
fn run_cli_command_with_fallback(
    args: &[&str],
    expect_json: bool,
    command_name: &str,
) -> Result<String, String> {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = cmd.args(args).output().expect("command execution");

    if output.status.success() {
        if expect_json {
            Ok(pretty_json_stdout(command_name, &output.stdout))
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    } else {
        // Return stderr for failed commands
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

// === help commands (guaranteed to work) ===

#[test]
fn franken_node_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("cli", || {
        assert_snapshot!("franken_node_help", stdout);
    });
}

#[test]
fn trust_card_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["trust-card", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("trust_card_cli", || {
        assert_snapshot!("trust_card_help", stdout);
    });
}

#[test]
fn fleet_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["fleet", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("fleet_cli", || {
        assert_snapshot!("fleet_help", stdout);
    });
}

#[test]
fn doctor_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["doctor", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("doctor_cli", || {
        assert_snapshot!("doctor_help", stdout);
    });
}

#[test]
fn remotecap_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["remotecap", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("remotecap_cli", || {
        assert_snapshot!("remotecap_help", stdout);
    });
}

#[test]
fn verify_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["verify", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("verify_cli", || {
        assert_snapshot!("verify_help", stdout);
    });
}

#[test]
fn registry_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["registry", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("registry_cli", || {
        assert_snapshot!("registry_help", stdout);
    });
}

#[test]
fn incident_help_output() {
    let mut cmd = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = cmd.args(["incident", "--help"]).assert().success();

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    with_scrubbed_snapshot_settings("incident_cli", || {
        assert_snapshot!("incident_help", stdout);
    });
}
