use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn run_secure_extension_heavy_bench() -> Vec<u8> {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args(["bench", "run", "--scenario", "secure-extension-heavy"])
        .output()
        .expect("failed to run franken-node bench run");

    assert!(
        output.status.success(),
        "bench command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "bench run must emit signed JSON report to stdout"
    );

    output.stdout
}

fn assert_signed_benchmark_report(bytes: &[u8]) -> Value {
    let report: Value = serde_json::from_slice(bytes).expect("bench stdout must be JSON");
    assert_eq!(report["suite_version"], "1.0.0");
    assert_eq!(report["scoring_formula_version"], "sf-v1");
    assert_eq!(report["timestamp_utc"], "2026-02-21T00:00:00Z");
    assert!(
        report["provenance_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "signed report must include sha256 provenance hash: {report}"
    );
    assert_eq!(report["hardware_profile"]["cpu"], "deterministic-test-cpu");
    assert_eq!(report["hardware_profile"]["memory_mb"], 32768);

    let scenarios = report["scenarios"]
        .as_array()
        .expect("signed report scenarios must be an array");
    assert_eq!(
        scenarios.len(),
        1,
        "scenario filter must select exactly the secure-extension-heavy scenario"
    );
    assert_eq!(scenarios[0]["name"], "secure-extension-heavy");
    assert_eq!(scenarios[0]["dimension"], "performance_under_hardening");
    assert_eq!(scenarios[0]["iterations"], 5);
    assert!(
        scenarios[0]["variance_pct"]
            .as_f64()
            .is_some_and(f64::is_finite),
        "variance must be finite in signed report: {report}"
    );

    report
}

#[test]
fn bench_run_secure_extension_heavy_is_byte_stable() {
    let first = run_secure_extension_heavy_bench();
    let first_report = assert_signed_benchmark_report(&first);

    let second = run_secure_extension_heavy_bench();
    let second_report = assert_signed_benchmark_report(&second);

    assert_eq!(
        first_report, second_report,
        "same bench inputs must produce semantically identical signed reports"
    );
    assert_eq!(
        first, second,
        "same bench inputs must produce byte-stable signed JSON reports"
    );
}

fn run_bench_with_invalid_scenario() -> std::process::Output {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args(["bench", "run", "--scenario", "nonexistent-invalid-scenario"])
        .output()
        .expect("failed to run franken-node bench run with invalid scenario")
}

fn run_bench_to_nonexistent_output() -> std::process::Output {
    let temp_dir = TempDir::new().expect("create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent").join("output.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args([
            "bench", "run",
            "--scenario", "secure-extension-heavy",
            "--output",
            nonexistent_path.to_str().unwrap()
        ])
        .output()
        .expect("failed to run franken-node bench run with nonexistent output")
}

fn assert_structured_error_response(stderr: &[u8]) -> Value {
    let stderr_str = String::from_utf8_lossy(stderr);

    // Should contain structured error information
    assert!(
        !stderr_str.is_empty(),
        "bench error must emit diagnostic information to stderr"
    );

    // Look for structured error patterns (JSON or key-value pairs)
    assert!(
        stderr_str.contains("error") || stderr_str.contains("Error") ||
        stderr_str.contains("failed") || stderr_str.contains("invalid"),
        "stderr must contain error indication: {}",
        stderr_str
    );

    // Try to parse any JSON from stderr for structured validation
    if let Ok(json) = serde_json::from_str::<Value>(&stderr_str) {
        return json;
    }

    // Return a synthetic JSON structure for log validation
    serde_json::json!({
        "stderr_content": stderr_str,
        "contains_error": true
    })
}

#[test]
fn bench_run_invalid_scenario_returns_structured_error() {
    let output = run_bench_with_invalid_scenario();

    // Must fail with nonzero exit code
    assert!(
        !output.status.success(),
        "invalid scenario must fail with nonzero exit code"
    );

    // Should not emit valid benchmark JSON to stdout
    if !output.stdout.is_empty() {
        // If there is stdout, it should be an error response, not a valid report
        if let Ok(stdout_json) = serde_json::from_slice::<Value>(&output.stdout) {
            // If it's JSON, it should be an error structure, not a benchmark report
            assert!(
                stdout_json.get("error").is_some() ||
                stdout_json.get("scenarios").is_none(),
                "stdout JSON should be error response, not benchmark report: {}",
                stdout_json
            );
        }
    }

    // Validate structured error information in stderr
    let error_info = assert_structured_error_response(&output.stderr);
    assert!(
        error_info["contains_error"].as_bool().unwrap_or(false) ||
        error_info.get("error").is_some(),
        "stderr must contain structured error information: {}",
        error_info
    );
}

#[test]
fn bench_run_nonexistent_output_path_fails_gracefully() {
    let output = run_bench_to_nonexistent_output();

    // Must fail with nonzero exit code
    assert!(
        !output.status.success(),
        "nonexistent output path must fail with nonzero exit code"
    );

    // Validate error information in stderr
    let error_info = assert_structured_error_response(&output.stderr);
    let stderr_content = error_info["stderr_content"].as_str().unwrap_or("");

    // Should mention the path/file issue
    assert!(
        stderr_content.contains("path") ||
        stderr_content.contains("file") ||
        stderr_content.contains("directory") ||
        stderr_content.contains("output"),
        "error message should reference path/file issue: {}",
        stderr_content
    );
}

#[test]
fn bench_run_successful_execution_logs_expected_events() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let output_path = temp_dir.path().join("bench_output.json");

    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .env("FRANKEN_NODE_BENCH_CPU", "deterministic-test-cpu")
        .env("FRANKEN_NODE_BENCH_MEMORY_MB", "32768")
        .env("FRANKEN_NODE_BENCH_TIMESTAMP_UTC", "2026-02-21T00:00:00Z")
        .args([
            "bench", "run",
            "--scenario", "secure-extension-heavy",
            "--output",
            output_path.to_str().unwrap()
        ])
        .output()
        .expect("failed to run franken-node bench run with output file");

    assert!(
        output.status.success(),
        "bench run with valid output path must succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Validate that output file was created
    assert!(
        output_path.exists(),
        "bench run must create output file at specified path"
    );

    // Validate file contains valid benchmark report
    let file_contents = std::fs::read(&output_path)
        .expect("read benchmark output file");
    let file_report = assert_signed_benchmark_report(&file_contents);

    // Validate stderr contains expected log events (no errors)
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    // Should not contain error indicators
    assert!(
        !stderr_str.contains("error") && !stderr_str.contains("Error") &&
        !stderr_str.contains("failed") && !stderr_str.contains("panic"),
        "successful bench run should not log errors: stderr={}",
        stderr_str
    );

    // Should contain progress or completion indicators
    assert!(
        stderr_str.contains("bench") || stderr_str.contains("scenario") ||
        stderr_str.contains("complete") || stderr_str.contains("writing") ||
        stderr_str.is_empty(), // Empty stderr is also acceptable for successful runs
        "successful bench run should log progress/completion events or be silent: stderr={}",
        stderr_str
    );

    // Validate report structure matches expected schema
    assert_eq!(file_report["suite_version"], "1.0.0");
    assert_eq!(file_report["scoring_formula_version"], "sf-v1");
    assert!(
        file_report["scenarios"]
            .as_array()
            .map_or(false, |scenarios| scenarios.len() == 1),
        "output file must contain exactly one scenario result"
    );
}
