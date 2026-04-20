use assert_cmd::Command;
use serde_json::Value;
use std::path::{Path, PathBuf};

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
