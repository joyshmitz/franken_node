use assert_cmd::Command;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join("fixtures/policy_activation").join(name)
}

fn run_doctor_stderr_jsonl(args: &[String]) -> Vec<Value> {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let output = command
        .current_dir(repo_root())
        .args(args)
        .output()
        .expect("failed to run franken-node doctor");

    assert!(
        output.status.success(),
        "doctor command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("doctor stderr must be UTF-8");
    assert!(
        !stderr.trim().is_empty(),
        "doctor --structured-logs-jsonl must emit JSONL to stderr"
    );

    stderr
        .lines()
        .enumerate()
        .map(|(index, line)| {
            assert!(
                !line.trim().is_empty(),
                "stderr JSONL line {index} is blank"
            );
            serde_json::from_str::<Value>(line).unwrap_or_else(|error| {
                panic!("stderr line {index} must parse as JSON: {error}; line={line:?}")
            })
        })
        .collect()
}

fn assert_structured_log_schema(line: &Value) {
    let object = line
        .as_object()
        .unwrap_or_else(|| panic!("structured log line must be an object: {line}"));

    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from(["detail", "event", "severity", "ts"]),
        "structured log line must match schema {{ts,event,severity,detail}}: {line}"
    );

    assert!(
        object["ts"].as_str().is_some_and(|ts| !ts.is_empty()),
        "structured log ts must be a non-empty string: {line}"
    );
    assert!(
        object["event"]
            .as_str()
            .is_some_and(|event| !event.is_empty()),
        "structured log event must be a non-empty string: {line}"
    );
    assert!(
        matches!(
            object["severity"].as_str(),
            Some("debug" | "info" | "warn" | "error")
        ),
        "structured log severity must be canonical: {line}"
    );
    assert!(
        object["detail"].is_object(),
        "structured log detail must be an object: {line}"
    );
}

fn scenario_args(trace_id: &str, extra_args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut args = vec![
        "doctor".to_string(),
        "--structured-logs-jsonl".to_string(),
        "--trace-id".to_string(),
        trace_id.to_string(),
    ];
    args.extend(extra_args);
    args
}

#[test]
fn doctor_structured_logs_jsonl_emits_parseable_schema_events() {
    let policy_pass_fixture = fixture_path("doctor_policy_activation_pass.json");
    let missing_fixture = fixture_path("doctor_policy_activation_missing.json");

    assert!(
        policy_pass_fixture.is_file(),
        "policy activation pass fixture must exist"
    );
    assert!(
        !missing_fixture.exists(),
        "missing-fixture scenario requires absent fixture path"
    );

    let scenarios = [
        scenario_args(
            "doctor-structured-jsonl-policy-pass",
            [
                "--policy-activation-input".to_string(),
                policy_pass_fixture.display().to_string(),
            ],
        ),
        scenario_args(
            "doctor-structured-jsonl-missing-fixture",
            [
                "--policy-activation-input".to_string(),
                missing_fixture.display().to_string(),
            ],
        ),
        scenario_args(
            "doctor-structured-jsonl-strict-profile",
            ["--profile".to_string(), "strict".to_string()],
        ),
    ];

    let mut observed_events = BTreeSet::new();
    for args in scenarios {
        let log_lines = run_doctor_stderr_jsonl(&args);
        assert!(!log_lines.is_empty(), "scenario must emit JSONL logs");

        for line in log_lines {
            assert_structured_log_schema(&line);
            observed_events.insert(
                line["event"]
                    .as_str()
                    .expect("event checked by schema")
                    .to_string(),
            );
        }
    }

    for required_event in [
        "policy_activation_pass",
        "missing_fixture_fallback",
        "strict_profile_warning",
    ] {
        assert!(
            observed_events.contains(required_event),
            "missing structured log event {required_event}; observed={observed_events:?}"
        );
    }
}
