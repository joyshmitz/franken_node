use assert_cmd::Command;
use insta::{Settings, assert_snapshot};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/migrate")
        .join(name)
}

fn validate_fixture_json(fixture: &str, expect_success: bool) -> String {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = command
        .args([
            "migrate",
            "validate",
            fixture_path(fixture).to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
        ])
        .assert();

    let assertion = if expect_success {
        assertion.success()
    } else {
        assertion.failure()
    };

    let stdout = &assertion.get_output().stdout;
    let value: Value = serde_json::from_slice(stdout).unwrap_or_else(|err| {
        panic!(
            "migrate validate stdout should be JSON: {err}\n{}",
            String::from_utf8_lossy(stdout)
        )
    });

    serde_json::to_string_pretty(&value).expect("pretty json")
}

fn assert_migrate_validate_snapshot(name: &str, stdout_json: &str) {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_path(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens/migrate_validate"),
    );
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.add_filter(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "[UUID]",
    );
    settings.add_filter(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?",
        "[TIMESTAMP]",
    );
    settings.add_filter(r"/[A-Za-z0-9_./-]+", "[PATH]");
    settings.bind(|| {
        assert_snapshot!(name, stdout_json);
    });
}

#[test]
fn migrate_validate_risky_fixture_json_matches_golden() {
    let stdout_json = validate_fixture_json("risky", false);
    assert_migrate_validate_snapshot("risky", &stdout_json);
}

#[test]
fn migrate_validate_hardened_fixture_json_matches_golden() {
    let stdout_json = validate_fixture_json("hardened", true);
    assert_migrate_validate_snapshot("hardened", &stdout_json);
}
