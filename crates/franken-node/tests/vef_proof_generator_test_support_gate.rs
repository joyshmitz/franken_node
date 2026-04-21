use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn write_probe_crate(
    root: &Path,
    crate_name: &str,
    target_dir: &Path,
    package_dependency: &str,
    source: &str,
) -> PathBuf {
    let crate_dir = root.join(crate_name);
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create probe src directory");
    let dependency_clause = if package_dependency.is_empty() {
        format!("path = {:?}", env!("CARGO_MANIFEST_DIR"))
    } else {
        format!(
            "path = {:?}, {}",
            env!("CARGO_MANIFEST_DIR"),
            package_dependency
        )
    };
    fs::write(
        crate_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"vef-proof-generator-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nfrankenengine-node = {{ {} }}\n",
            dependency_clause,
        ),
    )
    .expect("write probe Cargo.toml");
    fs::write(src_dir.join("main.rs"), source).expect("write probe main.rs");
    target_dir.to_path_buf()
}

fn cargo_check(crate_dir: &Path, target_dir: &Path) -> Output {
    Command::new("cargo")
        .arg("check")
        .arg("--quiet")
        .current_dir(crate_dir)
        .env("CARGO_TARGET_DIR", target_dir)
        .output()
        .expect("run cargo check for probe crate")
}

#[test]
fn test_proof_backend_requires_test_support_feature() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let target_dir = temp_dir.path().join("target");
    let source = r#"
use frankenengine_node::vef::proof_generator::TestProofBackend;

fn main() {
    let _ = TestProofBackend::new();
}
"#;

    let production_target =
        write_probe_crate(temp_dir.path(), "probe-production", &target_dir, "", source);
    let production_output = cargo_check(
        &temp_dir.path().join("probe-production"),
        &production_target,
    );
    assert!(
        !production_output.status.success(),
        "production surface should not expose TestProofBackend"
    );
    let production_stderr = String::from_utf8_lossy(&production_output.stderr);
    assert!(
        production_stderr.contains("TestProofBackend"),
        "unexpected compile failure: {production_stderr}"
    );

    let feature_target = write_probe_crate(
        temp_dir.path(),
        "probe-feature",
        &target_dir,
        "features = [\"test-support\"]",
        source,
    );
    let feature_output = cargo_check(&temp_dir.path().join("probe-feature"), &feature_target);
    assert!(
        feature_output.status.success(),
        "test-support feature should expose TestProofBackend: {}",
        String::from_utf8_lossy(&feature_output.stderr)
    );
}
