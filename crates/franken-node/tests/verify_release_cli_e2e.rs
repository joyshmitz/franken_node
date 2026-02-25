use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::supply_chain::artifact_signing::{
    build_and_sign_manifest, demo_signing_key, demo_signing_key_2, sign_artifact,
};
use tempfile::TempDir;

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

fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed creating {}: {err}", parent.display()));
    }
}

fn write_signed_release_fixture(release_dir: &Path, artifacts: &[(&str, &[u8])]) {
    let signing_key = demo_signing_key();
    let manifest = build_and_sign_manifest(artifacts, &signing_key);

    for (name, bytes) in artifacts {
        let artifact_path = release_dir.join(name);
        ensure_parent_dir(&artifact_path);
        std::fs::write(&artifact_path, bytes)
            .unwrap_or_else(|err| panic!("failed writing {}: {err}", artifact_path.display()));

        let signature = sign_artifact(&signing_key, bytes);
        let signature_path = release_dir.join(format!("{name}.sig"));
        ensure_parent_dir(&signature_path);
        std::fs::write(&signature_path, hex::encode(signature))
            .unwrap_or_else(|err| panic!("failed writing {}: {err}", signature_path.display()));
    }

    let manifest_path = release_dir.join("SHA256SUMS");
    std::fs::write(&manifest_path, manifest.canonical_bytes())
        .unwrap_or_else(|err| panic!("failed writing {}: {err}", manifest_path.display()));

    let manifest_signature_path = release_dir.join("SHA256SUMS.sig");
    std::fs::write(&manifest_signature_path, hex::encode(manifest.signature)).unwrap_or_else(
        |err| {
            panic!(
                "failed writing {}: {err}",
                manifest_signature_path.display()
            )
        },
    );
}

fn parse_json_stdout(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "expected JSON on stdout, got empty output; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("invalid JSON output: {err}\nstdout:\n{stdout}"))
}

#[test]
fn verify_release_succeeds_with_hex_encoded_signatures_and_key_dir() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    let artifacts = [
        (
            "franken-node-linux-x64.tar.xz",
            b"artifact-linux-x64" as &[u8],
        ),
        (
            "franken-node-darwin-arm64.tar.xz",
            b"artifact-darwin-arm64" as &[u8],
        ),
    ];
    write_signed_release_fixture(&release_dir, &artifacts);

    let wrong_key = demo_signing_key_2();
    std::fs::write(
        key_dir.join("00-rotated.pub"),
        hex::encode(wrong_key.verifying_key().as_bytes()),
    )
    .expect("write rotated key");
    let correct_key = demo_signing_key();
    std::fs::write(
        key_dir.join("10-current.pub"),
        hex::encode(correct_key.verifying_key().as_bytes()),
    )
    .expect("write current key");
    std::fs::write(key_dir.join("README.txt"), "non-key metadata").expect("write non-key file");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        output.status.success(),
        "verify release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(
        payload["manifest_signature_ok"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(payload["overall_pass"], serde_json::Value::Bool(true));
    let results = payload["results"].as_array().expect("results array");
    assert_eq!(results.len(), artifacts.len());
    assert!(
        results
            .iter()
            .all(|row| row["passed"] == serde_json::Value::Bool(true))
    );
}

#[test]
fn verify_release_fails_when_unlisted_artifact_exists() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    std::fs::write(release_dir.join("rogue-extra.bin"), b"rogue payload")
        .expect("write rogue artifact");

    let release_arg = release_dir.to_string_lossy().to_string();
    let output = run_cli(&["verify", "release", &release_arg, "--json"]);
    assert!(
        !output.status.success(),
        "expected verify release failure for unlisted artifact"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(
        payload["manifest_signature_ok"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(payload["overall_pass"], serde_json::Value::Bool(false));

    let results = payload["results"].as_array().expect("results array");
    let rogue_entry = results
        .iter()
        .find(|row| {
            row["artifact_name"] == serde_json::Value::String("rogue-extra.bin".to_string())
        })
        .expect("rogue artifact result entry");
    assert_eq!(rogue_entry["passed"], serde_json::Value::Bool(false));
    assert!(
        rogue_entry["failure_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("not listed")
    );
}

#[test]
fn verify_release_fails_with_invalid_key_directory() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    std::fs::write(key_dir.join("README.txt"), "this is not an Ed25519 key")
        .expect("write invalid key file");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "expected verify release failure with invalid key directory"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no usable Ed25519 public keys found"));
}
