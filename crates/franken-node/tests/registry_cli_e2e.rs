use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::supply_chain::artifact_signing::KeyId;

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

fn run_cli_in_workspace(workspace: &Path, args: &[&str]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn registry_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("plugin.fnext"), b"dummy extension payload").expect("write package");
    dir
}

fn write_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write signing key");
}

#[test]
fn registry_publish_requires_explicit_signing_key() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["registry", "publish", "plugin.fnext"]);
    assert!(
        !output.status.success(),
        "registry publish should fail when signing key is omitted"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--signing-key"));
}

#[test]
fn registry_publish_succeeds_with_operator_managed_signing_key() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();
    let expected_key_id = KeyId::from_verifying_key(
        &ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]).verifying_key(),
    )
    .to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("registry publish: extension_id="));
    assert!(stdout.contains(&format!("publisher_key_id={expected_key_id}")));
    assert!(stdout.contains("signing_key_source=cli"));
    assert!(stdout.contains(&format!("signing_key_path={signing_key_arg}")));
}

#[test]
fn registry_publish_rejects_invalid_signing_key_material() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/invalid.ed25519");
    fs::create_dir_all(signing_key_path.parent().expect("key parent")).expect("create key dir");
    fs::write(&signing_key_path, "not-a-valid-key").expect("write invalid key");
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        !output.status.success(),
        "registry publish should fail on invalid signing key material"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed decoding Ed25519 registry publish signing key"));
}
