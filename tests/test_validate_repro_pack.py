"""Tests for scripts/validate_repro_pack.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from validate_repro_pack import validate_env, validate_manifest, validate_lock


# ── validate_env ──────────────────────────────────────────────


def test_valid_env():
    data = {
        "schema_version": "1.0",
        "timestamp": "2025-01-15T12:00:00+00:00",
        "hostname": "host",
        "os": "Linux",
        "arch": "x86_64",
        "rust_toolchain": {"version": "nightly", "edition": "2024"},
    }
    assert validate_env(data) == []


def test_env_missing_fields():
    errors = validate_env({})
    assert any("missing required field 'schema_version'" in e for e in errors)
    assert any("missing required field 'hostname'" in e for e in errors)


def test_env_bad_schema_version():
    data = {
        "schema_version": "2.0",
        "timestamp": "t",
        "hostname": "h",
        "os": "o",
        "arch": "a",
        "rust_toolchain": {"version": "v", "edition": "e"},
    }
    errors = validate_env(data)
    assert any("schema_version must be '1.0'" in e for e in errors)


def test_env_rust_toolchain_not_object():
    data = {
        "schema_version": "1.0",
        "timestamp": "t",
        "hostname": "h",
        "os": "o",
        "arch": "a",
        "rust_toolchain": "nightly",
    }
    errors = validate_env(data)
    assert any("rust_toolchain must be an object" in e for e in errors)


def test_env_rust_toolchain_missing_subfield():
    data = {
        "schema_version": "1.0",
        "timestamp": "t",
        "hostname": "h",
        "os": "o",
        "arch": "a",
        "rust_toolchain": {"version": "nightly"},
    }
    errors = validate_env(data)
    assert any("rust_toolchain missing 'edition'" in e for e in errors)


# ── validate_manifest ────────────────────────────────────────


def test_valid_manifest():
    data = {
        "schema_version": "1.0",
        "bead_id": "bd-test",
        "artifact_type": "verification_evidence",
        "timestamp": "2025-01-15T12:00:00+00:00",
        "commands": [{"command": "echo test", "exit_code": 0}],
        "outputs": [{"path": "out.json", "sha256": "a" * 64}],
    }
    assert validate_manifest(data) == []


def test_manifest_missing_fields():
    errors = validate_manifest({})
    assert any("missing required field 'bead_id'" in e for e in errors)
    assert any("missing required field 'commands'" in e for e in errors)


def test_manifest_bad_command():
    data = {
        "schema_version": "1.0",
        "bead_id": "bd-test",
        "artifact_type": "verification_evidence",
        "timestamp": "t",
        "commands": [{"exit_code": 0}],
        "outputs": [],
    }
    errors = validate_manifest(data)
    assert any("commands[0] missing 'command'" in e for e in errors)


def test_manifest_bad_sha256():
    data = {
        "schema_version": "1.0",
        "bead_id": "bd-test",
        "artifact_type": "verification_evidence",
        "timestamp": "t",
        "commands": [],
        "outputs": [{"path": "f.json", "sha256": "not-a-hash"}],
    }
    errors = validate_manifest(data)
    assert any("invalid SHA-256" in e for e in errors)


# ── validate_lock ────────────────────────────────────────────


def test_valid_lock():
    data = {
        "schema_version": "1.0",
        "timestamp": "2025-01-15T12:00:00+00:00",
        "git_commit": "a" * 40,
        "cargo_lock_sha256": "b" * 64,
    }
    assert validate_lock(data) == []


def test_lock_missing_fields():
    errors = validate_lock({})
    assert any("missing required field 'git_commit'" in e for e in errors)


def test_lock_bad_git_commit():
    data = {
        "schema_version": "1.0",
        "timestamp": "t",
        "git_commit": "too-short",
        "cargo_lock_sha256": "b" * 64,
    }
    errors = validate_lock(data)
    assert any("git_commit must be 40-char hex" in e for e in errors)


def test_lock_bad_cargo_sha():
    data = {
        "schema_version": "1.0",
        "timestamp": "t",
        "git_commit": "a" * 40,
        "cargo_lock_sha256": "xyz",
    }
    errors = validate_lock(data)
    assert any("cargo_lock_sha256 must be 64-char hex" in e for e in errors)
