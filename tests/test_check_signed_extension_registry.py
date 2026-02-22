"""Unit tests for scripts/check_signed_extension_registry.py (bd-209w gate)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_signed_extension_registry.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_signed_extension_registry", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load_module()


@pytest.fixture(scope="module")
def results(mod):
    return mod.run_all()


# --- Self-test ---

def test_self_test(mod):
    assert mod.self_test() is True


# --- JSON output ---

def test_json_output():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["bead_id"] == "bd-209w"
    assert data["verdict"] == "PASS"
    assert isinstance(data["checks"], list)


# --- Individual checks ---

def test_source_exists(mod):
    name, ok, _ = mod.check_source_exists()
    assert name == "source_exists"
    assert ok is True


def test_module_wiring(mod):
    name, ok, _ = mod.check_module_wiring()
    assert name == "module_wiring"
    assert ok is True


def test_structs(mod):
    name, ok, _ = mod.check_structs()
    assert name == "structs"
    assert ok is True


def test_extension_statuses(mod):
    name, ok, _ = mod.check_extension_statuses()
    assert name == "extension_statuses"
    assert ok is True


def test_revocation_reasons(mod):
    name, ok, _ = mod.check_revocation_reasons()
    assert name == "revocation_reasons"
    assert ok is True


def test_registry_operations(mod):
    name, ok, _ = mod.check_registry_operations()
    assert name == "registry_operations"
    assert ok is True


def test_signature_verification(mod):
    name, ok, _ = mod.check_signature_verification()
    assert name == "signature_verification"
    assert ok is True


def test_provenance_validation(mod):
    name, ok, _ = mod.check_provenance_validation()
    assert name == "provenance_validation"
    assert ok is True


def test_monotonic_revocation(mod):
    name, ok, _ = mod.check_monotonic_revocation()
    assert name == "monotonic_revocation"
    assert ok is True


def test_event_codes(mod):
    name, ok, _ = mod.check_event_codes()
    assert name == "event_codes"
    assert ok is True


def test_invariants(mod):
    name, ok, _ = mod.check_invariants()
    assert name == "invariants"
    assert ok is True


def test_content_hash(mod):
    name, ok, _ = mod.check_content_hash()
    assert name == "content_hash"
    assert ok is True


def test_audit_logging(mod):
    name, ok, _ = mod.check_audit_logging()
    assert name == "audit_logging"
    assert ok is True


def test_spec_alignment(mod):
    name, ok, _ = mod.check_spec_alignment()
    assert name == "spec_alignment"
    assert ok is True


def test_test_coverage(mod):
    name, ok, _ = mod.check_test_coverage()
    assert name == "test_coverage"
    assert ok is True


# --- Overall ---

def test_all_checks_pass(results):
    for r in results:
        assert r["passed"] is True, f"{r['check']}: {r['detail']}"


def test_verdict_is_pass(results):
    assert all(r["passed"] for r in results)


# --- Human output ---

def test_human_output():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PASS" in result.stdout
