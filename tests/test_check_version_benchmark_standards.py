"""Unit tests for scripts/check_version_benchmark_standards.py (bd-3v8g gate)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_version_benchmark_standards.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_vbs", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load_module()


@pytest.fixture(scope="module")
def results(mod):
    return mod.run_all()


def test_self_test(mod):
    assert mod.self_test() is True


def test_json_output():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["bead"] == "bd-3v8g"
    assert data["verdict"] == "PASS"
    assert isinstance(data["checks"], list)


def test_source_exists(mod):
    _, ok, _ = mod.check_source_exists()
    assert ok is True


def test_module_wiring(mod):
    _, ok, _ = mod.check_module_wiring()
    assert ok is True


def test_structs(mod):
    _, ok, _ = mod.check_structs()
    assert ok is True


def test_semver(mod):
    _, ok, _ = mod.check_semver()
    assert ok is True


def test_compatibility_levels(mod):
    _, ok, _ = mod.check_compatibility_levels()
    assert ok is True


def test_migration_pipeline(mod):
    _, ok, _ = mod.check_migration_pipeline()
    assert ok is True


def test_change_types(mod):
    _, ok, _ = mod.check_change_types()
    assert ok is True


def test_effort_levels(mod):
    _, ok, _ = mod.check_effort_levels()
    assert ok is True


def test_event_codes(mod):
    _, ok, _ = mod.check_event_codes()
    assert ok is True


def test_invariants(mod):
    _, ok, _ = mod.check_invariants()
    assert ok is True


def test_spec_alignment(mod):
    _, ok, _ = mod.check_spec_alignment()
    assert ok is True


def test_audit_logging(mod):
    _, ok, _ = mod.check_audit_logging()
    assert ok is True


def test_test_coverage(mod):
    _, ok, _ = mod.check_test_coverage()
    assert ok is True


def test_all_checks_pass(results):
    for r in results:
        assert r["passed"] is True, f"{r['check']}: {r['detail']}"


def test_verdict_is_pass(results):
    assert all(r["passed"] for r in results)


def test_human_output():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PASS" in result.stdout
