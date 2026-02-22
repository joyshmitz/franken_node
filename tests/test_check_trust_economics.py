"""Unit tests for scripts/check_trust_economics.py (bd-10c gate)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_trust_economics.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_trust_economics", SCRIPT)
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
    assert data["bead"] == "bd-10c"
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


def test_attack_categories(mod):
    name, ok, _ = mod.check_attack_categories()
    assert name == "attack_categories"
    assert ok is True


def test_three_way_comparison(mod):
    name, ok, _ = mod.check_three_way_comparison()
    assert name == "three_way_comparison"
    assert ok is True


def test_privilege_pricing(mod):
    name, ok, _ = mod.check_privilege_pricing()
    assert name == "privilege_pricing"
    assert ok is True


def test_policy_recommendations(mod):
    name, ok, _ = mod.check_policy_recommendations()
    assert name == "policy_recommendations"
    assert ok is True


def test_expected_loss_model(mod):
    name, ok, _ = mod.check_expected_loss_model()
    assert name == "expected_loss_model"
    assert ok is True


def test_event_codes(mod):
    name, ok, _ = mod.check_event_codes()
    assert name == "event_codes"
    assert ok is True


def test_invariants(mod):
    name, ok, _ = mod.check_invariants()
    assert name == "invariants"
    assert ok is True


def test_confidence_versioning(mod):
    name, ok, _ = mod.check_confidence_versioning()
    assert name == "confidence_versioning"
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
