#!/usr/bin/env python3
"""Unit tests for scripts/check_substrate_gate.py (bd-3u2o).

Comprehensive test suite covering self-test, JSON output, manifest schema
validation, waiver registry validation, gate report schema validation,
substrate coverage checks, event code presence, and edge cases.
"""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_substrate_gate.py"

# ---------------------------------------------------------------------------
# Dynamic import of the checker module
# ---------------------------------------------------------------------------

spec = importlib.util.spec_from_file_location(
    "check_substrate_gate",
    SCRIPT,
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader is not None
spec.loader.exec_module(mod)


# ---- Fixtures --------------------------------------------------------------


@pytest.fixture()
def valid_manifest():
    """A minimal valid substrate policy manifest with all 4 substrates."""
    return {
        "schema_version": "1.0.0",
        "policy_id": "test-policy",
        "module_root": "crates/franken-node/src",
        "classification_mode": "first_match",
        "substrates": [
            {
                "name": "frankentui",
                "version": "^0.1.0",
                "plane": "presentation",
                "mandatory_modules": ["crates/franken-node/src/cli.rs"],
                "should_use_modules": ["crates/franken-node/src/main.rs"],
                "optional_modules": ["crates/franken-node/src/**"],
            },
            {
                "name": "frankensqlite",
                "version": "^0.1.0",
                "plane": "persistence",
                "mandatory_modules": ["crates/franken-node/src/connector/**"],
                "should_use_modules": ["crates/franken-node/src/runtime/**"],
                "optional_modules": ["crates/franken-node/src/**"],
            },
            {
                "name": "sqlmodel_rust",
                "version": "^0.1.0",
                "plane": "model",
                "mandatory_modules": ["crates/franken-node/src/config.rs"],
                "should_use_modules": ["crates/franken-node/src/connector/**"],
                "optional_modules": ["crates/franken-node/src/**"],
            },
            {
                "name": "fastapi_rust",
                "version": "^0.1.0",
                "plane": "service",
                "mandatory_modules": ["crates/franken-node/src/api/**"],
                "should_use_modules": ["crates/franken-node/src/main.rs"],
                "optional_modules": ["crates/franken-node/src/**"],
            },
        ],
        "exceptions": [],
        "metadata": {
            "schema_version": "1.0.0",
            "created_at": "2026-02-22T00:00:00Z",
            "policy_hash": "sha256:abc123",
        },
    }


@pytest.fixture()
def valid_waiver_registry():
    """A minimal valid waiver registry (empty waivers)."""
    return {
        "schema_version": "1.0.0",
        "max_waiver_duration_days": 90,
        "waivers": [],
    }


@pytest.fixture()
def valid_gate_report():
    """A minimal valid gate report with one passing check."""
    return {
        "schema_version": "1.0.0",
        "bead_id": "bd-3u2o",
        "section": "10.16",
        "title": "Adjacent substrate conformance gate",
        "generated_at": "2026-02-22T00:00:00Z",
        "policy_manifest": "artifacts/10.16/adjacent_substrate_policy_manifest.json",
        "waiver_registry": "artifacts/10.16/waiver_registry.json",
        "changed_modules": ["crates/franken-node/src/cli.rs"],
        "checks": [
            {
                "module": "crates/franken-node/src/cli.rs",
                "substrate": "frankentui",
                "rule": "adjacent-substrate.mandatory.frankentui.raw-output",
                "status": "pass",
                "remediation_hint": "",
                "waiver_id": "",
            },
        ],
        "summary": {"total_checks": 1, "passed": 1, "failed": 0, "waived": 0},
        "gate_verdict": "pass",
        "events": [
            {"code": "SUBSTRATE_GATE_START", "detail": "evaluating 1 changed modules"},
            {"code": "SUBSTRATE_GATE_PASS", "detail": "gate_verdict=pass"},
        ],
    }


# ===========================================================================
# 1. test_self_test
# ===========================================================================


class TestSelfTest:
    """Verify the self_test() entry point."""

    def test_self_test(self):
        """self_test() must return True (exit-code-0 semantics)."""
        result = mod.self_test()
        assert result is True


# ===========================================================================
# 2. test_gate_script_exists
# ===========================================================================


class TestGateScriptExists:
    """Verify the gate script file is present on disk."""

    def test_gate_script_exists(self):
        assert SCRIPT.is_file(), f"expected gate script at {SCRIPT}"

    def test_gate_script_is_python(self):
        text = SCRIPT.read_text(encoding="utf-8")
        assert "python" in text[:120].lower()


# ===========================================================================
# 3. test_json_output
# ===========================================================================


class TestJsonOutput:
    """Verify the --json CLI flag produces valid, parseable JSON."""

    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--build-report", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-3u2o"
        assert data["section"] == "10.16"
        assert "verdict" in data
        assert "checks" in data
        assert isinstance(data["checks"], list)

    def test_json_serializable_roundtrip(self):
        report = mod.build_gate_report(["crates/franken-node/src/cli.rs"])
        validation = mod.validate_gate_report(report)
        blob = json.dumps(validation, indent=2)
        parsed = json.loads(blob)
        assert parsed["bead_id"] == "bd-3u2o"

    def test_json_all_required_fields(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--build-report", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        for key in ("bead_id", "section", "title", "checks", "verdict", "total", "passed", "failed"):
            assert key in data, f"missing required field: {key}"


# ===========================================================================
# 4. test_manifest_schema_valid
# ===========================================================================


class TestManifestSchemaValid:
    """Validate that a valid manifest produces a passing gate report.

    The script validates manifests internally via build_gate_report. We test
    schema validation by building a report with a mock valid manifest and
    verifying the resulting report passes validate_gate_report.
    """

    def test_manifest_schema_valid(self, valid_manifest, tmp_path):
        """A valid manifest written to disk should produce a passing build."""
        fake_root = tmp_path / "repo"
        fake_root.mkdir()
        manifest_path = fake_root / "manifest.json"
        manifest_path.write_text(json.dumps(valid_manifest), encoding="utf-8")
        waiver_path = fake_root / "waiver_registry.json"
        waiver_path.write_text(json.dumps({"schema_version": "1.0.0", "waivers": []}), encoding="utf-8")
        with mock.patch.object(mod, "MANIFEST_PATH", manifest_path), \
             mock.patch.object(mod, "WAIVER_REGISTRY_PATH", waiver_path), \
             mock.patch.object(mod, "ROOT", fake_root):
            report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "pass"
        validation = mod.validate_gate_report(report)
        failing = [c for c in validation["checks"] if not c["pass"]]
        assert len(failing) == 0, f"valid manifest unexpectedly failed: {failing}"

    def test_four_substrates_in_fixture(self, valid_manifest):
        names = {s["name"] for s in valid_manifest["substrates"]}
        assert names == {"frankentui", "frankensqlite", "sqlmodel_rust", "fastapi_rust"}

    def test_real_manifest_valid(self):
        """The on-disk manifest must produce a loadable, non-None result."""
        manifest = mod._load_json(mod.MANIFEST_PATH)
        if manifest is None:
            pytest.skip("manifest not present on disk")
        assert isinstance(manifest.get("substrates"), list)
        assert len(manifest["substrates"]) >= 4
        assert manifest.get("classification_mode") == "first_match"


# ===========================================================================
# 5. test_manifest_schema_invalid
# ===========================================================================


class TestManifestSchemaInvalid:
    """Verify that invalid manifests cause build_gate_report to fail."""

    def test_manifest_schema_invalid_missing_file(self, tmp_path):
        """A missing manifest file should produce a fail gate verdict."""
        with mock.patch.object(mod, "MANIFEST_PATH", tmp_path / "nope.json"):
            report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "fail"

    def test_manifest_schema_invalid_bad_json(self, tmp_path):
        """Unparseable JSON in manifest should produce a fail gate verdict."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")
        with mock.patch.object(mod, "MANIFEST_PATH", bad_file):
            report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "fail"

    def test_manifest_schema_invalid_non_dict(self, tmp_path):
        """A manifest that is a JSON array should produce a fail gate verdict."""
        list_file = tmp_path / "list.json"
        list_file.write_text("[1,2,3]", encoding="utf-8")
        with mock.patch.object(mod, "MANIFEST_PATH", list_file):
            report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "fail"

    def test_manifest_empty_substrates_no_substrate_checks(self, valid_manifest, tmp_path):
        """A manifest with empty substrates produces no substrate rule checks."""
        fake_root = tmp_path / "repo"
        fake_root.mkdir()
        bad = copy.deepcopy(valid_manifest)
        bad["substrates"] = []
        manifest_path = fake_root / "empty_substrates.json"
        manifest_path.write_text(json.dumps(bad), encoding="utf-8")
        waiver_path = fake_root / "waiver_registry.json"
        waiver_path.write_text(json.dumps({"schema_version": "1.0.0", "waivers": []}), encoding="utf-8")
        with mock.patch.object(mod, "MANIFEST_PATH", manifest_path), \
             mock.patch.object(mod, "WAIVER_REGISTRY_PATH", waiver_path), \
             mock.patch.object(mod, "ROOT", fake_root):
            # Use no changed modules so no module-existence checks fire either
            report = mod.build_gate_report(changed_modules=[])
        # With no substrates and no changed modules, zero checks and pass
        assert report["summary"]["total_checks"] == 0
        assert report["gate_verdict"] == "pass"

    def test_manifest_missing_classification_mode(self, valid_manifest, tmp_path):
        """A manifest missing classification_mode is still loadable but may produce
        unexpected classification behavior."""
        fake_root = tmp_path / "repo"
        fake_root.mkdir()
        bad = copy.deepcopy(valid_manifest)
        del bad["classification_mode"]
        manifest_path = fake_root / "no_class_mode.json"
        manifest_path.write_text(json.dumps(bad), encoding="utf-8")
        waiver_path = fake_root / "waiver_registry.json"
        waiver_path.write_text(json.dumps({"schema_version": "1.0.0", "waivers": []}), encoding="utf-8")
        with mock.patch.object(mod, "MANIFEST_PATH", manifest_path), \
             mock.patch.object(mod, "WAIVER_REGISTRY_PATH", waiver_path), \
             mock.patch.object(mod, "ROOT", fake_root):
            report = mod.build_gate_report(changed_modules=[])
        # Should still produce a report (not crash)
        assert isinstance(report, dict)
        assert "gate_verdict" in report


# ===========================================================================
# 6. test_waiver_registry_present
# ===========================================================================


class TestWaiverRegistryPresent:
    """Verify the waiver registry file exists and is well-formed."""

    def test_waiver_registry_present(self):
        assert mod.WAIVER_REGISTRY_PATH.is_file(), (
            f"waiver registry missing at {mod.WAIVER_REGISTRY_PATH}"
        )

    def test_waiver_registry_valid_json(self):
        payload = mod._load_json(mod.WAIVER_REGISTRY_PATH)
        assert payload is not None, "waiver registry is not valid JSON"

    def test_waiver_registry_has_waivers_key(self):
        payload = mod._load_json(mod.WAIVER_REGISTRY_PATH)
        assert payload is not None
        assert "waivers" in payload
        assert isinstance(payload["waivers"], list)

    def test_waiver_registry_has_schema_version(self):
        payload = mod._load_json(mod.WAIVER_REGISTRY_PATH)
        assert payload is not None
        assert isinstance(payload.get("schema_version"), str)


# ===========================================================================
# 7. test_four_substrates
# ===========================================================================


class TestFourSubstrates:
    """Verify 4 substrates are present in the on-disk manifest."""

    def test_four_substrates(self):
        manifest = mod._load_json(mod.MANIFEST_PATH)
        if manifest is None:
            pytest.skip("manifest not present on disk")
        substrates = manifest.get("substrates", [])
        names = {s.get("name") for s in substrates if isinstance(s, dict)}
        assert len(names) == 4, f"expected 4 substrates, got {names}"
        for expected in ("frankentui", "frankensqlite", "sqlmodel_rust", "fastapi_rust"):
            assert expected in names, f"missing substrate: {expected}"


# ===========================================================================
# 8. test_gate_report_schema
# ===========================================================================


class TestGateReportSchema:
    """Validate gate report schema via validate_gate_report."""

    def test_gate_report_schema(self, valid_gate_report):
        result = mod.validate_gate_report(valid_gate_report)
        failing = [c for c in result["checks"] if not c["pass"]]
        assert len(failing) == 0, f"valid report unexpectedly failed: {failing}"

    def test_gate_report_verdict_consistent(self, valid_gate_report):
        result = mod.validate_gate_report(valid_gate_report)
        verdict_check = next(
            c for c in result["checks"] if c["check"] == "gate_verdict_consistent"
        )
        assert verdict_check["pass"]

    def test_gate_report_inconsistent_verdict_detected(self, valid_gate_report):
        bad = copy.deepcopy(valid_gate_report)
        bad["checks"][0]["status"] = "fail"
        bad["checks"][0]["remediation_hint"] = "fix it"
        bad["summary"]["passed"] = 0
        bad["summary"]["failed"] = 1
        # gate_verdict still says "pass" -> inconsistent
        result = mod.validate_gate_report(bad)
        verdict_check = next(
            c for c in result["checks"] if c["check"] == "gate_verdict_consistent"
        )
        assert not verdict_check["pass"]

    def test_gate_report_missing_remediation_hint(self):
        report = {
            "schema_version": "1.0.0",
            "bead_id": "bd-3u2o",
            "checks": [
                {
                    "module": "crates/franken-node/src/cli.rs",
                    "substrate": "frankentui",
                    "rule": "some-rule",
                    "status": "fail",
                    "remediation_hint": "",
                    "waiver_id": "",
                },
            ],
            "summary": {"total_checks": 1, "passed": 0, "failed": 1, "waived": 0},
            "gate_verdict": "fail",
            "events": [],
            "changed_modules": ["crates/franken-node/src/cli.rs"],
        }
        result = mod.validate_gate_report(report)
        hint_check = next(
            c for c in result["checks"]
            if c["check"] == "failure_remediation_hints_present"
        )
        assert not hint_check["pass"]

    def test_gate_report_event_codes_validated(self, valid_gate_report):
        result = mod.validate_gate_report(valid_gate_report)
        event_check = next(
            c for c in result["checks"]
            if c["check"] == "event_codes_from_expected_set"
        )
        assert event_check["pass"]

    def test_gate_report_unexpected_event_code_rejected(self, valid_gate_report):
        bad = copy.deepcopy(valid_gate_report)
        bad["events"].append({"code": "TOTALLY_UNEXPECTED_CODE", "detail": "x"})
        result = mod.validate_gate_report(bad)
        event_check = next(
            c for c in result["checks"]
            if c["check"] == "event_codes_from_expected_set"
        )
        assert not event_check["pass"]

    def test_gate_report_summary_mismatch(self, valid_gate_report):
        bad = copy.deepcopy(valid_gate_report)
        bad["summary"] = {"total_checks": 999, "passed": 0, "failed": 0, "waived": 0}
        result = mod.validate_gate_report(bad)
        summary_check = next(
            c for c in result["checks"]
            if c["check"] == "summary_matches_checks"
        )
        assert not summary_check["pass"]

    def test_gate_report_waived_without_waiver_id(self):
        report = {
            "schema_version": "1.0.0",
            "bead_id": "bd-3u2o",
            "checks": [
                {
                    "module": "crates/franken-node/src/cli.rs",
                    "substrate": "frankentui",
                    "rule": "some-rule",
                    "status": "waived",
                    "remediation_hint": "",
                    "waiver_id": "",
                },
            ],
            "summary": {"total_checks": 1, "passed": 0, "failed": 0, "waived": 1},
            "gate_verdict": "pass",
            "events": [],
            "changed_modules": ["crates/franken-node/src/cli.rs"],
        }
        result = mod.validate_gate_report(report)
        waiver_check = next(
            c for c in result["checks"]
            if c["check"] == "waived_checks_have_waiver_id"
        )
        assert not waiver_check["pass"]

    def test_gate_report_built_from_real_modules_validates(self):
        """A report built with a real module must pass validate_gate_report."""
        report = mod.build_gate_report(
            changed_modules=["crates/franken-node/src/cli.rs"]
        )
        validation = mod.validate_gate_report(report)
        failing = [c for c in validation["checks"] if not c["pass"]]
        assert len(failing) == 0, f"report validation failed: {failing}"


# ===========================================================================
# 9. test_event_codes_present
# ===========================================================================


class TestEventCodesPresent:
    """Verify all 6 expected event codes are defined in the module."""

    def test_event_codes_present(self):
        events = mod.EXPECTED_EVENTS
        for code in [
            "SUBSTRATE_GATE_START",
            "SUBSTRATE_GATE_VIOLATION",
            "SUBSTRATE_GATE_WAIVED",
            "SUBSTRATE_GATE_WAIVER_EXPIRED",
            "SUBSTRATE_GATE_PASS",
            "SUBSTRATE_GATE_FAIL",
        ]:
            assert code in events, f"missing event code: {code}"

    def test_event_codes_count(self):
        assert len(mod.EXPECTED_EVENTS) == 6

    def test_event_constants_match_list(self):
        assert mod.EVENT_START in mod.EXPECTED_EVENTS
        assert mod.EVENT_VIOLATION in mod.EXPECTED_EVENTS
        assert mod.EVENT_WAIVED in mod.EXPECTED_EVENTS
        assert mod.EVENT_WAIVER_EXPIRED in mod.EXPECTED_EVENTS
        assert mod.EVENT_PASS in mod.EXPECTED_EVENTS
        assert mod.EVENT_FAIL in mod.EXPECTED_EVENTS

    def test_event_codes_in_build_report(self):
        """Build a report and verify event codes appear in the output events."""
        report = mod.build_gate_report(changed_modules=[])
        event_codes = {e["code"] for e in report["events"]}
        assert "SUBSTRATE_GATE_START" in event_codes
        assert (
            "SUBSTRATE_GATE_PASS" in event_codes
            or "SUBSTRATE_GATE_FAIL" in event_codes
        )


# ===========================================================================
# Edge cases: empty substrates, missing fields, etc.
# ===========================================================================


class TestEdgeCases:
    """Test edge cases: empty substrates, missing fields, etc."""

    def test_build_report_missing_manifest(self, tmp_path):
        """Building a gate report with a missing manifest returns a fail report."""
        with mock.patch.object(mod, "MANIFEST_PATH", tmp_path / "nonexistent.json"):
            report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "fail"

    def test_validate_report_with_empty_checks(self):
        report = {
            "schema_version": "1.0.0",
            "bead_id": "bd-3u2o",
            "checks": [],
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "waived": 0},
            "gate_verdict": "pass",
            "events": [],
            "changed_modules": [],
        }
        result = mod.validate_gate_report(report)
        verdict_check = next(
            c for c in result["checks"] if c["check"] == "gate_verdict_consistent"
        )
        assert verdict_check["pass"]

    def test_validate_report_non_list_checks(self):
        report = {
            "schema_version": "1.0.0",
            "bead_id": "bd-3u2o",
            "checks": "not a list",
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "waived": 0},
            "gate_verdict": "pass",
            "events": [],
            "changed_modules": [],
        }
        result = mod.validate_gate_report(report)
        array_check = next(
            c for c in result["checks"] if c["check"] == "checks_array"
        )
        assert not array_check["pass"]

    def test_build_report_no_changed_modules(self):
        report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "pass"
        assert report["summary"]["failed"] == 0
        assert report["summary"]["total_checks"] == 0

    def test_build_report_nonexistent_module(self):
        report = mod.build_gate_report(
            changed_modules=["crates/franken-node/src/nonexistent_file.rs"]
        )
        failed = [c for c in report["checks"] if c["status"] == "fail"]
        assert len(failed) > 0

    def test_normalize_empty_input(self):
        result = mod._normalize_changed_modules([], "crates/franken-node/src")
        assert result == []

    def test_normalize_excludes_non_rs(self):
        result = mod._normalize_changed_modules(
            ["crates/franken-node/src/cli.py"],
            "crates/franken-node/src",
        )
        assert result == []

    def test_normalize_excludes_outside_root(self):
        result = mod._normalize_changed_modules(
            ["other/crate/src/lib.rs"],
            "crates/franken-node/src",
        )
        assert result == []

    def test_normalize_includes_rs_in_root(self):
        result = mod._normalize_changed_modules(
            ["crates/franken-node/src/cli.rs", "README.md"],
            "crates/franken-node/src",
        )
        assert result == ["crates/franken-node/src/cli.rs"]

    def test_load_json_missing_file(self, tmp_path):
        result = mod._load_json(tmp_path / "nope.json")
        assert result is None

    def test_load_json_invalid_json(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")
        result = mod._load_json(bad_file)
        assert result is None

    def test_load_json_non_dict(self, tmp_path):
        list_file = tmp_path / "list.json"
        list_file.write_text("[1,2,3]", encoding="utf-8")
        result = mod._load_json(list_file)
        assert result is None

    def test_validate_report_missing_top_level_keys(self):
        """A report with no required fields should flag missing fields."""
        result = mod.validate_gate_report({})
        required_check = next(
            c for c in result["checks"] if c["check"] == "report_required_fields"
        )
        assert not required_check["pass"]
        assert "missing" in required_check["detail"]


# ===========================================================================
# Module classification
# ===========================================================================


class TestClassifyModule:
    """Test module classification against substrate tier patterns."""

    def test_classify_mandatory(self, valid_manifest):
        tier = mod._classify_module(
            "crates/franken-node/src/cli.rs",
            valid_manifest["substrates"][0],  # frankentui
        )
        assert tier == "mandatory_modules"

    def test_classify_should_use(self, valid_manifest):
        tier = mod._classify_module(
            "crates/franken-node/src/main.rs",
            valid_manifest["substrates"][0],  # frankentui
        )
        assert tier == "should_use_modules"

    def test_classify_optional(self, valid_manifest):
        tier = mod._classify_module(
            "crates/franken-node/src/something_else.rs",
            valid_manifest["substrates"][0],  # frankentui
        )
        assert tier == "optional_modules"

    def test_classify_no_match(self):
        substrate = {
            "name": "frankentui",
            "mandatory_modules": ["other/**"],
            "should_use_modules": [],
            "optional_modules": [],
        }
        tier = mod._classify_module("crates/franken-node/src/cli.rs", substrate)
        assert tier is None


# ===========================================================================
# Waiver matching
# ===========================================================================


class TestWaiverForRule:
    """Test waiver lookup logic."""

    @staticmethod
    def _make_waiver(**overrides):
        base = {
            "waiver_id": "waiver-001",
            "module": "crates/franken-node/src/cli.rs",
            "substrate": "frankentui",
            "rules_waived": ["adjacent-substrate.mandatory.frankentui.raw-output"],
            "risk_analysis": "bounded",
            "scope_description": "test",
            "owner": "dev",
            "approved_by": "lead",
            "granted_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
            "remediation_plan": "migrate later",
            "status": "active",
        }
        base.update(overrides)
        return base

    def test_valid_waiver_found(self):
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        waiver = self._make_waiver()
        waiver_id, expired = mod._waiver_for_rule(
            [waiver],
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "adjacent-substrate.mandatory.frankentui.raw-output",
            now,
        )
        assert waiver_id == "waiver-001"
        assert not expired

    def test_expired_waiver_rejected(self):
        now = dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc)
        waiver = self._make_waiver()
        waiver_id, expired = mod._waiver_for_rule(
            [waiver],
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "adjacent-substrate.mandatory.frankentui.raw-output",
            now,
        )
        assert waiver_id is None
        assert expired

    def test_wrong_substrate_no_match(self):
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        waiver = self._make_waiver()
        waiver_id, expired = mod._waiver_for_rule(
            [waiver],
            "crates/franken-node/src/cli.rs",
            "frankensqlite",
            "adjacent-substrate.mandatory.frankentui.raw-output",
            now,
        )
        assert waiver_id is None
        assert not expired

    def test_wrong_rule_no_match(self):
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        waiver = self._make_waiver()
        waiver_id, expired = mod._waiver_for_rule(
            [waiver],
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "some-other-rule",
            now,
        )
        assert waiver_id is None
        assert not expired

    def test_empty_waivers_no_match(self):
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        waiver_id, expired = mod._waiver_for_rule(
            [],
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "adjacent-substrate.mandatory.frankentui.raw-output",
            now,
        )
        assert waiver_id is None
        assert not expired

    def test_waiver_matching_active_and_expired(self):
        """Verify correct discrimination between active and expired waivers."""
        now = dt.datetime(2026, 2, 22, tzinfo=dt.timezone.utc)
        waivers = [
            self._make_waiver(
                waiver_id="W-VALID",
                expires_at="2026-03-01T00:00:00Z",
                rules_waived=["adjacent-substrate.mandatory.frankentui.raw-output"],
            ),
            self._make_waiver(
                waiver_id="W-EXPIRED",
                expires_at="2026-02-01T00:00:00Z",
                rules_waived=["adjacent-substrate.mandatory.frankentui.ansi-literal"],
            ),
        ]

        waiver_id, expired = mod._waiver_for_rule(
            waivers,
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "adjacent-substrate.mandatory.frankentui.raw-output",
            now,
        )
        assert waiver_id == "W-VALID"
        assert not expired

        waiver_id, expired = mod._waiver_for_rule(
            waivers,
            "crates/franken-node/src/cli.rs",
            "frankentui",
            "adjacent-substrate.mandatory.frankentui.ansi-literal",
            now,
        )
        assert waiver_id is None
        assert expired


# ===========================================================================
# Mandatory rule evaluation
# ===========================================================================


class TestEvaluateMandatoryRules:
    """Test substrate-specific mandatory rule evaluation."""

    def test_frankentui_clean_source_passes(self):
        source = "use frankentui::render;\nfn display() { render::panel(); }\n"
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        events: list = []
        checks = mod._evaluate_mandatory_rules(
            "crates/franken-node/src/cli.rs",
            "frankentui",
            source,
            [],
            events,
            now,
        )
        statuses = {c["status"] for c in checks}
        assert "fail" not in statuses

    def test_frankensqlite_direct_fs_fails(self):
        source = "use std::fs::File;\nfn save() { File::create(\"state.db\").unwrap(); }\n"
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        events: list = []
        checks = mod._evaluate_mandatory_rules(
            "crates/franken-node/src/connector/mod.rs",
            "frankensqlite",
            source,
            [],
            events,
            now,
        )
        failed = [c for c in checks if c["status"] == "fail"]
        assert len(failed) > 0
        assert all(c["remediation_hint"] for c in failed)

    def test_fastapi_rust_middleware_present_passes(self):
        source = "use crate::api::middleware;\nfn handle() { middleware::run(); }\n"
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        events: list = []
        checks = mod._evaluate_mandatory_rules(
            "crates/franken-node/src/api/mod.rs",
            "fastapi_rust",
            source,
            [],
            events,
            now,
        )
        statuses = {c["status"] for c in checks}
        assert "fail" not in statuses

    def test_sqlmodel_rust_no_raw_sql_passes(self):
        source = "use sqlmodel::Model;\nfn query() { Model::find_by_id(1); }\n"
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        events: list = []
        checks = mod._evaluate_mandatory_rules(
            "crates/franken-node/src/config.rs",
            "sqlmodel_rust",
            source,
            [],
            events,
            now,
        )
        statuses = {c["status"] for c in checks}
        assert "fail" not in statuses


# ===========================================================================
# Build gate report
# ===========================================================================


class TestBuildGateReport:
    """Test the build_gate_report function."""

    def test_build_gate_report_returns_dict(self):
        report = mod.build_gate_report(changed_modules=[])
        assert isinstance(report, dict)
        assert report["bead_id"] == "bd-3u2o"
        assert "gate_verdict" in report
        assert "checks" in report
        assert "summary" in report
        assert "events" in report

    def test_build_gate_report_no_modules_passes(self):
        report = mod.build_gate_report(changed_modules=[])
        assert report["gate_verdict"] == "pass"
        assert report["summary"]["failed"] == 0

    def test_build_gate_report_with_real_module(self):
        report = mod.build_gate_report(
            changed_modules=["crates/franken-node/src/cli.rs"]
        )
        assert isinstance(report["checks"], list)
        assert report["gate_verdict"] in ("pass", "fail")

    def test_build_gate_report_validates_cleanly(self):
        report = mod.build_gate_report(
            changed_modules=["crates/franken-node/src/cli.rs"]
        )
        validation = mod.validate_gate_report(report)
        failing = [c for c in validation["checks"] if not c["pass"]]
        assert len(failing) == 0, f"report validation failed: {failing}"

    def test_build_gate_report_events_start_and_end(self):
        report = mod.build_gate_report(changed_modules=[])
        event_codes = [e["code"] for e in report["events"]]
        assert "SUBSTRATE_GATE_START" in event_codes
        assert (
            "SUBSTRATE_GATE_PASS" in event_codes
            or "SUBSTRATE_GATE_FAIL" in event_codes
        )


# ===========================================================================
# run_all orchestrator
# ===========================================================================


class TestRunAll:
    """Test the run_all orchestrator."""

    def test_run_all_build_report(self):
        result = mod.run_all(build_report=True, changed_modules=[])
        assert result["bead_id"] == "bd-3u2o"
        assert result["section"] == "10.16"
        assert "verdict" in result
        assert isinstance(result["checks"], list)

    def test_run_all_build_creates_report_file(self):
        result = mod.run_all(
            build_report=True,
            changed_modules=["crates/franken-node/src/cli.rs"],
        )
        assert result["verdict"] == "PASS"
        assert mod.REPORT_PATH.is_file()
        loaded = mod._load_json(mod.REPORT_PATH)
        assert loaded is not None
        assert "checks" in loaded
        assert "summary" in loaded

    def test_run_all_missing_report(self, tmp_path):
        """run_all without build_report returns FAIL when report file is missing."""
        with mock.patch.object(mod, "REPORT_PATH", tmp_path / "nonexistent.json"):
            result = mod.run_all(build_report=False, changed_modules=None)
        assert result["verdict"] == "FAIL"
        assert not result["overall_pass"]


# ===========================================================================
# JSON write/read roundtrip
# ===========================================================================


class TestJsonRoundtrip:
    """Verify JSON serialization round-trip."""

    def test_json_roundtrip(self):
        report = mod.build_gate_report(["crates/franken-node/src/cli.rs"])
        with tempfile.TemporaryDirectory(prefix="bd-3u2o-") as tmp:
            out = Path(tmp) / "report.json"
            mod._write_json(out, report)
            loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["bead_id"] == "bd-3u2o"
        assert "summary" in loaded


# ===========================================================================
# CLI self-test
# ===========================================================================


class TestCLISelfTest:
    """Test the CLI --self-test flag via subprocess."""

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"self-test failed: {result.stderr}"
        assert "self_test passed" in result.stdout


# ===========================================================================
# Constants
# ===========================================================================


class TestConstants:
    """Verify module-level constants are correctly defined."""

    def test_bead_id(self):
        assert mod.BEAD_ID == "bd-3u2o"

    def test_section(self):
        assert mod.SECTION == "10.16"

    def test_expected_events_count(self):
        assert len(mod.EXPECTED_EVENTS) == 6

    def test_tier_keys(self):
        assert mod.TIER_KEYS == ("mandatory_modules", "should_use_modules", "optional_modules")

    def test_statuses(self):
        assert mod.STATUSES == {"pass", "fail", "waived"}

    def test_manifest_path_under_root(self):
        assert str(mod.MANIFEST_PATH).startswith(str(mod.ROOT))

    def test_waiver_registry_path_under_root(self):
        assert str(mod.WAIVER_REGISTRY_PATH).startswith(str(mod.ROOT))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
