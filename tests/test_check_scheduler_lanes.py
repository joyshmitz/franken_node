"""Tests for scripts/check_scheduler_lanes.py (bd-lus)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_scheduler_lanes.py"

spec = importlib.util.spec_from_file_location("check_scheduler_lanes", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec is not None
assert spec.loader is not None
spec.loader.exec_module(module)


class TestSelfTest:
    def test_self_test_passes(self):
        assert module.self_test() is True


class TestChecks:
    def test_all_checks_have_shape(self):
        checks = module._checks()
        assert isinstance(checks, list)
        assert len(checks) >= 16
        for c in checks:
            assert set(c.keys()) == {"check", "passed", "detail"}
            assert isinstance(c["check"], str)
            assert isinstance(c["passed"], bool)
            assert isinstance(c["detail"], str)

    def test_expected_checks_are_present(self):
        checks = module._checks()
        names = {c["check"] for c in checks}
        expected = {
            "lane_router_exists",
            "bulkhead_exists",
            "runtime_config_contract",
            "lane_event_codes",
            "metrics_contract",
            "mixed_workload_integration_test",
        }
        assert expected.issubset(names)

    def test_all_checks_pass(self):
        checks = module._checks()
        failed = [c for c in checks if not c["passed"]]
        assert failed == [], f"failed checks: {[c['check'] for c in failed]}"


class TestCli:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["bead_id"] == "bd-lus"
        assert payload["section"] == "10.11"
        assert payload["verdict"] == "PASS"
        assert payload["checks_passed"] == payload["checks_total"]

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "self_test:" in result.stderr


class TestRegressionCases:
    def test_missing_lane_router_fails(self):
        original = module.LANE_ROUTER
        try:
            module.LANE_ROUTER = str(ROOT / "crates" / "franken-node" / "src" / "runtime" / "_missing_.rs")
            checks = module._checks()
        finally:
            module.LANE_ROUTER = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["lane_router_exists"]["passed"] is False

    def test_missing_spec_fails(self):
        original = module.SPEC
        with tempfile.TemporaryDirectory() as tmpdir:
            module.SPEC = str(Path(tmpdir) / "missing.md")
            checks = module._checks()
        module.SPEC = original

        by_name = {c["check"]: c for c in checks}
        assert by_name["spec_exists"]["passed"] is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
