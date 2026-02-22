"""Unit tests for scripts/check_latency_gates.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_latency_gates.py"


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


class TestSelfTest:
    def test_self_test_passes(self):
        result = run_script("--self-test")
        assert result.returncode == 0
        assert "SELF-TEST OK" in result.stderr


class TestJsonOutput:
    def test_json_output_valid(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-3lh"
        assert data["section"] == "10.6"
        assert isinstance(data["total"], int)
        assert isinstance(data["checks"], list)

    def test_json_has_verdict(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_json_has_profile(self):
        result = run_script("--json", "--profile", "enterprise")
        data = json.loads(result.stdout)
        assert data["profile"] == "enterprise"

    def test_json_check_structure(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "check" in check
            assert "pass" in check
            assert "detail" in check


class TestSpecChecks:
    def test_spec_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "spec_exists")
        assert check["pass"] is True

    def test_budgets_exists(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_exists")
        assert check["pass"] is True


class TestKeywordChecks:
    @pytest.mark.parametrize(
        "keyword",
        [
            "spec_keyword_cold_start",
            "spec_keyword_p99",
            "spec_keyword_flamegraph",
            "spec_keyword_profiles",
            "spec_keyword_early_warning",
        ],
    )
    def test_spec_keywords(self, keyword: str):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == keyword)
        assert check["pass"] is True, f"{keyword}: {check['detail']}"


class TestEventCodes:
    def test_event_codes_present(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "spec_event_codes")
        assert check["pass"] is True, check["detail"]


class TestInvariants:
    def test_invariants_present(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "spec_invariants")
        assert check["pass"] is True, check["detail"]


class TestBudgetConfig:
    def test_has_profiles(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_has_profiles")
        assert check["pass"] is True, check["detail"]

    def test_has_workflows(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_has_workflows")
        assert check["pass"] is True, check["detail"]

    def test_has_version(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_version")
        assert check["pass"] is True, check["detail"]

    def test_min_iterations(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_min_iterations")
        assert check["pass"] is True, check["detail"]

    def test_budget_resolution(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budget_resolution")
        assert check["pass"] is True, check["detail"]

    def test_values_positive(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budget_values_positive")
        assert check["pass"] is True, check["detail"]

    def test_enterprise_stricter(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budget_enterprise_stricter")
        assert check["pass"] is True, check["detail"]


class TestStatistics:
    def test_percentile_computation(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "percentile_computation")
        assert check["pass"] is True, check["detail"]


class TestOverallVerdict:
    def test_all_checks_pass(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["overall_pass"] is True, (
            f"Failed checks: {[c['check'] for c in data['checks'] if not c['pass']]}"
        )

    def test_human_readable(self):
        result = run_script()
        assert "bd-3lh verification" in result.stdout
