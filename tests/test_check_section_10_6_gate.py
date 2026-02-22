"""Unit tests for scripts/check_section_10_6_gate.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_section_10_6_gate.py"


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
    def test_json_valid(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-3p9n"
        assert data["section"] == "10.6"
        assert data["gate"] is True

    def test_json_has_section_beads(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert len(data["section_beads"]) == 7

    def test_json_check_structure(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "check" in check
            assert "pass" in check
            assert "detail" in check


class TestEvidenceChecks:
    @pytest.mark.parametrize(
        "bead_id",
        ["bd-k4s", "bd-3lh", "bd-38m", "bd-2q5", "bd-3kn", "bd-2pw", "bd-3q9"],
    )
    def test_bead_evidence_pass(self, bead_id: str):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == f"evidence_{bead_id}")
        assert check["pass"] is True, f"{bead_id}: {check['detail']}"

    @pytest.mark.parametrize(
        "bead_id",
        ["bd-k4s", "bd-3lh", "bd-38m", "bd-2q5", "bd-3kn", "bd-2pw", "bd-3q9"],
    )
    def test_bead_summary_exists(self, bead_id: str):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == f"summary_{bead_id}")
        assert check["pass"] is True, f"{bead_id}: {check['detail']}"


class TestAggregateChecks:
    def test_all_evidence_present(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "all_evidence_present")
        assert check["pass"] is True

    def test_all_verdicts_pass(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "all_verdicts_pass")
        assert check["pass"] is True


class TestArtifactChecks:
    def test_benchmark_suite_impl(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "benchmark_suite_impl")
        assert check["pass"] is True

    def test_budgets_config(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        check = next(c for c in data["checks"] if c["check"] == "budgets_config")
        assert check["pass"] is True


class TestOverallVerdict:
    def test_gate_passes(self):
        result = run_script("--json")
        data = json.loads(result.stdout)
        assert data["overall_pass"] is True, (
            f"Gate should pass. Failed: {[c['check'] for c in data['checks'] if not c['pass']]}"
        )

    def test_human_readable(self):
        result = run_script()
        assert "Section 10.6 Gate" in result.stdout
