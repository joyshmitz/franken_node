"""Unit tests for scripts/check_optimization_governor.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_optimization_governor.py"

spec = importlib.util.spec_from_file_location("check_optimization_governor", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TestRunAll(unittest.TestCase):
    def test_run_all_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_context(result))

    def test_run_all_has_core_fields(self):
        result = mod.run_all()
        for key in ["schema_version", "bead_id", "section", "verdict", "checks", "paths"]:
            self.assertIn(key, result)

    def test_bead_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-21fo")
        self.assertEqual(result["section"], "10.17")

    def test_check_count_floor(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 30)

    def test_every_check_has_shape(self):
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_required_code_lists_have_expected_lengths(self):
        result = mod.run_all()
        self.assertEqual(len(result["event_codes"]), 7)
        self.assertEqual(len(result["error_codes"]), 6)
        self.assertEqual(len(result["invariants"]), 6)

    def _failure_context(self, result):
        failed = [check for check in result["checks"] if not check["passed"]]
        return "\n".join(
            f"FAIL: {check['check']} :: {check['detail']}" for check in failed[:15]
        )


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_has_shape(self):
        result = mod.self_test()
        for key in ["name", "bead", "section", "verdict", "checks"]:
            self.assertIn(key, result)


class TestReportWriter(unittest.TestCase):
    def test_write_report_creates_json(self):
        report_data = mod.run_all()
        mod.write_report(report_data)
        report_path = ROOT / "artifacts/section_10_17/bd-21fo/check_report.json"
        self.assertTrue(report_path.exists())
        parsed = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(parsed["bead_id"], "bd-21fo")


class TestCli(unittest.TestCase):
    def test_cli_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-21fo")

    def test_cli_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_cli_build_report_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--build-report", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertIn(parsed["verdict"], {"PASS", "FAIL"})


if __name__ == "__main__":
    unittest.main()
