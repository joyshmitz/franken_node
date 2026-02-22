"""Unit tests for scripts/check_bd_274s_bayesian_quarantine.py."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_bd_274s_bayesian_quarantine.py"

spec = importlib.util.spec_from_file_location("check_bd_274s_bayesian_quarantine", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD, "bd-274s")
        self.assertEqual(mod.SECTION, "10.17")

    def test_required_actions(self):
        self.assertEqual(mod.REQUIRED_ACTION_TOKENS, ["throttle", "isolate", "revoke", "quarantine"])


class TestHelpers(unittest.TestCase):
    def test_evidence_pass(self):
        self.assertTrue(mod._evidence_pass({"status": "pass"}))
        self.assertTrue(mod._evidence_pass({"verdict": "PASS"}))
        self.assertFalse(mod._evidence_pass({"status": "fail"}))

    def test_load_json_missing(self):
        self.assertIsNone(mod._load_json(ROOT / "artifacts" / "section_10_17" / "bd-none" / "missing.json"))

    def test_check_shape(self):
        row = mod._check("sample", True, "ok")
        self.assertIn("check", row)
        self.assertIn("passed", row)
        self.assertIn("detail", row)


class TestRunAll(unittest.TestCase):
    def test_result_shape(self):
        result = mod.run_all()
        for key in [
            "schema_version",
            "bead_id",
            "section",
            "title",
            "verdict",
            "status",
            "total",
            "passed",
            "failed",
            "checks",
            "metrics",
        ]:
            self.assertIn(key, result)

    def test_verdict_enum(self):
        result = mod.run_all()
        self.assertIn(result["verdict"], {"PASS", "FAIL"})

    def test_total_minimum(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 10)

    def test_checks_have_shape(self):
        result = mod.run_all()
        for row in result["checks"]:
            self.assertIn("check", row)
            self.assertIn("passed", row)
            self.assertIn("detail", row)

    def test_metrics_shape(self):
        result = mod.run_all()
        metrics = result["metrics"]
        for key in [
            "dependency_count",
            "dependent_count",
            "required_file_count",
            "required_files_missing",
            "fallback_signal_hits",
        ]:
            self.assertIn(key, metrics)


class TestSelfTest(unittest.TestCase):
    def test_self_test_pass(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-274s")
        self.assertIn(proc.returncode, (0, 1))

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
