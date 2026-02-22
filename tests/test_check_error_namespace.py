"""Unit tests for scripts/check_error_namespace.py (bd-13q)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "check_error_namespace", ROOT / "scripts" / "check_error_namespace.py"
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllStructure(unittest.TestCase):
    """run_all() should always return a stable report shape."""

    def test_report_shape(self) -> None:
        report = mod.run_all()
        self.assertIsInstance(report, dict)
        self.assertEqual(report["bead_id"], "bd-13q")
        self.assertEqual(report["section"], "10.10")
        self.assertIn(report["verdict"], ("PASS", "FAIL"))
        self.assertIsInstance(report["checks"], list)
        self.assertEqual(report["total"], len(report["checks"]))
        self.assertEqual(report["failed"], report["total"] - report["passed"])

    def test_check_entries_have_required_fields(self) -> None:
        report = mod.run_all()
        for entry in report["checks"]:
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)
            self.assertIsInstance(entry["check"], str)
            self.assertIsInstance(entry["pass"], bool)
            self.assertIsInstance(entry["detail"], str)


class TestSelfTest(unittest.TestCase):
    """self_test should provide a deterministic boolean status."""

    def test_self_test_returns_bool(self) -> None:
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_consistency(self) -> None:
        report = mod.run_all()
        expected = report["failed"] == 0
        # self_test validates sub-checkers directly, so equality is expected.
        self.assertEqual(mod.self_test(), expected)


class TestCoverageAndCompatInvocations(unittest.TestCase):
    """Wrapper checks should run and append exactly one result each."""

    def setUp(self) -> None:
        mod.RESULTS = []

    def test_check_compat_script_adds_result(self) -> None:
        mod.check_compat_script()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "compatibility_policy")

    def test_check_coverage_script_adds_result(self) -> None:
        mod.check_coverage_script()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertEqual(mod.RESULTS[0]["check"], "coverage_policy")


if __name__ == "__main__":
    unittest.main()
