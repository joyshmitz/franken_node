"""Unit tests for scripts/check_voi_scheduler.py (bd-2nt)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_voi_scheduler as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        for key in ("bead_id", "section", "checks", "verdict",
                     "passed", "failed", "total", "all_passed", "status"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-2nt")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.11")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "VOI-Budgeted Monitor Scheduling")

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["all_passed"])
        else:
            self.assertEqual(result["verdict"], "FAIL")
            self.assertFalse(result["all_passed"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants_in_spec(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestRustModuleChecks(unittest.TestCase):
    def test_module_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_module_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_module_registered(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_module_registered")
        self.assertTrue(check["passed"], check["detail"])

    def test_structs(self):
        result = checker.run_all()
        for s in checker.REQUIRED_STRUCTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_struct:{s}")
            self.assertTrue(check["passed"], f"{s}: {check['detail']}")

    def test_methods(self):
        result = checker.run_all()
        for m in checker.REQUIRED_METHODS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_method:{m}")
            self.assertTrue(check["passed"], f"{m}: {check['detail']}")

    def test_event_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants_in_rust(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_test_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_test_count")
        self.assertTrue(check["passed"], check["detail"])

    def test_default_diagnostics(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_default_diagnostics")
        self.assertTrue(check["passed"], check["detail"])

    def test_default_diag_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_default_diag_count")
        self.assertTrue(check["passed"], check["detail"])

    def test_storm_protection(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_storm_protection")
        self.assertTrue(check["passed"], check["detail"])

    def test_regime_boost(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_regime_boost")
        self.assertTrue(check["passed"], check["detail"])

    def test_preemption(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_preemption")
        self.assertTrue(check["passed"], check["detail"])


class TestConstants(unittest.TestCase):
    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 6)

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_error_code_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 5)

    def test_struct_count(self):
        self.assertEqual(len(checker.REQUIRED_STRUCTS), 9)

    def test_method_count(self):
        self.assertEqual(len(checker.REQUIRED_METHODS), 13)

    def test_priority_count(self):
        self.assertEqual(len(checker.PRIORITY_CLASSES), 3)

    def test_voi_component_count(self):
        self.assertEqual(len(checker.VOI_COMPONENTS), 4)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_voi_scheduler.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-2nt")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_voi_scheduler.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestOverallVerdict(unittest.TestCase):
    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
