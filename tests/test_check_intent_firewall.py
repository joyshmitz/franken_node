"""Unit tests for scripts/check_intent_firewall.py (bd-3l2p)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_intent_firewall as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        for key in (
            "bead_id",
            "section",
            "checks",
            "verdict",
            "passed",
            "failed",
            "total",
            "all_passed",
            "status",
        ):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-3l2p")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.17")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "Intent-Aware Remote Effects Firewall")

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


class TestSourceChecks(unittest.TestCase):
    def test_source_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "SOURCE_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_module_registered(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "MODULE_REGISTERED")
        self.assertTrue(check["passed"], check["detail"])


class TestEventCodes(unittest.TestCase):
    def test_event_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(
                c for c in result["checks"] if c["name"] == f"EVENT_CODE:{code}"
            )
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestInvariants(unittest.TestCase):
    def test_invariants_in_rust(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(
                c for c in result["checks"] if c["name"] == f"INVARIANT:{inv}"
            )
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")


class TestErrorCodes(unittest.TestCase):
    def test_error_codes_in_rust(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(
                c for c in result["checks"] if c["name"] == f"ERROR_CODE:{code}"
            )
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestCoreTypes(unittest.TestCase):
    def test_core_types_defined(self):
        result = checker.run_all()
        for typ in checker.CORE_TYPES:
            check = next(
                c for c in result["checks"] if c["name"] == f"CORE_TYPE:{typ}"
            )
            self.assertTrue(check["passed"], f"{typ}: {check['detail']}")


class TestVerdicts(unittest.TestCase):
    def test_verdicts_present(self):
        result = checker.run_all()
        for v in checker.VERDICTS:
            check = next(
                c for c in result["checks"] if c["name"] == f"VERDICT:{v}"
            )
            self.assertTrue(check["passed"], f"{v}: {check['detail']}")


class TestMethods(unittest.TestCase):
    def test_required_methods(self):
        result = checker.run_all()
        for method in checker.REQUIRED_METHODS:
            check = next(
                c for c in result["checks"] if c["name"] == f"METHOD:{method}"
            )
            self.assertTrue(check["passed"], f"{method}: {check['detail']}")


class TestSpecContract(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "SPEC_EXISTS")
        self.assertTrue(check["passed"], check["detail"])


class TestTestCoverage(unittest.TestCase):
    def test_minimum_test_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "TEST_COVERAGE")
        self.assertTrue(check["passed"], check["detail"])


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        serialized = json.dumps(result, indent=2)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["bead_id"], "bd-3l2p")


if __name__ == "__main__":
    unittest.main()
