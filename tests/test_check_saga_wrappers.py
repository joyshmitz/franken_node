"""Unit tests for scripts/check_saga_wrappers.py (bd-3h63)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_saga_wrappers as checker


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
        self.assertEqual(result["bead_id"], "bd-3h63")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.15")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "Saga Wrappers with Deterministic Compensations")

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
            check = next(c for c in result["checks"]
                         if c["name"] == f"EVENT_CODE:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 8)


class TestInvariants(unittest.TestCase):
    def test_invariants_in_rust(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"INVARIANT:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 5)


class TestCoreTypes(unittest.TestCase):
    def test_types_in_rust(self):
        result = checker.run_all()
        for typ in checker.CORE_TYPES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"CORE_TYPE:{typ}")
            self.assertTrue(check["passed"], f"{typ}: {check['detail']}")

    def test_type_count(self):
        self.assertEqual(len(checker.CORE_TYPES), 6)


class TestMethods(unittest.TestCase):
    def test_methods_in_rust(self):
        result = checker.run_all()
        for method in checker.REQUIRED_METHODS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"METHOD:{method}")
            self.assertTrue(check["passed"], f"{method}: {check['detail']}")


class TestCompensationSemantics(unittest.TestCase):
    def test_compensation_reverse(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "COMPENSATION_REVERSE")
        self.assertTrue(check["passed"], check["detail"])

    def test_terminal_states(self):
        result = checker.run_all()
        for state in checker.TERMINAL_STATES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"TERMINAL_STATE:{state}")
            self.assertTrue(check["passed"], f"{state}: {check['detail']}")

    def test_trace_export(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "TRACE_EXPORT")
        self.assertTrue(check["passed"], check["detail"])

    def test_audit_trail(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "AUDIT_TRAIL")
        self.assertTrue(check["passed"], check["detail"])


class TestTestCoverage(unittest.TestCase):
    def test_rust_test_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "TEST_COVERAGE")
        self.assertTrue(check["passed"], check["detail"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "SPEC_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"SPEC_EVENT:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants_in_spec(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"SPEC_INVARIANT:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_types_in_spec(self):
        result = checker.run_all()
        for typ in checker.CORE_TYPES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"SPEC_TYPE:{typ}")
            self.assertTrue(check["passed"], f"{typ}: {check['detail']}")


class TestArtifactChecks(unittest.TestCase):
    def test_evidence_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_summary_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "SUMMARY_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_test_file_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "TEST_FILE_EXISTS")
        self.assertTrue(check["passed"], check["detail"])


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_saga_wrappers.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3h63")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_saga_wrappers.py"), "--self-test"],
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
