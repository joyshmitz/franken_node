"""Unit tests for scripts/check_remote_idempotency_saga.py (bd-3hw)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_remote_idempotency_saga as checker


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
        self.assertEqual(result["bead_id"], "bd-3hw")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.11")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"],
                         "Remote Idempotency and Saga Semantics Integration")

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


class TestSagaSourceChecks(unittest.TestCase):
    def test_saga_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "SAGA_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_idempotency_key_field(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "SAGA_IDEMPOTENCY_KEY")
        self.assertTrue(check["passed"], check["detail"])

    def test_computation_name_field(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "SAGA_COMPUTATION_NAME")
        self.assertTrue(check["passed"], check["detail"])

    def test_is_remote_field(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "SAGA_IS_REMOTE")
        self.assertTrue(check["passed"], check["detail"])


class TestEventCodes(unittest.TestCase):
    def test_event_codes_in_saga(self):
        result = checker.run_all()
        sag_codes = ["SAG-001", "SAG-002", "SAG-003", "SAG-004",
                     "SAG-005", "SAG-006", "SAG-007", "SAG-008"]
        for code in sag_codes:
            check = next(c for c in result["checks"]
                         if c["name"] == f"EVENT_CODE:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 12)


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


class TestEvidenceChecks(unittest.TestCase):
    def test_evidence_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_EXISTS")
        self.assertTrue(check["passed"], check["detail"])

    def test_evidence_required_fields(self):
        result = checker.run_all()
        for field in checker.EVIDENCE_REQUIRED_FIELDS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"EVIDENCE_FIELD:{field}")
            self.assertTrue(check["passed"], f"{field}: {check['detail']}")

    def test_evidence_saga_steps(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_SAGA_STEPS")
        self.assertTrue(check["passed"], check["detail"])

    def test_evidence_compensations(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_COMPENSATIONS")
        self.assertTrue(check["passed"], check["detail"])

    def test_evidence_no_cap_violations(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_NO_CAP_VIOLATIONS")
        self.assertTrue(check["passed"], check["detail"])

    def test_evidence_verdict(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "EVIDENCE_VERDICT")
        self.assertTrue(check["passed"], check["detail"])


class TestSummaryChecks(unittest.TestCase):
    def test_summary_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "SUMMARY_EXISTS")
        self.assertTrue(check["passed"], check["detail"])


class TestTestFileChecks(unittest.TestCase):
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
             str(ROOT / "scripts" / "check_remote_idempotency_saga.py"),
             "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3hw")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_remote_idempotency_saga.py"),
             "--self-test"],
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
