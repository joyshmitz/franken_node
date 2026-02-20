#!/usr/bin/env python3
"""Unit tests for check_control_evidence_replay.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_control_evidence_replay as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_impl_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_conformance_test_exists(self):
        result = checker.check_file(checker.CONFORMANCE_TEST, "conformance test")
        self.assertTrue(result["pass"])

    def test_adoption_doc_exists(self):
        result = checker.check_file(checker.ADOPTION_DOC, "adoption document")
        self.assertTrue(result["pass"])

    def test_replay_report_exists(self):
        result = checker.check_file(checker.REPLAY_REPORT, "replay report")
        self.assertTrue(result["pass"])

    def test_validator_impl_exists(self):
        result = checker.check_file(checker.VALIDATOR_IMPL, "canonical validator")
        self.assertTrue(result["pass"])

    def test_control_evidence_exists(self):
        result = checker.check_file(checker.CONTROL_EVIDENCE, "control evidence")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found_in_impl(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum ReplayVerdict"],
            "type",
        )
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(
            checker.IMPL,
            ["NONEXISTENT_XYZ_123"],
            "type",
        )
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])

    def test_multiple(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum ReplayVerdict", "pub struct ControlReplayGate"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = checker.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_minimum_50(self):
        result = checker.check_impl_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 50)


class TestCheckConformanceTestCount(unittest.TestCase):
    def test_minimum_15(self):
        result = checker.check_conformance_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 15)


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckCanonicalValidator(unittest.TestCase):
    def test_uses_canonical(self):
        result = checker.check_canonical_validator_usage()
        self.assertTrue(result["pass"])


class TestCheckAdoptionDoc(unittest.TestCase):
    def test_adoption_doc_all_pass(self):
        results = checker.check_adoption_doc()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_all_decision_types_documented(self):
        results = checker.check_adoption_doc()
        type_checks = [r for r in results if any(dt in r["check"] for dt in checker.DECISION_TYPES)]
        self.assertEqual(len(type_checks), 5)

    def test_all_verdicts_documented(self):
        results = checker.check_adoption_doc()
        verdict_checks = [r for r in results if "verdict" in r["check"]]
        self.assertEqual(len(verdict_checks), 3)


class TestCheckSpecContent(unittest.TestCase):
    def test_spec_has_all_types(self):
        results = checker.check_spec_content()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckReplayReport(unittest.TestCase):
    def test_report_checks_pass(self):
        results = checker.check_replay_report()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_all_decision_types_covered(self):
        results = checker.check_replay_report()
        types_check = [r for r in results if "all decision types" in r["check"]]
        self.assertTrue(len(types_check) > 0)
        self.assertTrue(types_check[0]["pass"])

    def test_determinism_verified(self):
        results = checker.check_replay_report()
        det_check = [r for r in results if "determinism" in r["check"]]
        self.assertTrue(len(det_check) > 0)
        self.assertTrue(det_check[0]["pass"])

    def test_gate_behavior_correct(self):
        results = checker.check_replay_report()
        gate_check = [r for r in results if "gate behavior" in r["check"]]
        self.assertTrue(len(gate_check) > 0)
        self.assertTrue(gate_check[0]["pass"])


class TestRunChecks(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_checks()
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_all_checks_pass(self):
        result = checker.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_verdict_is_pass(self):
        result = checker.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("replay", result["title"].lower())

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 50)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 100)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 4)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 10)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 5)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_impl_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_IMPL_TESTS), 50)

    def test_conformance_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_CONFORMANCE_TESTS), 15)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_evidence_replay.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_evidence_replay.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
