"""Unit tests for scripts/check_eviction_saga.py (bd-1ru2)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_eviction_saga as mod


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestChecksStructure(unittest.TestCase):
    def setUp(self):
        self.results = mod._checks()

    def test_minimum_check_count(self):
        self.assertGreaterEqual(len(self.results), 12)

    def test_checks_have_required_fields(self):
        for r in self.results:
            self.assertIn("check", r)
            self.assertIn("passed", r)
            self.assertIn("detail", r)

    def test_check_names_unique(self):
        names = [r["check"] for r in self.results]
        self.assertEqual(len(names), len(set(names)))


class TestSourceExists(unittest.TestCase):
    def test_source_found(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["SOURCE_EXISTS"]["passed"])


class TestEventCodes(unittest.TestCase):
    def test_all_event_codes_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["EVENT_CODES"]["passed"])
        self.assertIn("12/12", results["EVENT_CODES"]["detail"])


class TestInvariants(unittest.TestCase):
    def test_all_invariants_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["INVARIANTS"]["passed"])
        self.assertIn("6/6", results["INVARIANTS"]["detail"])


class TestCoreTypes(unittest.TestCase):
    def test_all_types_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["CORE_TYPES"]["passed"])
        self.assertIn("5/5", results["CORE_TYPES"]["detail"])


class TestSagaPhases(unittest.TestCase):
    def test_all_phases_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["SAGA_PHASES"]["passed"])
        self.assertIn("8", results["SAGA_PHASES"]["detail"])


class TestCompensationMatrix(unittest.TestCase):
    def test_all_compensations_present(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["COMPENSATION_MATRIX"]["passed"])
        self.assertIn("3/3", results["COMPENSATION_MATRIX"]["detail"])


class TestRemoteCapGating(unittest.TestCase):
    def test_remotecap_gating(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["REMOTECAP_GATING"]["passed"])


class TestCancelSafety(unittest.TestCase):
    def test_cancel_safety(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["CANCEL_SAFETY"]["passed"])


class TestLeakDetection(unittest.TestCase):
    def test_leak_detection(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["LEAK_DETECTION"]["passed"])


class TestCrashRecovery(unittest.TestCase):
    def test_crash_recovery(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["CRASH_RECOVERY"]["passed"])


class TestAuditTrail(unittest.TestCase):
    def test_audit_trail(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["AUDIT_TRAIL"]["passed"])


class TestTestCoverage(unittest.TestCase):
    def test_sufficient_tests(self):
        results = {r["check"]: r for r in mod._checks()}
        self.assertTrue(results["TEST_COVERAGE"]["passed"])


class TestJsonOutput(unittest.TestCase):
    def test_json_output_parseable(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_eviction_saga.py"), "--json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["bead"], "bd-1ru2")
        self.assertEqual(data["title"], "Cancel-Safe Eviction Saga")
        self.assertIn("verdict", data)
        self.assertIn("passed", data)
        self.assertIn("total", data)
        self.assertIn("checks", data)

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_eviction_saga.py"), "--json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["passed"], data["total"])

    def test_exit_code_zero_on_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_eviction_saga.py"), "--json"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)


class TestHumanOutput(unittest.TestCase):
    def test_human_output_contains_bead(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_eviction_saga.py")],
            capture_output=True, text=True
        )
        self.assertIn("bd-1ru2", result.stdout)
        self.assertIn("PASS", result.stdout)


class TestSelfTestCli(unittest.TestCase):
    def test_self_test_exit_code(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_eviction_saga.py"), "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)


class TestOverallVerdict(unittest.TestCase):
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        self.assertEqual(len(failed), 0,
                         f"Failing checks: {[r['check'] for r in failed]}")


if __name__ == "__main__":
    unittest.main()
