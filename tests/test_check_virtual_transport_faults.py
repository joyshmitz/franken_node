"""Tests for scripts/check_virtual_transport_faults.py (bd-2qqu)."""

import importlib.util
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_virtual_transport_faults.py")

# Import the module under test
spec = importlib.util.spec_from_file_location("check_vtf", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _run_script(*args):
    return subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def _results_dict():
    return {r["check"]: r for r in mod._checks()}


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())

    def test_self_test_exit_code(self):
        result = _run_script("--self-test")
        self.assertEqual(result.returncode, 0)

    def test_self_test_output_format(self):
        result = _run_script("--self-test")
        self.assertIn("self_test:", result.stdout)


class TestJsonOutput(unittest.TestCase):
    def test_json_is_valid(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertIsInstance(data, dict)

    def test_json_has_bead(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertEqual(data["bead"], "bd-2qqu")

    def test_json_has_title(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertEqual(data["title"], "Virtual Transport Fault Harness")

    def test_json_has_verdict(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertIn(data["verdict"], ("PASS", "FAIL"))

    def test_json_has_passed_total(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertIsInstance(data["passed"], int)
        self.assertIsInstance(data["total"], int)

    def test_json_checks_is_list(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertIsInstance(data["checks"], list)
        self.assertGreater(len(data["checks"]), 0)

    def test_json_check_structure(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        for c in data["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["passed"], bool)


class TestSourceExists(unittest.TestCase):
    def test_source_exists_passes(self):
        results = _results_dict()
        self.assertTrue(results["SOURCE_EXISTS"]["passed"])

    def test_source_exists_detail_has_path(self):
        results = _results_dict()
        self.assertIn("virtual_transport_faults.rs", results["SOURCE_EXISTS"]["detail"])


class TestEventCodes(unittest.TestCase):
    def test_event_codes_passes(self):
        results = _results_dict()
        self.assertTrue(results["EVENT_CODES"]["passed"])

    def test_event_codes_count(self):
        results = _results_dict()
        self.assertIn("12/12", results["EVENT_CODES"]["detail"])


class TestInvariants(unittest.TestCase):
    def test_invariants_passes(self):
        results = _results_dict()
        self.assertTrue(results["INVARIANTS"]["passed"])

    def test_invariants_count(self):
        results = _results_dict()
        self.assertIn("6/6", results["INVARIANTS"]["detail"])


class TestCoreTypes(unittest.TestCase):
    def test_core_types_passes(self):
        results = _results_dict()
        self.assertTrue(results["CORE_TYPES"]["passed"])

    def test_core_types_count(self):
        results = _results_dict()
        self.assertIn("5/5", results["CORE_TYPES"]["detail"])


class TestPrebuiltScenarios(unittest.TestCase):
    def test_prebuilt_scenarios_passes(self):
        results = _results_dict()
        self.assertTrue(results["PREBUILT_SCENARIOS"]["passed"])

    def test_prebuilt_scenarios_count(self):
        results = _results_dict()
        self.assertIn("5/5", results["PREBUILT_SCENARIOS"]["detail"])


class TestDeterministicSchedule(unittest.TestCase):
    def test_deterministic_schedule_passes(self):
        results = _results_dict()
        self.assertTrue(results["DETERMINISTIC_SCHEDULE"]["passed"])

    def test_deterministic_schedule_detail(self):
        results = _results_dict()
        self.assertIn("seed-based", results["DETERMINISTIC_SCHEDULE"]["detail"])


class TestFaultInjection(unittest.TestCase):
    def test_fault_injection_passes(self):
        results = _results_dict()
        self.assertTrue(results["FAULT_INJECTION"]["passed"])

    def test_fault_injection_detail(self):
        results = _results_dict()
        self.assertIn("3 fault injection", results["FAULT_INJECTION"]["detail"])


class TestCampaignRunner(unittest.TestCase):
    def test_campaign_runner_passes(self):
        results = _results_dict()
        self.assertTrue(results["CAMPAIGN_RUNNER"]["passed"])

    def test_campaign_runner_detail(self):
        results = _results_dict()
        self.assertIn("campaign execution", results["CAMPAIGN_RUNNER"]["detail"])


class TestAuditTrail(unittest.TestCase):
    def test_audit_trail_passes(self):
        results = _results_dict()
        self.assertTrue(results["AUDIT_TRAIL"]["passed"])

    def test_audit_trail_detail(self):
        results = _results_dict()
        self.assertIn("log export", results["AUDIT_TRAIL"]["detail"])


class TestTestCoverage(unittest.TestCase):
    def test_test_coverage_passes(self):
        results = _results_dict()
        self.assertTrue(results["TEST_COVERAGE"]["passed"])

    def test_test_coverage_has_count(self):
        results = _results_dict()
        self.assertIn("tests found", results["TEST_COVERAGE"]["detail"])

    def test_test_coverage_at_least_18(self):
        results = _results_dict()
        detail = results["TEST_COVERAGE"]["detail"]
        count = int(detail.split()[0])
        self.assertGreaterEqual(count, 18)


class TestOverall(unittest.TestCase):
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        self.assertEqual(len(failed), 0, f"Failed: {[r['check'] for r in failed]}")

    def test_check_count(self):
        results = mod._checks()
        self.assertEqual(len(results), 10)

    def test_verdict_is_pass(self):
        result = _run_script("--json")
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_human_readable_output(self):
        result = _run_script()
        self.assertIn("bd-2qqu", result.stdout)
        self.assertIn("PASS", result.stdout)

    def test_exit_code_zero_on_pass(self):
        result = _run_script()
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
