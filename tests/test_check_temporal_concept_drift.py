"""Unit tests for scripts/check_temporal_concept_drift.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_temporal_concept_drift as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-v4ps")
        self.assertEqual(mod.SECTION, "12")

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 5)

    def test_required_contract_terms(self):
        self.assertGreaterEqual(len(mod.REQUIRED_CONTRACT_TERMS), 9)


class TestFileChecks(unittest.TestCase):
    def test_contract_exists(self):
        result = mod.check_file(mod.CONTRACT, "contract")
        self.assertTrue(result["pass"])

    def test_report_exists(self):
        result = mod.check_file(mod.REPORT, "report")
        self.assertTrue(result["pass"])


class TestContractChecks(unittest.TestCase):
    def test_contract_passes(self):
        checks = mod.check_contract()
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestReportLoad(unittest.TestCase):
    def test_load_report_success(self):
        data, checks = mod.load_report()
        self.assertIsInstance(data, dict)
        self.assertTrue(all(c["pass"] for c in checks))


class TestHelpers(unittest.TestCase):
    def test_evaluate_models_shape(self):
        data, _ = mod.load_report()
        out = mod.evaluate_models(data)
        for key in [
            "models_total",
            "models_stale",
            "stale_models_blocked",
            "models_exceeding_drift_threshold",
            "recalibration_run_ids_valid",
            "drift_threshold_pct",
        ]:
            self.assertIn(key, out)

    def test_evaluate_models_values(self):
        data, _ = mod.load_report()
        out = mod.evaluate_models(data)
        self.assertEqual(out["models_total"], 3)
        self.assertGreaterEqual(out["models_stale"], 1)


class TestReportChecks(unittest.TestCase):
    def test_report_checks_pass(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")

    def test_scenario_b_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "scenario B: >5% drift triggers recalibration")
        self.assertTrue(item["pass"])

    def test_adversarial_check_present(self):
        data, _ = mod.load_report()
        checks = mod.check_report(data)
        item = next(c for c in checks if c["check"] == "adversarial: stale-model unblock attempt is detected")
        self.assertTrue(item["pass"])


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_result_shape(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


class TestJsonRoundTrip(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-v4ps")


if __name__ == "__main__":
    unittest.main()
