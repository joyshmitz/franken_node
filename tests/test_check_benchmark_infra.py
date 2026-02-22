"""Unit tests for scripts/check_benchmark_infra.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_benchmark_infra as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-f5d")
        self.assertEqual(mod.SECTION, "10.9")

    def test_required_counts(self):
        self.assertEqual(len(mod.REQUIRED_WORKLOADS), 10)
        self.assertEqual(len(mod.REQUIRED_DIMENSIONS), 6)
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 5)


class TestFiles(unittest.TestCase):
    def test_manifest_exists(self):
        result = mod.check_file(mod.MANIFEST, "manifest")
        self.assertTrue(result["pass"])

    def test_runner_exists(self):
        result = mod.check_file(mod.RUNNER, "runner")
        self.assertTrue(result["pass"])


class TestManifestChecks(unittest.TestCase):
    def test_manifest_loads(self):
        payload, check = mod.load_json(mod.MANIFEST)
        self.assertTrue(check["pass"])
        self.assertIsInstance(payload, dict)

    def test_manifest_passes(self):
        payload, _ = mod.load_json(mod.MANIFEST)
        checks = mod.check_manifest(payload)
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestResultsChecks(unittest.TestCase):
    def test_candidate_results_shape(self):
        payload, _ = mod.load_json(mod.CANDIDATE)
        checks = mod.check_campaign_results(payload, "candidate")
        for check in checks:
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


class TestGateExecution(unittest.TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_json_roundtrip(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-f5d")


if __name__ == "__main__":
    unittest.main()
