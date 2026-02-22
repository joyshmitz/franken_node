"""Unit tests for scripts/check_operator_runbooks.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_operator_runbooks as mod


class TestConstants(unittest.TestCase):
    def test_bead_and_section(self):
        self.assertEqual(mod.BEAD_ID, "bd-nr4")
        self.assertEqual(mod.SECTION, "10.8")

    def test_runbook_count(self):
        self.assertEqual(len(mod.RUNBOOKS), 6)

    def test_required_coverage_tags(self):
        self.assertEqual(len(mod.REQUIRED_COVERAGE_TAGS), 5)


class TestHelpers(unittest.TestCase):
    def test_parse_date_valid(self):
        self.assertIsNotNone(mod.parse_date("2026-02-21"))

    def test_parse_date_invalid(self):
        self.assertIsNone(mod.parse_date("2026/02/21"))

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


class TestRepositoryChecks(unittest.TestCase):
    def test_schema_exists(self):
        result = mod.check_file(mod.SCHEMA_PATH, "schema")
        self.assertTrue(result["pass"])

    def test_index_exists(self):
        result = mod.check_file(mod.INDEX_PATH, "index")
        self.assertTrue(result["pass"])

    def test_drill_results_exist(self):
        result = mod.check_file(mod.DRILL_RESULTS, "drill")
        self.assertTrue(result["pass"])


class TestGateExecution(unittest.TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-nr4")


if __name__ == "__main__":
    unittest.main()
