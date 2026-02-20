"""Unit tests for scripts/check_frankensqlite_migration.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_frankensqlite_migration as mod


class TestConstants(unittest.TestCase):
    def test_required_domains_count(self):
        self.assertEqual(len(mod.REQUIRED_DOMAINS), 9)

    def test_required_doc_sections_count(self):
        self.assertEqual(len(mod.REQUIRED_DOC_SECTIONS), 4)

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 6)

    def test_required_test_names_count(self):
        self.assertEqual(len(mod.REQUIRED_TEST_NAMES), 12)

    def test_required_domain_names_unique(self):
        names = [d["name"] for d in mod.REQUIRED_DOMAINS]
        self.assertEqual(len(names), len(set(names)))


class TestCheckFile(unittest.TestCase):
    def test_existing_file(self):
        result = mod.check_file(mod.MIGRATION_DOC, "migration doc")
        self.assertTrue(result["pass"])

    def test_missing_file(self):
        result = mod.check_file(Path("/nonexistent/file"), "missing")
        self.assertFalse(result["pass"])
        self.assertIn("MISSING", result["detail"])


class TestCheckDoc(unittest.TestCase):
    def test_doc_passes(self):
        results = mod.check_doc()
        for item in results:
            self.assertTrue(item["pass"], f"Failed: {item['check']} -> {item['detail']}")

    def test_doc_sections_present(self):
        results = mod.check_doc()
        section_checks = [r for r in results if r["check"].startswith("doc: section")]
        self.assertEqual(len(section_checks), 4)
        for item in section_checks:
            self.assertTrue(item["pass"], item["detail"])


class TestLoadReport(unittest.TestCase):
    def test_load_report_success(self):
        report, checks = mod.load_report()
        self.assertIsInstance(report, dict)
        self.assertGreaterEqual(len(checks), 2)
        self.assertTrue(all(c["pass"] for c in checks))


class TestCheckReport(unittest.TestCase):
    def test_check_report_passes(self):
        report, _ = mod.load_report()
        results = mod.check_report(report)
        for item in results:
            self.assertTrue(item["pass"], f"Failed: {item['check']} -> {item['detail']}")

    def test_report_contains_all_domains(self):
        report, _ = mod.load_report()
        results = mod.check_report(report)
        domain_checks = [
            r
            for r in results
            if r["check"].startswith("report: domain ")
            and r["check"] != "report: domain count"
        ]
        self.assertEqual(len(domain_checks), 9)
        self.assertTrue(all(r["pass"] for r in domain_checks))

    def test_report_idempotency_all_pass(self):
        report, _ = mod.load_report()
        results = mod.check_report(report)
        checks = [r for r in results if r["check"].startswith("report: idempotency ")]
        self.assertEqual(len(checks), 9)
        self.assertTrue(all(r["pass"] for r in checks))

    def test_report_rollback_all_pass(self):
        report, _ = mod.load_report()
        results = mod.check_report(report)
        checks = [r for r in results if r["check"].startswith("report: rollback ")]
        self.assertEqual(len(checks), 9)
        self.assertTrue(all(r["pass"] for r in checks))


class TestMigrationTestChecks(unittest.TestCase):
    def test_migration_test_passes(self):
        results = mod.check_migration_test()
        for item in results:
            self.assertTrue(item["pass"], f"Failed: {item['check']} -> {item['detail']}")

    def test_event_codes_present(self):
        results = mod.check_migration_test()
        checks = [r for r in results if r["check"].startswith("migration test: event code")]
        self.assertEqual(len(checks), 6)
        self.assertTrue(all(r["pass"] for r in checks))

    def test_required_tests_present(self):
        results = mod.check_migration_test()
        checks = [r for r in results if r["check"].startswith("migration test: ") and "event code" not in r["check"] and "test count" not in r["check"] and "exists" not in r["check"]]
        self.assertEqual(len(checks), 12)
        self.assertTrue(all(r["pass"] for r in checks))


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")

    def test_metadata(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-26ux")
        self.assertEqual(result["section"], "10.16")

    def test_summary(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertGreater(result["summary"]["passing"], 0)

    def test_check_shape(self):
        result = mod.run_checks()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = mod.run_checks()
        blob = json.dumps(result, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-26ux")

    def test_json_has_expected_keys(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "test_count", "summary", "checks"]:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
