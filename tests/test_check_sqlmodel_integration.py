"""Unit tests for scripts/check_sqlmodel_integration.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_sqlmodel_integration as mod


class TestConstants(unittest.TestCase):
    def test_model_names_count(self):
        self.assertEqual(len(mod.MODEL_NAMES), 21)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 5)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 8)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 10)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 35)


class TestCheckFile(unittest.TestCase):
    def test_existing(self):
        result = mod.check_file(mod.IMPL, "test")
        self.assertTrue(result["pass"])

    def test_missing(self):
        result = mod.check_file(Path("/no"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, ["pub enum ModelClassification"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckImplTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_impl_test_count()
        self.assertTrue(result["pass"])


class TestCheckCsv(unittest.TestCase):
    def test_csv_passes(self):
        results = mod.check_csv()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_csv_has_21_rows(self):
        results = mod.check_csv()
        row_checks = [r for r in results if "row count" in r["check"]]
        self.assertTrue(row_checks[0]["pass"])

    def test_csv_all_models_present(self):
        results = mod.check_csv()
        model_checks = [r for r in results if r["check"].startswith("CSV: model")]
        self.assertEqual(len(model_checks), 21)
        for r in model_checks:
            self.assertTrue(r["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_passes(self):
        results = mod.check_spec()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"])

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1v65")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.16")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, _ = mod.self_test()
        self.assertTrue(ok)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1v65")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestAllTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllEvents(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllInvariants(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllTests(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


if __name__ == "__main__":
    unittest.main()
