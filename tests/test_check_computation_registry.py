"""Tests for check_computation_registry.py verification script."""
import importlib.util
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_computation_registry.py")

def _load_module():
    spec = importlib.util.spec_from_file_location("check_computation_registry", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class TestCheckComputationRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_checks_returns_list(self):
        results = self.mod._checks()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_all_checks_have_required_keys(self):
        for r in self.mod._checks():
            self.assertIn("check", r)
            self.assertIn("passed", r)
            self.assertIn("detail", r)

    def test_all_checks_pass(self):
        for r in self.mod._checks():
            self.assertTrue(r["passed"], f"{r['check']}: {r['detail']}")

    def test_source_exists_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("SOURCE_EXISTS", results)
        self.assertTrue(results["SOURCE_EXISTS"]["passed"])

    def test_event_codes_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("EVENT_CODES", results)
        self.assertTrue(results["EVENT_CODES"]["passed"])

    def test_error_codes_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("ERROR_CODES", results)
        self.assertTrue(results["ERROR_CODES"]["passed"])

    def test_canonical_name_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("CANONICAL_NAME_VALIDATOR", results)
        self.assertTrue(results["CANONICAL_NAME_VALIDATOR"]["passed"])

    def test_core_types_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("CORE_TYPES", results)
        self.assertTrue(results["CORE_TYPES"]["passed"])

    def test_remotecap_gating_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("REMOTECAP_GATING", results)
        self.assertTrue(results["REMOTECAP_GATING"]["passed"])

    def test_catalog_roundtrip_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("CATALOG_ROUNDTRIP", results)
        self.assertTrue(results["CATALOG_ROUNDTRIP"]["passed"])

    def test_audit_trail_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("AUDIT_TRAIL", results)
        self.assertTrue(results["AUDIT_TRAIL"]["passed"])

    def test_test_coverage_check(self):
        results = {r["check"]: r for r in self.mod._checks()}
        self.assertIn("TEST_COVERAGE", results)
        self.assertTrue(results["TEST_COVERAGE"]["passed"])

    def test_self_test_passes(self):
        self.assertTrue(self.mod.self_test())

    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["bead"], "bd-ac83")
        self.assertEqual(report["verdict"], "PASS")

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)

if __name__ == "__main__":
    unittest.main()
