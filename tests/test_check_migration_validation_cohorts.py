#!/usr/bin/env python3
"""Tests for bd-sxt5: Migration validation cohorts gate."""

import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_validation_cohorts.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


mod = ScriptNamespace(runpy.run_path(str(SCRIPT)))


def _run_json() -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    return json.JSONDecoder().decode(proc.stdout)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestJsonOutput(unittest.TestCase):
    def test_json_has_required_keys(self):
        data = _run_json()
        for key in ("bead_id", "section", "gate_script", "checks_passed", "checks_total", "verdict", "checks"):
            self.assertIn(key, data)

    def test_bead_id(self):
        data = _run_json()
        self.assertEqual(data["bead_id"], "bd-sxt5")
        self.assertEqual(data["section"], "15")

    def test_verdict_field(self):
        self.assertIn(_run_json()["verdict"], ("PASS", "FAIL"))

    def test_checks_is_list(self):
        data = _run_json()
        self.assertIsInstance(data["checks"], list)
        self.assertGreaterEqual(len(data["checks"]), 16)

    def test_each_check_has_fields(self):
        for check in _run_json()["checks"]:
            self.assertIn("check", check)
            self.assertIn("passed", check)


class TestIndividualChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {check["check"]: check for check in mod._checks()}

    def assertCheckPasses(self, name: str) -> None:
        self.assertTrue(self.results[name]["passed"], self.results[name]["detail"])

    def test_source_exists(self):
        self.assertCheckPasses("source_exists")

    def test_module_wiring(self):
        self.assertCheckPasses("module_wiring")

    def test_cohort_categories(self):
        self.assertCheckPasses("cohort_categories")

    def test_struct_project_cohort(self):
        self.assertCheckPasses("struct_ProjectCohort")

    def test_struct_validation_run(self):
        self.assertCheckPasses("struct_ValidationRun")

    def test_struct_cohort_report(self):
        self.assertCheckPasses("struct_CohortReport")

    def test_struct_migration_validation_cohorts(self):
        self.assertCheckPasses("struct_MigrationValidationCohorts")

    def test_determinism_check(self):
        self.assertCheckPasses("determinism_check")

    def test_reproduction_command(self):
        self.assertCheckPasses("reproduction_command")

    def test_drift_detection(self):
        self.assertCheckPasses("drift_detection")

    def test_coverage_analysis(self):
        self.assertCheckPasses("coverage_analysis")

    def test_content_hash(self):
        self.assertCheckPasses("content_hash")

    def test_event_codes(self):
        self.assertCheckPasses("event_codes")

    def test_invariants(self):
        self.assertCheckPasses("invariants")

    def test_audit_log(self):
        self.assertCheckPasses("audit_log")

    def test_schema_version(self):
        self.assertCheckPasses("schema_version")

    def test_spec_alignment(self):
        self.assertCheckPasses("spec_alignment")

    def test_test_coverage(self):
        self.assertCheckPasses("test_coverage")


class TestOverall(unittest.TestCase):
    def test_all_pass(self):
        failed = [check["check"] for check in mod._checks() if not check["passed"]]
        self.assertEqual(failed, [])

    def test_minimum_check_count(self):
        self.assertGreaterEqual(len(mod._checks()), 16)


if __name__ == "__main__":
    unittest.main()
