"""Tests for scripts/check_migration_kit.py (bd-wpck)."""

import json
import runpy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_kit.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)


    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


mod = ScriptNamespace(runpy.run_path(str(SCRIPT)))


def _run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )


def _run_json() -> dict[str, object]:
    result = _run_script("--json")
    if result.returncode != 0:
        msg = f"{SCRIPT.name} --json failed: {result.stderr}"
        raise AssertionError(msg)
    return json.JSONDecoder().decode(result.stdout)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class TestJsonOutput(unittest.TestCase):
    def test_json_output(self):
        data = _run_json()
        self.assertEqual(data["bead_id"], "bd-wpck")
        self.assertEqual(data["section"], "15")
        self.assertIn("checks_passed", data)
        self.assertIn("checks_total", data)
        self.assertIn("verdict", data)
        self.assertIsInstance(data["checks"], list)


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

    def test_archetypes(self):
        self.assertCheckPasses("archetypes")

    def test_migration_phases(self):
        self.assertCheckPasses("migration_phases")

    def test_struct_migration_step(self):
        self.assertCheckPasses("struct_MigrationStep")

    def test_struct_compatibility_mapping(self):
        self.assertCheckPasses("struct_CompatibilityMapping")

    def test_struct_migration_kit(self):
        self.assertCheckPasses("struct_MigrationKit")

    def test_struct_migration_report(self):
        self.assertCheckPasses("struct_MigrationReport")

    def test_struct_mke_audit_record(self):
        self.assertCheckPasses("struct_MkeAuditRecord")

    def test_struct_migration_kit_ecosystem(self):
        self.assertCheckPasses("struct_MigrationKitEcosystem")

    def test_compatibility_gating(self):
        self.assertCheckPasses("compatibility_gating")

    def test_step_management(self):
        self.assertCheckPasses("step_management")

    def test_deterministic_hashing(self):
        self.assertCheckPasses("deterministic_hashing")

    def test_content_hash_surface(self):
        self.assertCheckPasses("content_hash_surface")

    def test_nan_inf_guard(self):
        self.assertCheckPasses("nan_inf_guard")

    def test_kit_versioning(self):
        self.assertCheckPasses("kit_versioning")

    def test_report_generation(self):
        self.assertCheckPasses("report_generation")

    def test_event_codes(self):
        self.assertCheckPasses("event_codes")

    def test_invariants(self):
        self.assertCheckPasses("invariants")

    def test_audit_log(self):
        self.assertCheckPasses("audit_log")

    def test_spec_alignment(self):
        self.assertCheckPasses("spec_alignment")

    def test_test_coverage(self):
        self.assertCheckPasses("test_coverage")


class TestOverall(unittest.TestCase):
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [check["check"] for check in results if not check["passed"]]
        self.assertEqual(failed, [])

    def test_verdict_is_pass(self):
        self.assertEqual(_run_json()["verdict"], "PASS")

    def test_human_output(self):
        result = _run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-wpck", result.stdout)
        self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
