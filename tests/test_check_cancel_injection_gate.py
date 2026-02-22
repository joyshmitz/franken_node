#!/usr/bin/env python3
"""Unit tests for scripts/check_cancel_injection_gate.py (bd-3tpg)."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_cancel_injection_gate as mod


class TestConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertEqual(len(mod.TYPES), 6)

    def test_ops_count(self):
        self.assertGreaterEqual(len(mod.OPS), 8)

    def test_control_workflows_count(self):
        self.assertEqual(len(mod.CONTROL_WORKFLOWS), 6)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 6)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 6)


class TestCheckFiles(unittest.TestCase):
    def test_all_files_exist(self):
        results = mod.check_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_files()
        self.assertEqual(len(results), 3)


class TestModuleWired(unittest.TestCase):
    def test_module_wired(self):
        results = mod.check_module_wired()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestCanonicalImport(unittest.TestCase):
    def test_canonical_import(self):
        results = mod.check_canonical_import()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_types()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestOps(unittest.TestCase):
    def test_all_ops_found(self):
        results = mod.check_ops()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestControlWorkflows(unittest.TestCase):
    def test_all_workflows_found(self):
        results = mod.check_control_workflows()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestEventCodes(unittest.TestCase):
    def test_all_event_codes(self):
        results = mod.check_event_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestErrorCodes(unittest.TestCase):
    def test_all_error_codes(self):
        results = mod.check_error_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestInvariants(unittest.TestCase):
    def test_all_invariants(self):
        results = mod.check_invariants()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestSchema(unittest.TestCase):
    def test_schema_version(self):
        results = mod.check_schema_version()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_serde(self):
        results = mod.check_serde()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_test_count(self):
        results = mod.check_test_count()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestSpecSections(unittest.TestCase):
    def test_all_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"],
                        f"Failed checks: {[c for c in result['checks'] if not c['pass']]}")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3tpg")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.15")

    def test_verdict(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)

    def test_self_test_message(self):
        ok, msg = mod.self_test()
        self.assertEqual(msg, "self_test passed")


class TestCliInterface(unittest.TestCase):
    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_cancel_injection_gate.py")],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_cancel_injection_gate.py")],
            capture_output=True, text=True
        )
        self.assertIn("PASS", result.stdout)

    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_cancel_injection_gate.py"), "--json"],
            text=True
        )
        data = json.loads(out)
        self.assertEqual(data["bead_id"], "bd-3tpg")
        self.assertTrue(data["overall_pass"])

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_cancel_injection_gate.py"), "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
