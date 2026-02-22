#!/usr/bin/env python3
"""Unit tests for scripts/check_control_lane_mapping.py (bd-cuut).

Tests both the module-level API and the CLI interface of the control-plane
lane mapping verification gate.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_control_lane_mapping as mod


class TestConstants(unittest.TestCase):
    """Verify the verification script's own constants are consistent."""

    def test_types_count(self):
        self.assertEqual(len(mod.TYPES), 9)

    def test_ops_count(self):
        self.assertGreaterEqual(len(mod.OPS), 12)

    def test_lanes_count(self):
        self.assertEqual(len(mod.LANES), 3)

    def test_cancel_tasks_count(self):
        self.assertEqual(len(mod.CANCEL_TASKS), 4)

    def test_timed_tasks_count(self):
        self.assertEqual(len(mod.TIMED_TASKS), 5)

    def test_ready_tasks_count(self):
        self.assertEqual(len(mod.READY_TASKS), 5)

    def test_all_tasks_count(self):
        self.assertEqual(len(mod.ALL_TASKS), 14)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 6)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 6)


class TestCheckFiles(unittest.TestCase):
    """Verify file existence checks work correctly."""

    def test_all_files_exist(self):
        results = mod.check_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_files()
        self.assertEqual(len(results), 2)


class TestModuleWired(unittest.TestCase):
    """Verify module wiring."""

    def test_module_wired(self):
        results = mod.check_module_wired()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestTypes(unittest.TestCase):
    """Verify all expected types are present."""

    def test_all_types_found(self):
        results = mod.check_types()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_type_count(self):
        results = mod.check_types()
        self.assertEqual(len(results), 9)


class TestOps(unittest.TestCase):
    """Verify all expected operations are present."""

    def test_all_ops_found(self):
        results = mod.check_ops()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_ops_count(self):
        results = mod.check_ops()
        self.assertEqual(len(results), 12)


class TestLanes(unittest.TestCase):
    """Verify lane definitions."""

    def test_all_lanes_found(self):
        results = mod.check_lanes()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_lane_count(self):
        results = mod.check_lanes()
        self.assertEqual(len(results), 3)


class TestTaskClasses(unittest.TestCase):
    """Verify task class definitions."""

    def test_all_task_classes_found(self):
        results = mod.check_task_classes()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")

    def test_task_class_count(self):
        results = mod.check_task_classes()
        self.assertEqual(len(results), 14)


class TestLaneAssignments(unittest.TestCase):
    """Verify lane assignments."""

    def test_cancel_lane(self):
        results = mod.check_cancel_lane_tasks()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_timed_lane(self):
        results = mod.check_timed_lane_tasks()
        self.assertTrue(results[0]["pass"], results[0]["detail"])

    def test_ready_lane(self):
        results = mod.check_ready_lane_tasks()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestEventCodes(unittest.TestCase):
    """Verify event codes."""

    def test_all_event_codes(self):
        results = mod.check_event_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestErrorCodes(unittest.TestCase):
    """Verify error codes."""

    def test_all_error_codes(self):
        results = mod.check_error_codes()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestInvariants(unittest.TestCase):
    """Verify invariants."""

    def test_all_invariants(self):
        results = mod.check_invariants()
        self.assertTrue(results[0]["pass"], results[0]["detail"])


class TestBudget(unittest.TestCase):
    """Verify budget defaults."""

    def test_budget_defaults(self):
        results = mod.check_budget_defaults()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


class TestSchema(unittest.TestCase):
    """Verify schema and serde."""

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
    """Verify spec contract sections."""

    def test_all_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Missing: {r['check']}")


class TestRunChecks(unittest.TestCase):
    """Verify the aggregate run_checks function."""

    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"],
                        f"Failed checks: {[c for c in result['checks'] if not c['pass']]}")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-cuut")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.15")

    def test_verdict(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_summary_counts(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)
        self.assertEqual(result["summary"]["passing"], result["summary"]["total"])


class TestSelfTest(unittest.TestCase):
    """Verify the self_test function."""

    def test_self_test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)

    def test_self_test_message(self):
        ok, msg = mod.self_test()
        self.assertEqual(msg, "self_test passed")


class TestCliInterface(unittest.TestCase):
    """Verify the CLI interface works correctly."""

    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_lane_mapping.py")],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_lane_mapping.py")],
            capture_output=True, text=True
        )
        self.assertIn("PASS", result.stdout)

    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_control_lane_mapping.py"), "--json"],
            text=True
        )
        data = json.loads(out)
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-cuut")
        self.assertTrue(data["overall_pass"])

    def test_json_has_checks_array(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_control_lane_mapping.py"), "--json"],
            text=True
        )
        data = json.loads(out)
        self.assertIsInstance(data["checks"], list)
        self.assertGreater(len(data["checks"]), 0)

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_control_lane_mapping.py"), "--self-test"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
