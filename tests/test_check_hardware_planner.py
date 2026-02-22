#!/usr/bin/env python3
"""Unit tests for scripts/check_hardware_planner.py (bd-2o8b)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Load the module via importlib to avoid naming issues
_spec = importlib.util.spec_from_file_location(
    "check_mod", ROOT / "scripts" / "check_hardware_planner.py"
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class TestSelfTest(unittest.TestCase):
    """Verify the self_test function produces a correct verdict."""

    def test_self_test_verdict_pass(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS",
                         f"Expected PASS, got failures: "
                         f"{[c for c in result['checks'] if not c['passed']]}")

    def test_self_test_has_bead(self):
        result = mod.self_test()
        self.assertEqual(result["bead"], "bd-2o8b")

    def test_self_test_has_section(self):
        result = mod.self_test()
        self.assertEqual(result["section"], "10.17")


class TestAllChecksPass(unittest.TestCase):
    """Every individual check should pass in the real repo."""

    def test_all_checks_pass(self):
        checks = mod._checks()
        for c in checks:
            self.assertTrue(c["passed"], f"Check failed: {c['check']}: {c['detail']}")


class TestRunChecks(unittest.TestCase):
    """Verify run_checks() output structure."""

    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"],
                        f"Failed: {[c for c in result['checks'] if not c['passed']]}")

    def test_verdict_is_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2o8b")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.17")

    def test_summary_no_failures(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0)

    def test_events_field_count(self):
        result = mod.run_checks()
        self.assertEqual(len(result["events"]), 12)


class TestRunAll(unittest.TestCase):
    """Verify run_all() output structure."""

    def test_run_all_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed: {[c for c in result['checks'] if not c['passed']]}")

    def test_run_all_has_planner_event_codes(self):
        result = mod.run_all()
        self.assertEqual(len(result["event_codes"]), 5)
        self.assertIn("PLANNER_PLACEMENT_START", result["event_codes"])

    def test_run_all_has_planner_error_codes(self):
        result = mod.run_all()
        self.assertEqual(len(result["error_codes"]), 6)
        self.assertIn("ERR_PLANNER_CONSTRAINT_VIOLATED", result["error_codes"])

    def test_run_all_has_planner_invariants(self):
        result = mod.run_all()
        self.assertEqual(len(result["invariants"]), 4)
        self.assertIn("INV-PLANNER-REPRODUCIBLE", result["invariants"])

    def test_run_all_has_schema_version(self):
        result = mod.run_all()
        self.assertEqual(result["schema_version"], "hwp-v1.0")


class TestJsonOutput(unittest.TestCase):
    """Verify --json CLI flag produces valid JSON with correct fields."""

    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, str(ROOT / "scripts" / "check_hardware_planner.py"), "--json"],
            text=True,
        )
        data = json.loads(out)
        self.assertEqual(data["bead_id"], "bd-2o8b")
        self.assertTrue(data["overall_pass"])
        self.assertEqual(data["verdict"], "PASS")


class TestCheckStructure(unittest.TestCase):
    """Verify each check dict has the required keys."""

    def test_check_keys(self):
        checks = mod._checks()
        for c in checks:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestMinimumCheckCount(unittest.TestCase):
    """We expect a minimum number of checks to be performed."""

    def test_at_least_25_checks(self):
        checks = mod._checks()
        self.assertGreaterEqual(len(checks), 25,
                                f"Only {len(checks)} checks found, expected >= 25")


class TestEventCodesPresent(unittest.TestCase):
    """All 12 internal event codes should be defined in the module constants."""

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 12)

    def test_event_codes_all_hwp(self):
        for ec in mod.EVENT_CODES:
            self.assertTrue(ec.startswith("HWP-"), f"Unexpected prefix: {ec}")


class TestPlannerEventCodesPresent(unittest.TestCase):
    """All 5 semantic planner event codes should be defined."""

    def test_planner_event_codes_count(self):
        self.assertEqual(len(mod.PLANNER_EVENT_CODES), 5)

    def test_planner_event_codes_prefix(self):
        for ec in mod.PLANNER_EVENT_CODES:
            self.assertTrue(ec.startswith("PLANNER_"), f"Unexpected prefix: {ec}")


class TestErrorCodesPresent(unittest.TestCase):
    """All 10 internal error codes should be defined."""

    def test_error_codes_count(self):
        self.assertEqual(len(mod.ERROR_CODES), 10)


class TestPlannerErrorCodesPresent(unittest.TestCase):
    """All 6 semantic planner error codes should be defined."""

    def test_planner_error_codes_count(self):
        self.assertEqual(len(mod.PLANNER_ERROR_CODES), 6)

    def test_planner_error_codes_prefix(self):
        for ec in mod.PLANNER_ERROR_CODES:
            self.assertTrue(ec.startswith("ERR_PLANNER_"), f"Unexpected prefix: {ec}")


class TestInvariantsPresent(unittest.TestCase):
    """All 8 internal invariants should be defined."""

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 8)


class TestPlannerInvariantsPresent(unittest.TestCase):
    """All 4 semantic planner invariants should be defined."""

    def test_planner_invariants_count(self):
        self.assertEqual(len(mod.PLANNER_INVARIANTS), 4)

    def test_planner_invariants_prefix(self):
        for inv in mod.PLANNER_INVARIANTS:
            self.assertTrue(inv.startswith("INV-PLANNER-"), f"Unexpected prefix: {inv}")


class TestMissingSource(unittest.TestCase):
    """When source file is missing, the relevant checks should fail."""

    def test_missing_source_detection(self):
        original = mod.SRC
        try:
            mod.SRC = ROOT / "nonexistent" / "hardware_planner.rs"
            checks = mod._checks()
            src_check = next(c for c in checks if c["check"] == "source file exists")
            self.assertFalse(src_check["passed"])
        finally:
            mod.SRC = original


class TestMissingSpec(unittest.TestCase):
    """When spec contract is missing, the relevant check should fail."""

    def test_missing_spec_detection(self):
        original = mod.SPEC
        try:
            mod.SPEC = ROOT / "nonexistent" / "bd-2o8b_contract.md"
            checks = mod._checks()
            spec_check = next(c for c in checks if c["check"] == "spec contract exists")
            self.assertFalse(spec_check["passed"])
        finally:
            mod.SPEC = original


class TestCliInterface(unittest.TestCase):
    """CLI invocation tests."""

    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_hardware_planner.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_hardware_planner.py")],
            capture_output=True, text=True,
        )
        self.assertIn("PASS", result.stdout)

    def test_self_test_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_hardware_planner.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("self_test passed", result.stdout)

    def test_self_test_json_cli(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_hardware_planner.py"),
             "--self-test", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["bead"], "bd-2o8b")


if __name__ == "__main__":
    unittest.main()
