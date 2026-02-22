#!/usr/bin/env python3
"""Unit tests for scripts/check_control_lane_policy.py (bd-cuut)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_control_lane_policy.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_control_lane_policy", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        mod = load_module()
        self.assertTrue(mod.self_test())


class TestJsonOutput(unittest.TestCase):
    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-cuut")

    def test_json_has_checks_array(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        self.assertIsInstance(data["checks"], list)
        self.assertGreater(len(data["checks"]), 0)

    def test_json_ok_is_true(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])

    def test_json_section(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        self.assertEqual(data["section"], "10.15")


class TestIndividualChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        cls.checks = {c["name"]: c for c in data["checks"]}

    def _assert_pass(self, name):
        self.assertIn(name, self.checks, f"check {name} not found")
        self.assertTrue(self.checks[name]["passed"], f"check {name} failed")

    def test_source_exists(self):
        self._assert_pass("source_exists")

    def test_mod_wired(self):
        self._assert_pass("mod_wired")

    def test_lane_cancel(self):
        self._assert_pass("lane_cancel")

    def test_lane_timed(self):
        self._assert_pass("lane_timed")

    def test_lane_ready(self):
        self._assert_pass("lane_ready")

    def test_three_lanes(self):
        self._assert_pass("three_lanes")

    def test_type_control_lane(self):
        self._assert_pass("type_ControlLane")

    def test_type_control_task_class(self):
        self._assert_pass("type_ControlTaskClass")

    def test_type_lane_assignment(self):
        self._assert_pass("type_LaneAssignment")

    def test_type_lane_budget(self):
        self._assert_pass("type_LaneBudget")

    def test_type_lane_tick_metrics(self):
        self._assert_pass("type_LaneTickMetrics")

    def test_type_starvation_event(self):
        self._assert_pass("type_StarvationEvent")

    def test_type_preemption_event(self):
        self._assert_pass("type_PreemptionEvent")

    def test_type_control_lane_policy(self):
        self._assert_pass("type_ControlLanePolicy")

    def test_task_classes_19(self):
        self._assert_pass("task_classes_19")

    def test_cancel_budget(self):
        self._assert_pass("cancel_budget_20")

    def test_timed_budget(self):
        self._assert_pass("timed_budget_30")

    def test_ready_budget(self):
        self._assert_pass("ready_budget_50")

    def test_event_codes(self):
        self._assert_pass("event_codes_5")

    def test_error_codes(self):
        self._assert_pass("error_codes_8")

    def test_invariants(self):
        self._assert_pass("invariants_6")

    def test_schema_version(self):
        self._assert_pass("schema_version")

    def test_csv_header(self):
        self._assert_pass("csv_header")

    def test_cancel_max_starve(self):
        self._assert_pass("cancel_max_starve_1")

    def test_test_coverage(self):
        self._assert_pass("test_coverage")

    def test_spec_exists(self):
        self._assert_pass("spec_exists")

    def test_serde_derives(self):
        self._assert_pass("serde_derives")

    def test_op_canonical_lane(self):
        self._assert_pass("op_canonical_lane")

    def test_op_verify_all_assigned(self):
        self._assert_pass("op_verify_all_assigned")

    def test_op_verify_budget_sum(self):
        self._assert_pass("op_verify_budget_sum")

    def test_op_assign_task(self):
        self._assert_pass("op_assign_task")

    def test_op_tick(self):
        self._assert_pass("op_tick")

    def test_op_preempt_task(self):
        self._assert_pass("op_preempt_task")

    def test_op_export_csv(self):
        self._assert_pass("op_export_csv")

    def test_op_has_priority(self):
        self._assert_pass("op_has_priority")


class TestOverall(unittest.TestCase):
    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, SCRIPT], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT], capture_output=True, text=True
        )
        self.assertIn("PASS", result.stdout)

    def test_all_checks_pass(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True
        )
        data = json.loads(out)
        self.assertEqual(data["passed"], data["total"])


if __name__ == "__main__":
    unittest.main()
