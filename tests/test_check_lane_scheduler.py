#!/usr/bin/env python3
"""Unit tests for scripts/check_lane_scheduler.py (bd-qlc6)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_lane_scheduler.py")
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "lane_scheduler.rs")


def load_module():
    spec = importlib.util.spec_from_file_location("check_lane_scheduler", SCRIPT)
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
        self.assertEqual(data["bead_id"], "bd-qlc6")

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
        self.assertEqual(data["section"], "10.14")


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

    def test_lane_controlcritical(self):
        self._assert_pass("lane_controlcritical")

    def test_lane_remoteeffect(self):
        self._assert_pass("lane_remoteeffect")

    def test_lane_maintenance(self):
        self._assert_pass("lane_maintenance")

    def test_lane_background(self):
        self._assert_pass("lane_background")

    def test_lane_count_4(self):
        self._assert_pass("lane_count_4")

    def test_taskclass_epoch_transition(self):
        self._assert_pass("taskclass_epoch_transition")

    def test_taskclass_barrier_coordination(self):
        self._assert_pass("taskclass_barrier_coordination")

    def test_taskclass_marker_write(self):
        self._assert_pass("taskclass_marker_write")

    def test_taskclass_remote_computation(self):
        self._assert_pass("taskclass_remote_computation")

    def test_taskclass_artifact_upload(self):
        self._assert_pass("taskclass_artifact_upload")

    def test_taskclass_artifact_eviction(self):
        self._assert_pass("taskclass_artifact_eviction")

    def test_taskclass_garbage_collection(self):
        self._assert_pass("taskclass_garbage_collection")

    def test_taskclass_compaction(self):
        self._assert_pass("taskclass_compaction")

    def test_taskclass_telemetry_export(self):
        self._assert_pass("taskclass_telemetry_export")

    def test_taskclass_log_rotation(self):
        self._assert_pass("taskclass_log_rotation")

    def test_type_scheduler_lane(self):
        self._assert_pass("type_SchedulerLane")

    def test_type_task_class(self):
        self._assert_pass("type_TaskClass")

    def test_type_lane_config(self):
        self._assert_pass("type_LaneConfig")

    def test_type_lane_mapping_policy(self):
        self._assert_pass("type_LaneMappingPolicy")

    def test_type_lane_counters(self):
        self._assert_pass("type_LaneCounters")

    def test_type_lane_scheduler_error(self):
        self._assert_pass("type_LaneSchedulerError")

    def test_type_lane_scheduler(self):
        self._assert_pass("type_LaneScheduler")

    def test_event_codes_10(self):
        self._assert_pass("event_codes_10")

    def test_error_codes_8(self):
        self._assert_pass("error_codes_8")

    def test_invariants_6(self):
        self._assert_pass("invariants_6")

    def test_schema_version(self):
        self._assert_pass("schema_version")

    def test_default_policy(self):
        self._assert_pass("default_policy")

    def test_jsonl_export(self):
        self._assert_pass("jsonl_export")

    def test_starvation_window(self):
        self._assert_pass("starvation_window")

    def test_test_coverage(self):
        self._assert_pass("test_coverage")

    def test_spec_exists(self):
        self._assert_pass("spec_exists")

    def test_spec_mentions_lanes(self):
        self._assert_pass("spec_mentions_lanes")

    def test_serde_derives(self):
        self._assert_pass("serde_derives")

    def test_policy_validation(self):
        self._assert_pass("policy_validation")

    def test_op_assign_task(self):
        self._assert_pass("op_assign_task")

    def test_op_complete_task(self):
        self._assert_pass("op_complete_task")

    def test_op_check_starvation(self):
        self._assert_pass("op_check_starvation")

    def test_op_reload_policy(self):
        self._assert_pass("op_reload_policy")

    def test_op_telemetry_snapshot(self):
        self._assert_pass("op_telemetry_snapshot")

    def test_op_export_audit_log_jsonl(self):
        self._assert_pass("op_export_audit_log_jsonl")


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
