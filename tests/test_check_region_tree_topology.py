#!/usr/bin/env python3
"""Unit tests for scripts/check_region_tree_topology.py (bd-2tdi)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_region_tree_topology.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_region_tree_topology", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        mod = load_module()
        self.assertTrue(mod.self_test())


class TestSelfTestCli(unittest.TestCase):
    def test_self_test_flag_exits_zero(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_self_test_flag_prints_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--self-test"],
            capture_output=True, text=True,
        )
        self.assertIn("self_test:", result.stdout)


class TestJsonOutput(unittest.TestCase):
    def test_json_flag_produces_valid_json(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertIn("bead_id", data)
        self.assertEqual(data["bead_id"], "bd-2tdi")

    def test_json_has_checks_array(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertIsInstance(data["checks"], list)
        self.assertGreater(len(data["checks"]), 0)

    def test_json_verdict_is_pass(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertEqual(data["verdict"], "PASS")

    def test_json_ok_is_true(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])

    def test_json_section(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertEqual(data["section"], "10.15")

    def test_json_has_events(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertIn("events", data)
        self.assertEqual(len(data["events"]), 8)


class TestIndividualChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
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

    def test_spec_exists(self):
        self._assert_pass("spec_exists")

    def test_spec_mentions_hierarchy(self):
        self._assert_pass("spec_mentions_hierarchy")

    def test_spec_schema_version(self):
        self._assert_pass("spec_schema_version")

    def test_type_region_id(self):
        self._assert_pass("type_RegionId")

    def test_type_region_state(self):
        self._assert_pass("type_RegionState")

    def test_type_region_tree(self):
        self._assert_pass("type_RegionTree")

    def test_type_region_handle(self):
        self._assert_pass("type_RegionHandle")

    def test_state_active(self):
        self._assert_pass("state_active")

    def test_state_draining(self):
        self._assert_pass("state_draining")

    def test_state_closed(self):
        self._assert_pass("state_closed")

    def test_op_open_region(self):
        self._assert_pass("op_open_region")

    def test_op_register_task(self):
        self._assert_pass("op_register_task")

    def test_op_close(self):
        self._assert_pass("op_close")

    def test_op_force_terminate(self):
        self._assert_pass("op_force_terminate")

    def test_invariants_3(self):
        self._assert_pass("invariants_3")

    def test_event_codes_8(self):
        self._assert_pass("event_codes_8")

    def test_error_codes_4(self):
        self._assert_pass("error_codes_4")

    def test_trace_exists(self):
        self._assert_pass("trace_exists")

    def test_trace_valid_jsonl(self):
        self._assert_pass("trace_valid_jsonl")

    def test_trace_has_lifecycle_actions(self):
        self._assert_pass("trace_has_lifecycle_actions")

    def test_unit_tests_present(self):
        self._assert_pass("unit_tests_present")

    def test_serde_derives(self):
        self._assert_pass("serde_derives")

    def test_schema_version(self):
        self._assert_pass("schema_version")

    def test_jsonl_export(self):
        self._assert_pass("jsonl_export")


class TestOverall(unittest.TestCase):
    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, SCRIPT], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)

    def test_human_output_contains_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT], capture_output=True, text=True,
        )
        self.assertIn("PASS", result.stdout)

    def test_all_checks_pass(self):
        out = subprocess.check_output(
            [sys.executable, SCRIPT, "--json"], text=True,
        )
        data = json.loads(out)
        self.assertEqual(data["passed"], data["total"])


if __name__ == "__main__":
    unittest.main()
