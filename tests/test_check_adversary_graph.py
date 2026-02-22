"""Unit tests for scripts/check_adversary_graph.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_adversary_graph.py"

spec = importlib.util.spec_from_file_location("check_adversary_graph", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestVerdict(unittest.TestCase):
    def test_gate_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["passed"]]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures[:10])


class TestResultShape(unittest.TestCase):
    def test_required_fields(self):
        result = mod.run_all()
        for key in [
            "schema_version",
            "bead_id",
            "section",
            "verdict",
            "checks",
            "event_codes",
            "error_codes",
            "invariants",
            "policy_thresholds",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-274s")
        self.assertEqual(result["section"], "10.17")

    def test_schema_version(self):
        result = mod.run_all()
        self.assertEqual(result["schema_version"], "adversary-graph-v1.0")


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 40)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestEventCodes(unittest.TestCase):
    def test_event_code_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["event_codes"]), 8)

    def test_event_codes_list(self):
        result = mod.run_all()
        for code in ["ADV-001", "ADV-002", "ADV-003", "ADV-004",
                      "ADV-005", "ADV-006", "ADV-007", "ADV-008"]:
            self.assertIn(code, result["event_codes"])


class TestPolicyThresholds(unittest.TestCase):
    def test_threshold_values(self):
        result = mod.run_all()
        t = result["policy_thresholds"]
        self.assertAlmostEqual(t["throttle"], 0.3)
        self.assertAlmostEqual(t["isolate"], 0.5)
        self.assertAlmostEqual(t["revoke"], 0.7)
        self.assertAlmostEqual(t["quarantine"], 0.9)


class TestInvariants(unittest.TestCase):
    def test_invariant_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["invariants"]), 6)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")

    def test_self_test_has_checks(self):
        st = mod.self_test()
        self.assertGreaterEqual(st["passed"], 6)


class TestCli(unittest.TestCase):
    def test_json_output_parseable(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-274s")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
