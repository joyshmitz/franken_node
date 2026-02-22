"""Unit tests for scripts/check_counterfactual_lab.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_counterfactual_lab.py"

spec = importlib.util.spec_from_file_location("check_counterfactual_lab", SCRIPT)
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
        for key in ["schema_version", "bead_id", "section", "verdict", "checks",
                     "event_codes", "error_codes", "invariants"]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-383z")
        self.assertEqual(result["section"], "10.17")


class TestChecks(unittest.TestCase):
    def test_minimum_check_count(self):
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 20)

    def test_all_checks_have_keys(self):
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("passed", c)
            self.assertIn("detail", c)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")


class TestLabContract(unittest.TestCase):
    def test_lab_contract_fields(self):
        result = mod.run_all()
        contract = result.get("lab_contract", {})
        self.assertTrue(contract.get("requires_signed_rollout"))
        self.assertTrue(contract.get("requires_rollback_contract"))
        self.assertTrue(contract.get("requires_positive_loss_delta"))
        self.assertTrue(contract.get("requires_trace_integrity"))


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
        self.assertEqual(parsed["bead_id"], "bd-383z")

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
