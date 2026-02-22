"""Unit tests for scripts/check_intent_firewall.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_intent_firewall.py"

spec = importlib.util.spec_from_file_location("check_intent_firewall", SCRIPT)
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
                     "event_codes", "error_codes", "invariants", "firewall_contract"]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3l2p")
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


class TestFirewallContract(unittest.TestCase):
    def test_contract_fields(self):
        result = mod.run_all()
        fc = result["firewall_contract"]
        self.assertTrue(fc["fail_closed_unclassifiable"])
        self.assertTrue(fc["risky_default_deny"])
        self.assertTrue(fc["receipt_every_decision"])
        self.assertTrue(fc["extension_scoped"])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")


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
        self.assertEqual(parsed["bead_id"], "bd-3l2p")

    def test_self_test_exit_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_build_report_creates_file(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--build-report", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report_path = ROOT / "artifacts/10.17/intent_firewall_eval_report.json"
        self.assertTrue(report_path.exists())
        data = json.loads(report_path.read_text())
        self.assertEqual(data["bead_id"], "bd-3l2p")


if __name__ == "__main__":
    unittest.main()
