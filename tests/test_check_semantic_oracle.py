"""Unit tests for scripts/check_semantic_oracle.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_semantic_oracle.py"

spec = importlib.util.spec_from_file_location("check_semantic_oracle", SCRIPT)
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
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-al8i")
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


class TestDivergenceContract(unittest.TestCase):
    def test_contract_present(self):
        result = mod.run_all()
        self.assertIn("divergence_contract", result)
        contract = result["divergence_contract"]
        self.assertTrue(contract["high_risk_blocks_release"])
        self.assertTrue(contract["low_risk_requires_receipt"])
        self.assertTrue(contract["receipts_link_l1_oracle"])
        self.assertTrue(contract["classification_is_deterministic"])


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
        self.assertEqual(parsed["bead_id"], "bd-al8i")

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
        report_path = ROOT / "artifacts/10.17/semantic_oracle_report.json"
        self.assertTrue(report_path.exists(), f"report not found at {report_path}")


if __name__ == "__main__":
    unittest.main()
