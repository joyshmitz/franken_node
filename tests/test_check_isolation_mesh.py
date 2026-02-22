"""Unit tests for scripts/check_isolation_mesh.py."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_isolation_mesh.py"

_spec = importlib.util.spec_from_file_location("check_isolation_mesh", SCRIPT)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


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
            "schema_version", "bead_id", "section", "verdict",
            "checks", "event_codes", "error_codes", "invariants",
        ]:
            self.assertIn(key, result)

    def test_bead_and_section(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-gad3")
        self.assertEqual(result["section"], "10.17")

    def test_schema_version(self):
        result = mod.run_all()
        self.assertEqual(result["schema_version"], "isolation-mesh-v1.0")


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

    def test_event_codes_present(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["event_codes"]), 5)

    def test_error_codes_present(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["error_codes"]), 6)

    def test_invariants_present(self):
        result = mod.run_all()
        self.assertGreaterEqual(len(result["invariants"]), 4)


class TestMeshContract(unittest.TestCase):
    def test_mesh_contract_fields(self):
        result = mod.run_all()
        contract = result.get("mesh_contract", {})
        self.assertTrue(contract.get("monotonic_elevation_only"))
        self.assertTrue(contract.get("demotion_forbidden"))
        self.assertTrue(contract.get("policy_continuity_preserved"))
        self.assertTrue(contract.get("latency_budget_enforced"))


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        st = mod.self_test()
        self.assertEqual(st["verdict"], "PASS")

    def test_self_test_has_checks(self):
        st = mod.self_test()
        self.assertGreaterEqual(st["passed"], 5)


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
        self.assertEqual(parsed["bead_id"], "bd-gad3")

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
