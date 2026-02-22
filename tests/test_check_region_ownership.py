"""Tests for scripts/check_region_ownership.py (bd-2tdi)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_region_ownership as gate


class TestConstants(unittest.TestCase):
    def test_event_codes_count(self):
        self.assertEqual(len(gate.REQUIRED_EVENT_CODES), 5)

    def test_region_kinds_count(self):
        self.assertEqual(len(gate.REQUIRED_REGION_KINDS), 4)

    def test_required_types_count(self):
        self.assertEqual(len(gate.REQUIRED_TYPES), 7)

    def test_bead_id(self):
        self.assertEqual(gate.BEAD, "bd-2tdi")

    def test_section(self):
        self.assertEqual(gate.SECTION, "10.15")


class TestCheckHelper(unittest.TestCase):
    def test_pass_check(self):
        result = gate._check("test", True, "ok")
        self.assertTrue(result["passed"])
        self.assertEqual(result["detail"], "ok")

    def test_fail_check_default_detail(self):
        result = gate._check("test", False)
        self.assertFalse(result["passed"])
        self.assertEqual(result["detail"], "failed")

    def test_pass_check_default_detail(self):
        result = gate._check("test", True)
        self.assertTrue(result["passed"])
        self.assertEqual(result["detail"], "ok")


class TestFileChecks(unittest.TestCase):
    def test_existing_file(self):
        result = gate.check_file_exists(gate.REGION_MODULE, "test")
        self.assertTrue(result["passed"])

    def test_missing_file(self):
        result = gate.check_file_exists(Path("/nonexistent"), "test")
        self.assertFalse(result["passed"])
        self.assertIn("MISSING", result["detail"])


class TestModuleTypes(unittest.TestCase):
    def test_all_types_found(self):
        checks = gate.check_module_types()
        for check in checks:
            self.assertTrue(check["passed"], f"type check failed: {check}")


class TestEventCodes(unittest.TestCase):
    def test_all_event_codes_found(self):
        checks = gate.check_event_codes_in_module()
        for check in checks:
            self.assertTrue(check["passed"], f"event code check failed: {check}")


class TestRegionKinds(unittest.TestCase):
    def test_all_region_kinds_found(self):
        checks = gate.check_region_kinds_in_module()
        for check in checks:
            self.assertTrue(check["passed"], f"region kind check failed: {check}")


class TestSpecDoc(unittest.TestCase):
    def test_all_sections_present(self):
        checks = gate.check_spec_doc_sections()
        for check in checks:
            self.assertTrue(check["passed"], f"spec section check failed: {check}")


class TestQuiescenceTrace(unittest.TestCase):
    def test_trace_valid(self):
        checks = gate.check_quiescence_trace()
        for check in checks:
            self.assertTrue(check["passed"], f"trace check failed: {check}")


class TestRunChecks(unittest.TestCase):
    def test_gate_passes(self):
        result = gate.run_checks()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["checks_passed"], result["checks_total"])

    def test_result_structure(self):
        result = gate.run_checks()
        self.assertEqual(result["bead_id"], "bd-2tdi")
        self.assertEqual(result["section"], "10.15")
        self.assertIn("checks", result)
        self.assertIn("summary", result)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(gate.self_test())


class TestCli(unittest.TestCase):
    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_region_ownership.py"), "--self-test"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_region_ownership.py"), "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS")

    def test_cli_human_readable(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_region_ownership.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
