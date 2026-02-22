"""Unit tests for scripts/check_dr_drills.py (bd-3m6)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_dr_drills as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        self.assertIn("bead_id", result)
        self.assertIn("section", result)
        self.assertIn("checks", result)
        self.assertIn("verdict", result)
        self.assertIn("passed", result)
        self.assertIn("failed", result)
        self.assertIn("total", result)
        self.assertIn("all_passed", result)
        self.assertIn("status", result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-3m6")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.8")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"],
                         "Disaster-recovery drills for control-plane failures")

    def test_check_count_reasonable(self):
        result = checker.run_all()
        self.assertGreaterEqual(result["total"], 100)

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(result["status"], "pass")
            self.assertTrue(result["all_passed"])
        else:
            self.assertEqual(result["verdict"], "FAIL")
            self.assertEqual(result["status"], "fail")
            self.assertFalse(result["all_passed"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_spec_scenarios(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_scenarios")
        self.assertTrue(check["passed"], check["detail"])

    def test_spec_scenario_ids(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_scenario_ids")
        self.assertTrue(check["passed"], check["detail"])


class TestSchemaChecks(unittest.TestCase):
    def test_schema_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "schema_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_schema_valid_json(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "schema_valid_json")
        self.assertTrue(check["passed"], check["detail"])

    def test_schema_required_fields(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "schema_required_fields")
        self.assertTrue(check["passed"], check["detail"])

    def test_schema_category_enum(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "schema_category_enum")
        self.assertTrue(check["passed"], check["detail"])


class TestEventCodes(unittest.TestCase):
    def test_event_codes_in_spec(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"event_code_spec:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 6)

    def test_event_code_values(self):
        expected = ["DRD-001", "DRD-002", "DRD-003", "DRD-004", "DRD-005", "DRD-006"]
        self.assertEqual(checker.EVENT_CODES, expected)


class TestInvariants(unittest.TestCase):
    def test_invariants_in_spec(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"invariant_spec:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 5)

    def test_invariant_values(self):
        self.assertIn("INV-DRD-DETERMINISTIC", checker.INVARIANTS)
        self.assertIn("INV-DRD-ISOLATED", checker.INVARIANTS)
        self.assertIn("INV-DRD-MEASURED", checker.INVARIANTS)
        self.assertIn("INV-DRD-EVIDENCE", checker.INVARIANTS)
        self.assertIn("INV-DRD-ABORT-SAFE", checker.INVARIANTS)


class TestJsonDrills(unittest.TestCase):
    def test_all_json_drills_exist(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_exists:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_ids(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_id:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_categories(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_category:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_severity(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_severity:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_slo(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_slo:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_interval(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_interval:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_fault_steps(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_fault_steps:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_recovery_steps(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_recovery_steps:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_verification_steps(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_verification_steps:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_abort_conditions(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_abort:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_related_runbook(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_runbook:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_cross_refs(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_cross_refs:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_fault_description(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"json_fault_desc:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")

    def test_all_json_drill_fields(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            for field in checker.REQUIRED_SCHEMA_FIELDS:
                check = next(
                    c for c in result["checks"]
                    if c["name"] == f"json_field:{sc['category']}:{field}"
                )
                self.assertTrue(
                    check["passed"],
                    f"{sc['category']}/{field}: {check['detail']}",
                )


class TestAggregateChecks(unittest.TestCase):
    def test_scenario_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "scenario_count")
        self.assertTrue(check["passed"], check["detail"])

    def test_critical_weekly(self):
        result = checker.run_all()
        for sc in checker.SCENARIOS:
            if sc["severity"] != "critical":
                continue
            check = next(c for c in result["checks"]
                         if c["name"] == f"critical_weekly:{sc['category']}")
            self.assertTrue(check["passed"], f"{sc['category']}: {check['detail']}")


class TestConstants(unittest.TestCase):
    def test_scenarios_count(self):
        self.assertEqual(len(checker.SCENARIOS), 5)

    def test_required_schema_fields_count(self):
        self.assertEqual(len(checker.REQUIRED_SCHEMA_FIELDS), 13)

    def test_required_steps_not_in_schema_fields(self):
        # Steps phases are inside the steps object, not top-level
        self.assertNotIn("containment", checker.REQUIRED_SCHEMA_FIELDS)


class TestSafeRel(unittest.TestCase):
    def test_path_within_root(self):
        rel = checker._safe_rel(checker.SPEC)
        self.assertNotIn(str(checker.ROOT), rel)
        self.assertIn("bd-3m6_contract.md", rel)

    def test_path_outside_root(self):
        outside = Path("/tmp/something/else.txt")
        rel = checker._safe_rel(outside)
        self.assertEqual(rel, str(outside))


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_dr_drills.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3m6")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_dr_drills.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestOverallVerdict(unittest.TestCase):
    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
