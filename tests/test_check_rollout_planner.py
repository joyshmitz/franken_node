#!/usr/bin/env python3
"""Unit tests for rollout_planner.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rollout_planner as planner


class TestGeneratePlan(unittest.TestCase):
    def test_has_four_phases(self):
        plan = planner.generate_plan()
        self.assertEqual(len(plan["phases"]), 4)

    def test_phase_order(self):
        plan = planner.generate_plan()
        names = [p["name"] for p in plan["phases"]]
        self.assertEqual(names, ["shadow", "canary", "ramp", "default"])

    def test_all_phases_have_gates(self):
        plan = planner.generate_plan()
        for phase in plan["phases"]:
            self.assertIn("gate", phase)
            self.assertTrue(len(phase["gate"]) > 0)

    def test_all_phases_have_rollback(self):
        plan = planner.generate_plan()
        for phase in plan["phases"]:
            self.assertIn("rollback", phase)

    def test_high_risk_adjusts_canary(self):
        plan = planner.generate_plan({"risk_score": 80, "difficulty": {"level": "critical"}, "project": "x"})
        canary = next(p for p in plan["phases"] if p["name"] == "canary")
        self.assertEqual(canary["traffic_pct"], 1)

    def test_low_risk_normal_canary(self):
        plan = planner.generate_plan({"risk_score": 5, "difficulty": {"level": "low"}, "project": "x"})
        canary = next(p for p in plan["phases"] if p["name"] == "canary")
        self.assertEqual(canary["traffic_pct"], 5)

    def test_has_checklist(self):
        plan = planner.generate_plan()
        self.assertGreaterEqual(len(plan["pre_migration_checklist"]), 5)

    def test_constraints_strict(self):
        plan = planner.generate_plan()
        self.assertTrue(plan["constraints"]["phase_order_strict"])
        self.assertTrue(plan["constraints"]["rollback_always_available"])


class TestValidatePlan(unittest.TestCase):
    def test_valid_plan_passes(self):
        plan = planner.generate_plan()
        checks = planner.validate_plan(plan)
        self.assertTrue(all(c["status"] == "PASS" for c in checks))

    def test_empty_plan_fails(self):
        checks = planner.validate_plan({"phases": []})
        failing = [c for c in checks if c["status"] == "FAIL"]
        self.assertGreater(len(failing), 0)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = planner.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
