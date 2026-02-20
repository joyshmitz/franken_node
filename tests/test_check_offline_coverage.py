"""Unit tests for check_offline_coverage.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestOfflineCoverageFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29w6/offline_slo_dashboard_snapshot.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29w6/offline_slo_dashboard_snapshot.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("snapshots", data)
        self.assertGreaterEqual(len(data["snapshots"]), 3)

    def test_fixtures_have_breach(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-29w6/offline_slo_dashboard_snapshot.json")
        with open(path) as f:
            data = json.load(f)
        breached = [s for s in data["snapshots"]
                    if any(t.get("status") == "BREACH" for t in s.get("slo_targets", []))]
        self.assertGreater(len(breached), 0)


class TestOfflineCoverageImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/offline_coverage.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_tracker(self):
        self.assertIn("struct OfflineCoverageTracker", self.content)

    def test_has_coverage_metrics(self):
        self.assertIn("struct CoverageMetrics", self.content)

    def test_has_slo_target(self):
        self.assertIn("struct SloTarget", self.content)

    def test_has_slo_breach_alert(self):
        self.assertIn("struct SloBreachAlert", self.content)

    def test_has_dashboard_snapshot(self):
        self.assertIn("struct DashboardSnapshot", self.content)

    def test_has_record_event(self):
        self.assertIn("fn record_event", self.content)

    def test_has_compute_metrics(self):
        self.assertIn("fn compute_metrics", self.content)

    def test_has_all_error_codes(self):
        for code in ["OCT_SLO_BREACH", "OCT_INVALID_EVENT",
                     "OCT_NO_EVENTS", "OCT_SCOPE_UNKNOWN"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestOfflineCoverageSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-29w6_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-OCT-CONTINUOUS", "INV-OCT-SLO-BREACH",
                    "INV-OCT-TRACEABLE", "INV-OCT-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["OCT_SLO_BREACH", "OCT_INVALID_EVENT",
                     "OCT_NO_EVENTS", "OCT_SCOPE_UNKNOWN"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestOfflineCoverageIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/offline_coverage_metrics.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_continuous(self):
        self.assertIn("inv_oct_continuous", self.content)

    def test_covers_slo_breach(self):
        self.assertIn("inv_oct_slo_breach", self.content)

    def test_covers_traceable(self):
        self.assertIn("inv_oct_traceable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_oct_deterministic", self.content)


if __name__ == "__main__":
    unittest.main()
