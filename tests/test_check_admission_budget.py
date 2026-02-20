"""Unit tests for check_admission_budget.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestAdmissionBudgetReport(unittest.TestCase):

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2k74/admission_budget_violation_report.json")
        self.assertTrue(os.path.isfile(path))

    def test_report_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2k74/admission_budget_violation_report.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_report_has_violation_scenario(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2k74/admission_budget_violation_report.json")
        with open(path) as f:
            data = json.load(f)
        verdicts = [s.get("verdict") for s in data["scenarios"]]
        self.assertIn("REJECT", verdicts)


class TestAdmissionBudgetImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/admission_budget.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_admission_budget(self):
        self.assertIn("struct AdmissionBudget", self.content)

    def test_has_peer_usage(self):
        self.assertIn("struct PeerUsage", self.content)

    def test_has_admission_request(self):
        self.assertIn("struct AdmissionRequest", self.content)

    def test_has_admission_verdict(self):
        self.assertIn("struct AdmissionVerdict", self.content)

    def test_has_budget_tracker(self):
        self.assertIn("struct AdmissionBudgetTracker", self.content)

    def test_has_check_admission(self):
        self.assertIn("fn check_admission", self.content)

    def test_has_admit(self):
        self.assertIn("fn admit", self.content)

    def test_has_all_error_codes(self):
        for code in ["PAB_BYTES_EXCEEDED", "PAB_SYMBOLS_EXCEEDED", "PAB_AUTH_EXCEEDED",
                     "PAB_INFLIGHT_EXCEEDED", "PAB_CPU_EXCEEDED", "PAB_INVALID_BUDGET"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_all_dimensions(self):
        for dim in ["bytes", "symbols", "failed_auth", "inflight_decode", "decode_cpu"]:
            self.assertIn(dim, self.content, f"Missing dimension {dim}")


class TestAdmissionBudgetSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2k74_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-PAB-ENFORCED", "INV-PAB-BOUNDED",
                    "INV-PAB-AUDITABLE", "INV-PAB-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PAB_BYTES_EXCEEDED", "PAB_SYMBOLS_EXCEEDED", "PAB_AUTH_EXCEEDED",
                     "PAB_INFLIGHT_EXCEEDED", "PAB_CPU_EXCEEDED", "PAB_INVALID_BUDGET"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestAdmissionBudgetIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/admission_budget_enforcement.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_enforced(self):
        self.assertIn("inv_pab_enforced", self.content)

    def test_covers_bounded(self):
        self.assertIn("inv_pab_bounded", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_pab_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_pab_deterministic", self.content)


if __name__ == "__main__":
    unittest.main()
