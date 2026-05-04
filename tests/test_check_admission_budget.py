"""Unit tests for check_admission_budget.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import check_admission_budget

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_admission_budget.py"
REPORT_PATH = ROOT / "artifacts/section_10_13/bd-2k74/admission_budget_violation_report.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-2k74/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestAdmissionBudgetReport(unittest.TestCase):

    def test_report_exists(self):
        self.assertTrue(REPORT_PATH.is_file())

    def test_report_valid_json(self):
        data = decode_json_object(REPORT_PATH.read_text(encoding="utf-8"))
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_report_has_violation_scenario(self):
        data = decode_json_object(REPORT_PATH.read_text(encoding="utf-8"))
        verdicts = [s.get("verdict") for s in data["scenarios"]]
        self.assertIn("REJECT", verdicts)


class TestAdmissionBudgetImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/admission_budget.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-2k74_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

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
        self.integ_path = ROOT / "tests/integration/admission_budget_enforcement.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_enforced(self):
        self.assertIn("inv_pab_enforced", self.content)

    def test_covers_bounded(self):
        self.assertIn("inv_pab_bounded", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_pab_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_pab_deterministic", self.content)


class TestAdmissionBudgetCheckerCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_admission_budget.parse_args(["--json"])

        self.assertTrue(check_admission_budget.should_run_rust_tests(args))

    def test_structural_json_mode_is_partial_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "admission_budget_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["PAB-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-2k74:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
