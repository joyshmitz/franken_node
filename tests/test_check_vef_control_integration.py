"""Unit tests for scripts/check_vef_control_integration.py (bd-8qlj)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_vef_control_integration.py"

spec = importlib.util.spec_from_file_location("check_vef_control_integration", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestRunAllShape(unittest.TestCase):
    def test_run_all_shape(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-8qlj")
        self.assertEqual(result["section"], "10.18")
        self.assertIn(result["verdict"], ("PASS", "FAIL"))
        self.assertEqual(result["failed"], result["total"] - result["passed"])
        self.assertEqual(result["total"], len(result["checks"]))

    def test_check_entries_shape(self) -> None:
        result = mod.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)
            self.assertIsInstance(check["check"], str)
            self.assertIsInstance(check["pass"], bool)
            self.assertIsInstance(check["detail"], str)

    def test_has_timestamp(self) -> None:
        result = mod.run_all()
        self.assertIn("timestamp", result)
        self.assertIsInstance(result["timestamp"], str)

    def test_check_count_reasonable(self) -> None:
        result = mod.run_all()
        self.assertGreaterEqual(result["total"], 80, "should have at least 80 checks")


class TestVerdict(unittest.TestCase):
    def test_verdict_pass(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_text(result))

    def test_pending_feasibility_check_present(self) -> None:
        result = mod.run_all()
        check_names = {check["check"] for check in result["checks"]}
        self.assertIn(
            "contract_pending_verification_requires_feasible_min_evidence",
            check_names,
        )
        self.assertIn("spec_pending_verification_feasibility", check_names)
        self.assertIn("summary_pending_verification_feasibility", check_names)
        self.assertIn(
            "evidence_pending_verification_requires_feasible_min_evidence",
            check_names,
        )

    @staticmethod
    def _failure_text(result: dict) -> str:
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"FAIL: {c['check']}: {c['detail']}" for c in failures[:20])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_shape(self) -> None:
        result = mod.self_test()
        self.assertEqual(result["mode"], "self-test")
        self.assertGreaterEqual(result["total"], 10)
        self.assertEqual(result["failed"], result["total"] - result["passed"])


class TestCli(unittest.TestCase):
    def test_json_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-8qlj")
        self.assertIn("checks", parsed)

    def test_self_test_cli_exit_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_plain_cli_output(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertIn("[bd-8qlj]", proc.stdout)
        self.assertIn("PASS", proc.stdout)


class TestFailureInjection(unittest.TestCase):
    def _set_module_attr(self, name: str, value: object) -> None:
        original = getattr(mod, name)
        self.addCleanup(setattr, mod, name, original)
        setattr(mod, name, value)

    def _replace_once(self, text: str, old: str, new: str) -> str:
        self.assertIn(old, text)
        return text.replace(old, new, 1)

    def test_missing_summary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._set_module_attr("SUMMARY", Path(temp_dir) / "missing-summary.md")
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("summary_exists", failed_checks)

    def test_missing_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._set_module_attr("EVIDENCE", Path(temp_dir) / "missing-evidence.json")
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("evidence_exists", failed_checks)

    def test_missing_impl_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self._set_module_attr("IMPL", Path(temp_dir) / "missing-impl.rs")
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("impl_exists", failed_checks)

    def test_old_pending_semantics_fail(self) -> None:
        original_text = mod.IMPL.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            weakened = Path(temp_dir) / "control_integration.rs"
            weakened.write_text(
                self._replace_once(
                    original_text,
                    "valid_evidence_ids.len() + pending_evidence_ids.len() >= min_evidence\n            && !pending_evidence_ids.is_empty()",
                    "!pending_evidence_ids.is_empty()",
                ),
                encoding="utf-8",
            )
            self._set_module_attr("IMPL", weakened)
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn(
                "contract_pending_verification_requires_feasible_min_evidence",
                failed_checks,
            )

    def test_stale_spec_pending_semantics_fail(self) -> None:
        original_text = mod.SPEC_CONTRACT.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            stale = Path(temp_dir) / "bd-8qlj_contract.md"
            stale.write_text(
                self._replace_once(
                    original_text,
                    "Unverified evidence produces PendingVerification only when the combined verified and pending evidence set can still satisfy the effective min_evidence_count; otherwise the decision is Denied with ERR-CTL-MISSING-EVIDENCE.",
                    "Unverified evidence produces a PendingVerification decision.",
                ),
                encoding="utf-8",
            )
            self._set_module_attr("SPEC_CONTRACT", stale)
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("spec_pending_verification_feasibility", failed_checks)

    def test_stale_summary_pending_semantics_fail(self) -> None:
        original_text = mod.SUMMARY.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            stale = Path(temp_dir) / "verification_summary.md"
            stale.write_text(
                self._replace_once(
                    original_text,
                    "- **Unverified evidence:** Produces `PendingVerification` only when the combined verified and pending evidence set can still satisfy the effective `min_evidence_count`; otherwise the request fails closed with ERR-CTL-MISSING-EVIDENCE / CTL-003.",
                    "- **Unverified evidence:** Produces PendingVerification decision / CTL-006.",
                ),
                encoding="utf-8",
            )
            self._set_module_attr("SUMMARY", stale)
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn("summary_pending_verification_feasibility", failed_checks)

    def test_stale_evidence_pending_semantics_fail(self) -> None:
        evidence = json.loads(mod.EVIDENCE.read_text(encoding="utf-8"))
        contract = evidence["evidence"]["contract_compliance"]
        self.assertIn(
            "pending_verification_requires_feasible_min_evidence",
            contract,
        )
        contract["pending_verification_requires_feasible_min_evidence"] = False
        with tempfile.TemporaryDirectory() as temp_dir:
            stale = Path(temp_dir) / "verification_evidence.json"
            stale.write_text(json.dumps(evidence), encoding="utf-8")
            self._set_module_attr("EVIDENCE", stale)
            result = mod.run_all()
            self.assertEqual(result["verdict"], "FAIL")
            failed_checks = [c["check"] for c in result["checks"] if not c["pass"]]
            self.assertIn(
                "evidence_pending_verification_requires_feasible_min_evidence",
                failed_checks,
            )


class TestConstants(unittest.TestCase):
    def test_transition_type_count(self) -> None:
        self.assertEqual(len(mod.TRANSITION_TYPES), 4)

    def test_verification_state_count(self) -> None:
        self.assertEqual(len(mod.VERIFICATION_STATES), 4)

    def test_event_code_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 8)

    def test_error_code_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 6)

    def test_invariant_count(self) -> None:
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 3)

    def test_impl_symbols_minimum(self) -> None:
        self.assertGreaterEqual(len(mod.REQUIRED_IMPL_SYMBOLS), 20)


if __name__ == "__main__":
    unittest.main()
