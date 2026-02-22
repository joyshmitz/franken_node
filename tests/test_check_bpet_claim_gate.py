"""Unit tests for scripts/check_bpet_claim_gate.py (bd-3v9l)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_bpet_claim_gate",
    ROOT / "scripts" / "check_bpet_claim_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestBpetClaimGate(unittest.TestCase):
    def test_repo_artifacts_pass(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-3v9l")
        self.assertEqual(report["verdict"], "PASS")

    def test_tampered_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, tamper_signature=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "signature verification" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_missing_evidence_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, drop_evidence=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-004" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_p95_budget_breach_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, breach_p95=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-002" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_p99_budget_breach_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, breach_p99=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-003" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_storage_budget_breach_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, breach_storage=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-003" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_calibration_shortfall_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, calibration_shortfall=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-004" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_signed_provenance_shortfall_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, _ = mod._signed_report_fixture(
                base, signed_shortfall=True
            )
            report = mod.run_checks(spec_path, report_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "claim BPET-CLAIM-004" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_signature_roundtrip_consistent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-3v9l-test-") as tmp:
            base = Path(tmp)
            _, report_path, _ = mod._signed_report_fixture(base)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            expected = mod._expected_signature(payload)
            self.assertEqual(payload["signing"]["signature"], expected)
            self.assertEqual(mod._expected_signature(payload), expected)

    def test_self_test(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
