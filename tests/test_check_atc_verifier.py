"""Unit tests for scripts/check_atc_verifier.py (bd-2zip)."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_atc_verifier",
    ROOT / "scripts" / "check_atc_verifier.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestAtcVerifierChecker(unittest.TestCase):
    def test_repo_artifacts_pass(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-2zip")
        self.assertEqual(report["verdict"], "PASS")

    def test_tampered_signature_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, conformance_path = mod._fixture(
                base, tamper_signature=True
            )
            report = mod.run_checks(spec_path, report_path, conformance_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "signature verification" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_determinism_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, conformance_path = mod._fixture(
                base, determinism_mismatch=True
            )
            report = mod.run_checks(spec_path, report_path, conformance_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "determinism checks" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_raw_exposure_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, conformance_path = mod._fixture(
                base, raw_exposure=True
            )
            report = mod.run_checks(spec_path, report_path, conformance_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "metric snapshots aggregate-only" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_broken_chain_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, conformance_path = mod._fixture(
                base, broken_chain=True
            )
            report = mod.run_checks(spec_path, report_path, conformance_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "proof_chain continuity" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_missing_endpoint_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            spec_path, report_path, conformance_path = mod._fixture(
                base, missing_endpoint=True
            )
            report = mod.run_checks(spec_path, report_path, conformance_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "spec endpoint ATC-VERIFIER-ENDPOINT-004"
                and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_signature_roundtrip_consistent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-2zip-test-") as tmp:
            base = Path(tmp)
            _, report_path, _ = mod._fixture(base)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            expected = mod._expected_signature(payload)
            self.assertEqual(payload["signing"]["signature"], expected)

    def test_self_test(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
