"""Unit tests for scripts/check_open_trust_compat_specs.py (bd-f955)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_open_trust_compat_specs",
    ROOT / "scripts" / "check_open_trust_compat_specs.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestOpenTrustCompatSpecs(unittest.TestCase):
    def test_repo_artifacts_pass(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-f955")
        self.assertEqual(report["verdict"], "PASS")

    def test_missing_heading_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-f955-test-") as tmp:
            spec_path, artifact_path = mod._fixture(Path(tmp), missing_heading=True)
            report = mod.run_checks(spec_path, artifact_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "spec_required_headings" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_missing_event_code_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-f955-test-") as tmp:
            spec_path, artifact_path = mod._fixture(Path(tmp), missing_code=True)
            report = mod.run_checks(spec_path, artifact_path)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "spec_event_codes" and not check["pass"]
                for check in report["checks"]
            )
        )

    def test_self_test(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
