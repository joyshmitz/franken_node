"""Unit tests for scripts/check_trust_card.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_trust_card",
    ROOT / "scripts" / "check_trust_card.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_impl_paths_exist(self) -> None:
        self.assertTrue(mod.TRUST_CARD_IMPL.is_file())
        self.assertTrue(mod.API_IMPL.is_file())
        self.assertTrue(mod.CLI_IMPL.is_file())
        self.assertTrue(mod.MAIN_IMPL.is_file())

    def test_contract_exists(self) -> None:
        self.assertTrue(mod.SPEC.parent.is_dir())


class TestSimulation(TestCase):
    def test_deterministic_hash_and_signatures(self) -> None:
        result = mod.simulate_trust_card_flow()
        self.assertTrue(result["deterministic"])
        self.assertTrue(result["v1_verified"])
        self.assertTrue(result["v2_verified"])
        self.assertTrue(result["hash_chain_linked"])

    def test_simulation_detects_changes(self) -> None:
        result = mod.simulate_trust_card_flow()
        self.assertIn("certification_level", result["changed_fields"])
        self.assertIn("reputation_score_basis_points", result["changed_fields"])
        self.assertIn("revocation_status", result["changed_fields"])


class TestChecks(TestCase):
    def test_run_checks_passes(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-2yh")
        self.assertEqual(report["verdict"], "PASS")

    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 10)

    def test_missing_file_is_detected(self) -> None:
        with patch.object(mod, "CLI_IMPL", ROOT / "does" / "not" / "exist.rs"):
            report = mod.run_checks()
        failed = [check for check in report["checks"] if not check["pass"]]
        self.assertTrue(any("file: cli surface" in check["check"] for check in failed))

    def test_required_cli_patterns_include_trust_card_surface(self) -> None:
        self.assertIn("name = \"trust-card\"", mod.REQUIRED_CLI_PATTERNS)
        self.assertIn("pub enum TrustCardCommand", mod.REQUIRED_CLI_PATTERNS)


if __name__ == "__main__":
    main()
