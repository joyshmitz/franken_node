#!/usr/bin/env python3
"""Unit tests for scripts/check_verifier_contract.py (bd-3ex)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_verifier_contract.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_verifier_contract", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_contract(path: Path, *, previous_major: int, snapshots: dict[str, Path]) -> None:
    commands = [
        ("verify-module", "module"),
        ("verify-migration", "migration"),
        ("verify-compatibility", "compatibility"),
        ("verify-corpus", "corpus"),
    ]
    scenarios = [
        ("verify_module_default", "verify-module", 0),
        ("verify_migration_default", "verify-migration", 0),
        ("verify_compatibility_default", "verify-compatibility", 0),
        ("verify_corpus_default", "verify-corpus", 0),
        ("verify_module_invalid_compat", "verify-module", 9),
    ]

    lines: list[str] = [
        'schema_version = "1.0"',
        'contract_name = "verifier-cli"',
        'contract_version = "2.0.0"',
        f"previous_contract_major = {previous_major}",
        "",
        "[exit_codes]",
        "pass = 0",
        "fail = 1",
        "error = 2",
        "skipped = 3",
        "",
        "[error_format]",
        'schema = "verifier-error-v1"',
        'required_fields = ["error_code", "message", "remediation"]',
        "",
    ]
    for cmd_id, sub in commands:
        lines.extend(
            [
                "[[commands]]",
                f'id = "{cmd_id}"',
                f'subcommand = "{sub}"',
                'output_schema = "verifier-cli-output-v1"',
                "supports_json = true",
                "supports_compat_version = true",
                'required_output_fields = ["command","contract_version","schema_version","compat_version","verdict","status","exit_code","reason"]',
                "",
            ]
        )
    for scenario_id, command_id, compat in scenarios:
        lines.extend(
            [
                "[[scenarios]]",
                f'scenario_id = "{scenario_id}"',
                f'command_id = "{command_id}"',
                f"compat_version = {compat}",
                f'snapshot = "{snapshots[scenario_id]}"',
                "",
            ]
        )

    path.write_text("\n".join(lines), encoding="utf-8")


class VerifierContractCheckerTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_checker()

    def test_self_test(self):
        self.assertTrue(self.mod.self_test())

    def test_run_checks_shape(self):
        report = self.mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-3ex")
        self.assertIn(report["verdict"], {"PASS", "FAIL"})
        self.assertIsInstance(report["checks"], list)
        self.assertGreaterEqual(len(report["checks"]), 10)

    def test_real_contract_passes(self):
        report = self.mod.run_checks()
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["failed"], 0)

    def test_cli_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-3ex")
        self.assertEqual(data["verdict"], "PASS")

    def test_compare_snapshot_additive_only(self):
        diff = self.mod._compare_snapshot({"a": 1, "b": 2}, {"a": 1})
        self.assertTrue(diff["additive_only"])
        self.assertFalse(diff["breaking"])

    def test_compare_snapshot_breaking(self):
        diff = self.mod._compare_snapshot({"a": 2}, {"a": 1, "b": 2})
        self.assertTrue(diff["breaking"])
        self.assertIn("b", diff["removed_fields"])

    def test_additive_snapshot_update_path(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_additive_", dir=ROOT) as tmpdir:
            tmp = Path(tmpdir)
            contract_path = tmp / "contract.toml"
            scenarios = [
                "verify_module_default",
                "verify_migration_default",
                "verify_compatibility_default",
                "verify_corpus_default",
                "verify_module_invalid_compat",
            ]
            snapshot_paths = {name: (tmp / f"{name}.json") for name in scenarios}

            for scenario in scenarios:
                command_id = "verify-module"
                compat = None
                if "migration" in scenario:
                    command_id = "verify-migration"
                elif "compatibility" in scenario:
                    command_id = "verify-compatibility"
                elif "corpus" in scenario:
                    command_id = "verify-corpus"
                if scenario == "verify_module_invalid_compat":
                    compat = 9
                payload = self.mod._simulated_output(command_id, "2.0.0", compat)
                snapshot_paths[scenario].write_text(json.dumps(payload, indent=2), encoding="utf-8")

            # Introduce additive-only diff for one scenario.
            snapshot_paths["verify_module_default"].write_text(
                json.dumps({"command": "verify module"}, indent=2),
                encoding="utf-8",
            )
            write_contract(contract_path, previous_major=1, snapshots=snapshot_paths)

            report_no_update = self.mod.run_checks(
                update_snapshots=False,
                contract_path=contract_path,
            )
            self.assertEqual(report_no_update["verdict"], "PASS")

            report_update = self.mod.run_checks(
                update_snapshots=True,
                contract_path=contract_path,
            )
            self.assertEqual(report_update["verdict"], "PASS")
            refreshed = json.loads(
                snapshot_paths["verify_module_default"].read_text(encoding="utf-8")
            )
            self.assertEqual(refreshed["exit_code"], 0)
            self.assertEqual(refreshed["status"], "pass")

    def test_breaking_without_major_bump_fails(self):
        with tempfile.TemporaryDirectory(prefix="bd3ex_breaking_", dir=ROOT) as tmpdir:
            tmp = Path(tmpdir)
            contract_path = tmp / "contract.toml"
            scenarios = [
                "verify_module_default",
                "verify_migration_default",
                "verify_compatibility_default",
                "verify_corpus_default",
                "verify_module_invalid_compat",
            ]
            snapshot_paths = {name: (tmp / f"{name}.json") for name in scenarios}

            for scenario in scenarios:
                command_id = "verify-module"
                compat = None
                if "migration" in scenario:
                    command_id = "verify-migration"
                elif "compatibility" in scenario:
                    command_id = "verify-compatibility"
                elif "corpus" in scenario:
                    command_id = "verify-corpus"
                if scenario == "verify_module_invalid_compat":
                    compat = 9
                payload = self.mod._simulated_output(command_id, "2.0.0", compat)
                snapshot_paths[scenario].write_text(json.dumps(payload, indent=2), encoding="utf-8")

            # Breaking change: mutate existing field value with no major bump.
            broken = json.loads(snapshot_paths["verify_module_default"].read_text(encoding="utf-8"))
            broken["reason"] = "different-reason"
            snapshot_paths["verify_module_default"].write_text(
                json.dumps(broken, indent=2),
                encoding="utf-8",
            )
            write_contract(contract_path, previous_major=2, snapshots=snapshot_paths)

            report = self.mod.run_checks(update_snapshots=False, contract_path=contract_path)
            self.assertEqual(report["verdict"], "FAIL")
            failing_names = {c["check"] for c in report["checks"] if not c["passed"]}
            self.assertIn(
                "scenario:verify_module_default:snapshot_breaking_without_major_bump",
                failing_names,
            )


if __name__ == "__main__":
    unittest.main()
