"""Unit tests for scripts/check_waiver_workflow.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_waiver_workflow",
    ROOT / "scripts" / "check_waiver_workflow.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _now() -> datetime:
    return datetime(2026, 2, 20, 0, 0, 0, tzinfo=timezone.utc)


class TestFixturePaths(TestCase):
    def test_paths_exist(self) -> None:
        self.assertTrue(mod.WAIVER_REGISTRY.is_file())
        self.assertTrue(mod.SUBSTRATE_MANIFEST.is_file())
        self.assertTrue(mod.POLICY_DOC.is_file())


class TestManifestIndex(TestCase):
    def test_build_manifest_index_extracts_modules_and_rules(self) -> None:
        manifest = {
            "modules": [
                {
                    "path": "crates/franken-node/src/connector",
                    "substrates": [
                        {"name": "frankensqlite", "integration_type": "mandatory"},
                        {"name": "fastapi_rust", "integration_type": "should_use"},
                    ],
                }
            ]
        }
        index = mod.build_manifest_index(manifest)
        self.assertIn("crates/franken-node/src/connector", index["module_paths"])
        self.assertIn("adjacent-substrate.mandatory.frankensqlite", index["rule_ids"])
        self.assertIn("adjacent-substrate.should_use.fastapi_rust", index["rule_ids"])


class TestWaiverValidation(TestCase):
    def setUp(self) -> None:
        self.manifest = {
            "modules": [
                {
                    "path": "crates/franken-node/src/connector",
                    "substrates": [
                        {"name": "frankensqlite", "integration_type": "mandatory"},
                        {"name": "fastapi_rust", "integration_type": "should_use"},
                    ],
                }
            ]
        }
        self.valid_registry = {
            "schema_version": "1.0.0",
            "max_waiver_duration_days": 90,
            "waivers": [
                {
                    "waiver_id": "waiver-1",
                    "module": "crates/franken-node/src/connector",
                    "substrate": "frankensqlite",
                    "rules_waived": ["adjacent-substrate.mandatory.frankensqlite"],
                    "risk_analysis": "bounded risk",
                    "scope_description": "narrow scope",
                    "owner": "owner-a",
                    "approved_by": "approver-a",
                    "granted_at": "2026-02-01T00:00:00Z",
                    "expires_at": "2026-03-01T00:00:00Z",
                    "remediation_plan": "remove waiver",
                    "status": "active",
                }
            ],
        }

    def test_valid_waiver_passes(self) -> None:
        ok, report = mod.evaluate_registry(self.valid_registry, self.manifest, _now())
        self.assertTrue(ok)
        self.assertEqual(report["verdict"], "PASS")

    def test_active_expired_waiver_fails(self) -> None:
        registry = json.loads(json.dumps(self.valid_registry))
        registry["waivers"][0]["expires_at"] = "2026-02-10T00:00:00Z"
        ok, report = mod.evaluate_registry(registry, self.manifest, _now())
        self.assertFalse(ok)
        self.assertTrue(any("active waiver is expired" in err for err in report["errors"]))

    def test_missing_required_field_fails(self) -> None:
        registry = json.loads(json.dumps(self.valid_registry))
        del registry["waivers"][0]["risk_analysis"]
        ok, report = mod.evaluate_registry(registry, self.manifest, _now())
        self.assertFalse(ok)
        self.assertTrue(any("missing fields" in err for err in report["errors"]))

    def test_unknown_module_or_rule_fails(self) -> None:
        registry = json.loads(json.dumps(self.valid_registry))
        registry["waivers"][0]["module"] = "crates/franken-node/src/unknown"
        registry["waivers"][0]["rules_waived"] = ["adjacent-substrate.mandatory.unknown"]
        ok, report = mod.evaluate_registry(registry, self.manifest, _now())
        self.assertFalse(ok)
        self.assertTrue(any("unknown module" in err for err in report["errors"]))
        self.assertTrue(any("unknown rule id" in err for err in report["errors"]))

    def test_empty_registry_passes(self) -> None:
        empty_registry = {
            "schema_version": "1.0.0",
            "max_waiver_duration_days": 90,
            "waivers": [],
        }
        ok, report = mod.evaluate_registry(empty_registry, self.manifest, _now())
        self.assertTrue(ok)
        self.assertEqual(report["verdict"], "PASS")


class TestEndToEnd(TestCase):
    def test_run_checks_passes_on_repo_artifacts(self) -> None:
        ok, report = mod.run_checks(now=_now())
        self.assertTrue(ok)
        self.assertEqual(report["verdict"], "PASS")

    def test_self_test_passes(self) -> None:
        ok, messages = mod.self_test()
        self.assertTrue(ok)
        self.assertTrue(messages)


if __name__ == "__main__":
    main()
