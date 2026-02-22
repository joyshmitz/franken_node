"""Tests for scripts/check_adjacent_substrate_policy.py."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_adjacent_substrate_policy.py")

spec = importlib.util.spec_from_file_location("check_adjacent_substrate_policy", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestCLI:
    def test_json_output(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["bead_id"] == "bd-2owx"
        assert payload["section"] == "10.16"
        assert payload["verdict"] == "PASS"

    def test_self_test_cli(self):
        proc = subprocess.run(
            [sys.executable, SCRIPT, "--self-test"], capture_output=True, text=True
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "self_test passed" in proc.stdout


class TestSchemaAndCoverage:
    def test_unknown_substrate_name_rejected(self):
        manifest = {
            "schema_version": "1.0.0",
            "policy_id": "x",
            "module_root": "crates/franken-node/src",
            "classification_mode": "first_match",
            "substrates": [
                {
                    "name": "unknown_substrate",
                    "version": "^0.1.0",
                    "plane": "model",
                    "mandatory_modules": ["crates/franken-node/src/config.rs"],
                    "should_use_modules": ["crates/franken-node/src/main.rs"],
                    "optional_modules": ["crates/franken-node/src/**"],
                }
            ],
            "exceptions": [],
            "metadata": {
                "schema_version": "1.0.0",
                "created_at": "2026-02-22T00:00:00Z",
                "policy_hash": "sha256:test",
            },
        }
        errors = mod.validate_manifest_schema(manifest)
        assert any("unknown substrate name" in err for err in errors)

    def test_empty_module_inventory_is_detected(self):
        manifest = mod._load_json(mod.MANIFEST_PATH)
        assert manifest is not None
        assignments, unmapped = mod.classify_modules([], manifest["substrates"])
        assert all(len(v) == 0 for v in assignments.values())
        assert unmapped == []

    def test_module_coverage_complete_on_real_manifest(self):
        manifest = mod._load_json(mod.MANIFEST_PATH)
        assert manifest is not None
        modules = mod.list_source_modules(manifest["module_root"])
        assignments, unmapped = mod.classify_modules(modules, manifest["substrates"])
        assert len(modules) > 0
        assert not unmapped
        assert set(assignments.keys()) == {
            "frankentui",
            "frankensqlite",
            "sqlmodel_rust",
            "fastapi_rust",
        }


class TestContractConsistency:
    @pytest.fixture(scope="class")
    def manifest(self):
        payload = mod._load_json(mod.MANIFEST_PATH)
        assert payload is not None
        return payload

    @pytest.fixture(scope="class")
    def contract(self):
        policy_src = mod.POLICY_PATH.read_text(encoding="utf-8")
        payload = mod.parse_policy_contract_block(policy_src)
        assert payload is not None
        return payload

    def test_contract_matches_manifest(self, contract, manifest):
        errors = mod.compare_contract_to_manifest(contract, manifest)
        assert not errors, errors

    def test_contract_mismatch_detected(self, contract, manifest):
        tampered = copy.deepcopy(contract)
        tampered["manifest_path"] = "artifacts/10.16/WRONG.json"
        errors = mod.compare_contract_to_manifest(tampered, manifest)
        assert errors
        assert any("manifest_path mismatch" in err for err in errors)

    def test_policy_hash_is_stable(self, manifest):
        digest_one = mod.compute_policy_hash(manifest)
        digest_two = mod.compute_policy_hash(manifest)
        assert digest_one == digest_two
