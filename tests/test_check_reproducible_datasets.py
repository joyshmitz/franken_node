"""Tests for scripts/check_reproducible_datasets.py (bd-2ad0)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_reproducible_datasets.py")

# Dynamic import
spec = importlib.util.spec_from_file_location("check_reproducible_datasets", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2ad0"
        assert data["section"] == "16"
        assert "checks_passed" in data
        assert "checks_total" in data
        assert "verdict" in data
        assert isinstance(data["checks"], list)


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results):
        assert results["source_exists"]["passed"]

    def test_module_wiring(self, results):
        assert results["module_wiring"]["passed"]

    def test_dataset_types(self, results):
        assert results["dataset_types"]["passed"]

    def test_struct_dataset_entry(self, results):
        assert results["struct_DatasetEntry"]["passed"]

    def test_struct_dataset_provenance(self, results):
        assert results["struct_DatasetProvenance"]["passed"]

    def test_struct_replay_instructions(self, results):
        assert results["struct_ReplayInstructions"]["passed"]

    def test_struct_dataset_bundle(self, results):
        assert results["struct_DatasetBundle"]["passed"]

    def test_struct_dataset_catalog(self, results):
        assert results["struct_DatasetCatalog"]["passed"]

    def test_struct_reproducible_datasets(self, results):
        assert results["struct_ReproducibleDatasets"]["passed"]

    def test_content_hash_integrity(self, results):
        assert results["content_hash_integrity"]["passed"]

    def test_provenance_metadata(self, results):
        assert results["provenance_metadata"]["passed"]

    def test_replay_instructions(self, results):
        assert results["replay_instructions"]["passed"]

    def test_schema_versioning(self, results):
        assert results["schema_versioning"]["passed"]

    def test_bundle_publication(self, results):
        assert results["bundle_publication"]["passed"]

    def test_catalog_generation(self, results):
        assert results["catalog_generation"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

    def test_spec_alignment(self, results):
        assert results["spec_alignment"]["passed"]

    def test_test_coverage(self, results):
        assert results["test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        results = mod._checks()
        failed = [r for r in results if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, SCRIPT],
            capture_output=True, text=True,
        )
        assert "bd-2ad0" in result.stdout
        assert "PASS" in result.stdout
