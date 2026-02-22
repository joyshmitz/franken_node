#!/usr/bin/env python3
"""Tests for scripts/check_case_study_registry.py (bd-cv49)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_case_study_registry.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("check_case_study_registry", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load_module()


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_contains_required_keys(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        payload = json.loads(result.stdout)
        for key in (
            "bead_id",
            "section",
            "gate_script",
            "checks_passed",
            "checks_total",
            "verdict",
            "checks",
        ):
            assert key in payload

    def test_json_reports_expected_bead(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        payload = json.loads(result.stdout)
        assert payload["bead_id"] == "bd-cv49"
        assert payload["section"] == "15"

    def test_verdict_is_valid(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        payload = json.loads(result.stdout)
        assert payload["verdict"] in ("PASS", "FAIL")

    def test_checks_have_consistent_shape(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        payload = json.loads(result.stdout)
        for check in payload["checks"]:
            assert "check" in check
            assert "passed" in check
            assert "detail" in check


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def checks_by_name(self):
        return {entry["check"]: entry for entry in mod._checks()}

    def test_source_exists(self, checks_by_name):
        assert checks_by_name["source_exists"]["passed"]

    def test_module_wiring(self, checks_by_name):
        assert checks_by_name["module_wiring"]["passed"]

    def test_struct_case_study(self, checks_by_name):
        assert checks_by_name["struct_CaseStudy"]["passed"]

    def test_struct_key_metrics(self, checks_by_name):
        assert checks_by_name["struct_KeyMetrics"]["passed"]

    def test_struct_publication_status(self, checks_by_name):
        assert checks_by_name["struct_PublicationStatus"]["passed"]

    def test_struct_summary(self, checks_by_name):
        assert checks_by_name["struct_CaseStudyRegistrySummary"]["passed"]

    def test_struct_registry(self, checks_by_name):
        assert checks_by_name["struct_SecurityOpsCaseStudyRegistry"]["passed"]

    def test_event_codes(self, checks_by_name):
        assert checks_by_name["event_codes"]["passed"]

    def test_invariants(self, checks_by_name):
        assert checks_by_name["invariants"]["passed"]

    def test_spec_alignment(self, checks_by_name):
        assert checks_by_name["spec_alignment"]["passed"]

    def test_template_exists(self, checks_by_name):
        assert checks_by_name["template_exists"]["passed"]

    def test_docs_page_exists(self, checks_by_name):
        assert checks_by_name["docs_page_exists"]["passed"]

    def test_registry_exists(self, checks_by_name):
        assert checks_by_name["registry_exists"]["passed"]

    def test_registry_json_parse(self, checks_by_name):
        assert checks_by_name["registry_json_parse"]["passed"]

    def test_registry_schema_version(self, checks_by_name):
        assert checks_by_name["registry_schema_version"]["passed"]

    def test_minimum_case_study_count(self, checks_by_name):
        assert checks_by_name["minimum_case_study_count"]["passed"]

    def test_security_improvement_threshold(self, checks_by_name):
        assert checks_by_name["security_improvement_threshold"]["passed"]

    def test_review_coverage(self, checks_by_name):
        assert checks_by_name["review_coverage"]["passed"]

    def test_website_publication_threshold(self, checks_by_name):
        assert checks_by_name["website_publication_threshold"]["passed"]

    def test_external_submission_threshold(self, checks_by_name):
        assert checks_by_name["external_submission_threshold"]["passed"]

    def test_required_case_fields(self, checks_by_name):
        assert checks_by_name["required_case_fields"]["passed"]

    def test_publication_urls_https(self, checks_by_name):
        assert checks_by_name["publication_urls_https"]["passed"]

    def test_summary_verdict_true(self, checks_by_name):
        assert checks_by_name["summary_verdict_true"]["passed"]

    def test_rust_test_coverage(self, checks_by_name):
        assert checks_by_name["rust_test_coverage"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [entry["check"] for entry in mod._checks() if not entry["passed"]]
        assert not failed, f"Failed checks: {failed}"

    def test_minimum_check_count(self):
        assert len(mod._checks()) >= 20

    def test_human_output_contains_pass(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-cv49" in result.stdout
        assert "PASS" in result.stdout
