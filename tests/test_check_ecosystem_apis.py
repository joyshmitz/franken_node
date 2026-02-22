"""Unit tests for scripts/check_ecosystem_apis.py (bd-2aj)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add scripts directory to import path.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_ecosystem_apis as checker


class TestSelfTest:
    def test_self_test_passes(self) -> None:
        assert checker.self_test() is True


class TestFileChecks:
    def test_contract_exists(self) -> None:
        result = checker.check_file_exists(checker.CONTRACT_PATH)
        assert result["exists"] is True
        assert result["size_bytes"] > 0

    def test_schema_exists(self) -> None:
        result = checker.check_file_exists(checker.API_SCHEMA_PATH)
        assert result["exists"] is True
        assert result["size_bytes"] > 0

    def test_registry_module_exists(self) -> None:
        result = checker.check_file_exists(checker.REGISTRY_PATH)
        assert result["exists"] is True

    def test_reputation_module_exists(self) -> None:
        result = checker.check_file_exists(checker.REPUTATION_PATH)
        assert result["exists"] is True

    def test_compliance_module_exists(self) -> None:
        result = checker.check_file_exists(checker.COMPLIANCE_PATH)
        assert result["exists"] is True


class TestContractCoverage:
    def test_contract_invariants_present(self) -> None:
        result = checker.check_content(
            checker.CONTRACT_PATH,
            checker.REQUIRED_CONTRACT_INVARIANTS,
            "contract file not found",
        )
        assert result["pass"] is True, f"missing invariants: {result['missing']}"


class TestApiSchemaCoverage:
    def test_schema_endpoints_present(self) -> None:
        result = checker.check_content(
            checker.API_SCHEMA_PATH,
            checker.REQUIRED_SCHEMA_ENDPOINTS,
            "api schema file not found",
        )
        assert result["pass"] is True, f"missing endpoints: {result['missing']}"

    def test_endpoint_coverage_threshold(self) -> None:
        result = checker.check_endpoint_coverage()
        assert result["pass"] is True
        assert result["coverage_pct"] >= 95.0

    def test_auth_and_pagination_terms_present(self) -> None:
        result = checker.check_content(
            checker.API_SCHEMA_PATH,
            checker.REQUIRED_SCHEMA_AUTH_TERMS,
            "api schema file not found",
        )
        assert result["pass"] is True, f"missing terms: {result['missing']}"


class TestRustSymbolCoverage:
    def test_registry_symbols_present(self) -> None:
        result = checker.check_content(
            checker.REGISTRY_PATH,
            checker.REQUIRED_REGISTRY_SYMBOLS,
            "registry module not found",
        )
        assert result["pass"] is True, f"missing symbols: {result['missing']}"

    def test_reputation_symbols_present(self) -> None:
        result = checker.check_content(
            checker.REPUTATION_PATH,
            checker.REQUIRED_REPUTATION_SYMBOLS,
            "reputation module not found",
        )
        assert result["pass"] is True, f"missing symbols: {result['missing']}"

    def test_compliance_symbols_present(self) -> None:
        result = checker.check_content(
            checker.COMPLIANCE_PATH,
            checker.REQUIRED_COMPLIANCE_SYMBOLS,
            "compliance module not found",
        )
        assert result["pass"] is True, f"missing symbols: {result['missing']}"


class TestBehaviorChecks:
    def test_event_codes_present(self) -> None:
        result = checker.check_event_codes()
        assert result["pass"] is True, f"missing event codes: {result['missing']}"

    def test_anti_gaming_markers_present(self) -> None:
        result = checker.check_anti_gaming()
        assert result["pass"] is True, f"missing markers: {result['missing']}"

    def test_cross_program_evidence_tests_present(self) -> None:
        result = checker.check_cross_program_evidence()
        assert result["pass"] is True, f"missing tests: {result['missing']}"

    def test_mod_registration(self) -> None:
        result = checker.check_mod_registration()
        assert result["pass"] is True, f"missing modules: {result['missing']}"


class TestFullEvidence:
    def test_run_all_checks_shape(self) -> None:
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-2aj"
        assert evidence["section"] == "10.12"
        assert "timestamp" in evidence
        assert "checks" in evidence
        assert "summary" in evidence

    def test_overall_pass(self) -> None:
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_summary_counts(self) -> None:
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 12
        assert evidence["summary"]["passed"] == 12
        assert evidence["summary"]["failed"] == 0

    def test_json_serializable(self) -> None:
        evidence = checker.run_all_checks()
        payload = json.dumps(evidence)
        assert len(payload) > 0
        restored = json.loads(payload)
        assert restored["bead_id"] == "bd-2aj"
