"""Tests for scripts/check_cancellation_protocol.py (bd-1cs7)."""

import importlib.util, json, os, subprocess, sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_cancellation_protocol.py")

spec = importlib.util.spec_from_file_location("check_cancellation_protocol", SCRIPT)
mod = importlib.util.module_from_spec(spec)
sys.modules["check_cancellation_protocol"] = mod
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-1cs7"
        assert data["section"] == "10.15"
        assert isinstance(data["checks"], list)

    def test_verdict_field(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_checks_have_fields(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        for c in data["checks"]:
            assert "check" in c and "passed" in c and "detail" in c

    def test_minimum_check_count(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert len(data["checks"]) >= 40


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {r["check"]: r for r in mod._checks()}

    def test_source_exists(self, results):
        assert results["source_exists"]["passed"]

    def test_module_wiring(self, results):
        assert results["module_wiring"]["passed"]

    def test_spec_contract_exists(self, results):
        assert results["spec_contract_exists"]["passed"]

    def test_conformance_test_exists(self, results):
        assert results["conformance_test_exists"]["passed"]

    def test_timing_csv_exists(self, results):
        assert results["timing_csv_exists"]["passed"]

    def test_evidence_exists(self, results):
        assert results["evidence_exists"]["passed"]

    def test_summary_exists(self, results):
        assert results["summary_exists"]["passed"]

    def test_type_CancelPhase(self, results):
        assert results["type_CancelPhase"]["passed"]

    def test_type_CancelProtocolError(self, results):
        assert results["type_CancelProtocolError"]["passed"]

    def test_type_DrainConfig(self, results):
        assert results["type_DrainConfig"]["passed"]

    def test_type_CancelAuditEvent(self, results):
        assert results["type_CancelAuditEvent"]["passed"]

    def test_type_ResourceTracker(self, results):
        assert results["type_ResourceTracker"]["passed"]

    def test_type_CancellationRecord(self, results):
        assert results["type_CancellationRecord"]["passed"]

    def test_type_CancellationProtocol(self, results):
        assert results["type_CancellationProtocol"]["passed"]

    def test_phase_Idle(self, results):
        assert results["phase_Idle"]["passed"]

    def test_phase_CancelRequested(self, results):
        assert results["phase_CancelRequested"]["passed"]

    def test_phase_Draining(self, results):
        assert results["phase_Draining"]["passed"]

    def test_phase_DrainComplete(self, results):
        assert results["phase_DrainComplete"]["passed"]

    def test_phase_Finalizing(self, results):
        assert results["phase_Finalizing"]["passed"]

    def test_phase_Finalized(self, results):
        assert results["phase_Finalized"]["passed"]

    def test_fn_request_cancel(self, results):
        assert results["fn_request_cancel"]["passed"]

    def test_fn_start_drain(self, results):
        assert results["fn_start_drain"]["passed"]

    def test_fn_complete_drain(self, results):
        assert results["fn_complete_drain"]["passed"]

    def test_fn_finalize(self, results):
        assert results["fn_finalize"]["passed"]

    def test_drain_timeout_ms(self, results):
        assert results["drain_timeout_ms"]["passed"]

    def test_force_on_timeout(self, results):
        assert results["force_on_timeout"]["passed"]

    def test_default_drain_timeout(self, results):
        assert results["default_drain_timeout"]["passed"]

    def test_resource_tracker_clean(self, results):
        assert results["resource_tracker_clean"]["passed"]

    def test_resource_tracker_leaks(self, results):
        assert results["resource_tracker_leaks"]["passed"]

    def test_audit_log(self, results):
        assert results["audit_log"]["passed"]

    def test_audit_event_schema(self, results):
        assert results["audit_event_schema"]["passed"]

    def test_event_codes(self, results):
        assert results["event_codes"]["passed"]

    def test_error_codes(self, results):
        assert results["error_codes"]["passed"]

    def test_invariants(self, results):
        assert results["invariants"]["passed"]

    def test_schema_version(self, results):
        assert results["schema_version"]["passed"]

    def test_idempotent_cancel(self, results):
        assert results["idempotent_cancel"]["passed"]

    def test_lifecycle_cancelling_state(self, results):
        assert results["lifecycle_cancelling_state"]["passed"]

    def test_lifecycle_cancel_transition(self, results):
        assert results["lifecycle_cancel_transition"]["passed"]

    def test_rollout_cancel_phase(self, results):
        assert results["rollout_cancel_phase"]["passed"]

    def test_rollout_set_cancel(self, results):
        assert results["rollout_set_cancel"]["passed"]

    def test_rollout_is_cancelling(self, results):
        assert results["rollout_is_cancelling"]["passed"]

    def test_rollout_imports_cancel(self, results):
        assert results["rollout_imports_cancel"]["passed"]

    def test_fn_active_count(self, results):
        assert results["fn_active_count"]["passed"]

    def test_fn_finalized_count(self, results):
        assert results["fn_finalized_count"]["passed"]

    def test_fn_current_phase(self, results):
        assert results["fn_current_phase"]["passed"]

    def test_fn_get_record(self, results):
        assert results["fn_get_record"]["passed"]

    def test_fn_timing_report(self, results):
        assert results["fn_timing_report"]["passed"]

    def test_fn_readiness_check(self, results):
        assert results["fn_readiness_check"]["passed"]

    def test_test_coverage(self, results):
        assert results["test_coverage"]["passed"]

    def test_timing_csv_header(self, results):
        assert results["timing_csv_header"]["passed"]

    def test_timing_csv_has_rows(self, results):
        assert results["timing_csv_has_rows"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [r for r in mod._checks() if not r["passed"]]
        assert len(failed) == 0, f"Failed: {[r['check'] for r in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert json.loads(result.stdout)["verdict"] == "PASS"

    def test_human_output(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-1cs7" in result.stdout and "PASS" in result.stdout
