"""Unit tests for scripts/lib/e2e_scenario_logger.py."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.e2e_scenario_logger import ScenarioTimeline


@pytest.fixture(autouse=True)
def _isolate_loggers():
    """Clean up loggers after each test."""
    yield
    manager = logging.Logger.manager
    to_remove = [
        name for name in list(manager.loggerDict)
        if name.startswith("e2e_test_")
    ]
    for name in to_remove:
        logger = manager.loggerDict[name]
        if isinstance(logger, logging.Logger):
            logger.handlers.clear()
        del manager.loggerDict[name]


class TestScenarioTimeline:
    """Core timeline behavior."""

    def test_start_and_end_scenario(self):
        tl = ScenarioTimeline("e2e_test_start_end", json_mode=False)
        tl.start_scenario("basic")
        tl.end_scenario(passed=True)
        report = tl.build_report()
        assert report.scenario_name == "basic"
        assert report.passed is True
        assert report.event_count == 2

    def test_failed_scenario(self):
        tl = ScenarioTimeline("e2e_test_fail", json_mode=False)
        tl.start_scenario("fail_case")
        tl.end_scenario(passed=False)
        assert tl.build_report().passed is False

    def test_request_response_pair(self):
        tl = ScenarioTimeline("e2e_test_reqresp", json_mode=False)
        tl.start_scenario("http")
        rid = tl.log_request("POST", "/v1/test", body='{"x":1}')
        tl.log_response(rid, status=201, body='{"id":"abc"}')
        tl.end_scenario(passed=True)
        report = tl.build_report()
        assert report.request_count == 1
        # Check events have matching req_id
        req_evt = [e for e in report.events if e["kind"] == "http_request"]
        resp_evt = [e for e in report.events if e["kind"] == "http_response"]
        assert len(req_evt) == 1
        assert len(resp_evt) == 1
        assert req_evt[0]["req_id"] == resp_evt[0]["req_id"]

    def test_multiple_requests_get_distinct_ids(self):
        tl = ScenarioTimeline("e2e_test_multi_req", json_mode=False)
        tl.start_scenario("multi")
        r1 = tl.log_request("GET", "/a")
        r2 = tl.log_request("GET", "/b")
        assert r1 != r2

    def test_process_lifecycle(self):
        tl = ScenarioTimeline("e2e_test_proc", json_mode=False)
        tl.start_scenario("proc")
        tl.log_process_start("node", pid=42, cmd=["./node"])
        tl.log_process_stop("node", exit_code=0, pid=42)
        tl.end_scenario(passed=True)
        report = tl.build_report()
        assert report.process_count == 1
        start_evts = [e for e in report.events if e["kind"] == "process_start"]
        stop_evts = [e for e in report.events if e["kind"] == "process_stop"]
        assert len(start_evts) == 1
        assert start_evts[0]["pid"] == 42
        assert stop_evts[0]["exit_code"] == 0

    def test_process_nonzero_exit(self):
        tl = ScenarioTimeline("e2e_test_proc_fail", json_mode=False)
        tl.start_scenario("proc_fail")
        tl.log_process_start("crasher", pid=99)
        tl.log_process_stop("crasher", exit_code=1, pid=99)
        tl.end_scenario(passed=False)
        stop = [e for e in tl.build_report().events if e["kind"] == "process_stop"][0]
        assert stop["exit_code"] == 1

    def test_monotonic_sequence_numbers(self):
        tl = ScenarioTimeline("e2e_test_seq", json_mode=False)
        tl.start_scenario("seq")
        tl.log_request("GET", "/a")
        tl.log_event("custom", detail="x")
        tl.end_scenario(passed=True)
        seqs = [e["seq"] for e in tl.build_report().events]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == len(seqs)

    def test_custom_event(self):
        tl = ScenarioTimeline("e2e_test_custom_evt", json_mode=False)
        tl.start_scenario("custom")
        seq = tl.log_event("assertion_check", check="health_ok", result=True)
        tl.end_scenario(passed=True)
        custom = [e for e in tl.build_report().events if e["kind"] == "assertion_check"]
        assert len(custom) == 1
        assert custom[0]["check"] == "health_ok"
        assert custom[0]["seq"] == seq

    def test_report_json_roundtrip(self):
        tl = ScenarioTimeline("e2e_test_json_rt", json_mode=False)
        tl.start_scenario("json_rt")
        tl.end_scenario(passed=True)
        report = tl.build_report()
        parsed = json.loads(report.to_json())
        assert parsed["scenario_name"] == "json_rt"
        assert parsed["passed"] is True
        assert isinstance(parsed["events"], list)

    def test_duration_is_positive(self):
        tl = ScenarioTimeline("e2e_test_dur", json_mode=False)
        tl.start_scenario("dur")
        # Tiny sleep not needed — just ensure non-negative
        tl.end_scenario(passed=True)
        assert tl.build_report().duration_secs >= 0.0

    def test_report_without_start_is_unnamed(self):
        tl = ScenarioTimeline("e2e_test_no_start", json_mode=False)
        report = tl.build_report()
        assert report.scenario_name == "(unnamed)"
        assert report.passed is False

    def test_request_body_truncation(self):
        tl = ScenarioTimeline("e2e_test_trunc", json_mode=False)
        tl.start_scenario("trunc")
        big_body = "x" * 10000
        rid = tl.log_request("POST", "/big", body=big_body)
        tl.end_scenario(passed=True)
        req = [e for e in tl.build_report().events if e["kind"] == "http_request"][0]
        assert len(req["body"]) == 4096

    def test_request_headers_captured(self):
        tl = ScenarioTimeline("e2e_test_hdrs", json_mode=False)
        tl.start_scenario("hdrs")
        rid = tl.log_request("GET", "/h", headers={"Authorization": "Bearer tok"})
        tl.log_response(rid, status=200, headers={"Content-Type": "application/json"})
        tl.end_scenario(passed=True)
        req = [e for e in tl.build_report().events if e["kind"] == "http_request"][0]
        resp = [e for e in tl.build_report().events if e["kind"] == "http_response"][0]
        assert req["headers"]["Authorization"] == "Bearer tok"
        assert resp["headers"]["Content-Type"] == "application/json"

    def test_event_timestamps_are_positive(self):
        tl = ScenarioTimeline("e2e_test_ts", json_mode=False)
        tl.start_scenario("ts")
        tl.end_scenario(passed=True)
        for evt in tl.build_report().events:
            assert evt["ts"] > 0

    def test_process_cmd_captured(self):
        tl = ScenarioTimeline("e2e_test_cmd", json_mode=False)
        tl.start_scenario("cmd")
        tl.log_process_start("svc", cmd=["./svc", "--port", "8080"])
        tl.end_scenario(passed=True)
        proc = [e for e in tl.build_report().events if e["kind"] == "process_start"][0]
        assert proc["cmd"] == ["./svc", "--port", "8080"]


class TestSelfTest:
    def test_self_test_runs(self, capsys):
        from scripts.lib.e2e_scenario_logger import self_test
        self_test()
        assert "PASSED" in capsys.readouterr().out
