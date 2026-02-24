"""E2E scenario logging with structured timeline, request/response capture, and process tracking.

Builds on ``test_logger.configure_test_logging`` to provide:

1. **Monotonic sequence numbers** — each event gets a globally ordered ``seq``.
2. **HTTP request/response capture** — ``log_request`` / ``log_response`` emit
   structured pairs linked by ``req_id``.
3. **Process management tracking** — ``log_process_start`` / ``log_process_stop``
   track subprocess lifecycle.
4. **Scenario timeline** — ``ScenarioTimeline`` aggregates all events in
   wall-clock order for post-hoc analysis.

Usage::

    from scripts.lib.e2e_scenario_logger import ScenarioTimeline

    timeline = ScenarioTimeline("e2e_node_lifecycle")
    timeline.start_scenario("boot-and-health")
    req_id = timeline.log_request("POST", "/v1/verifier/conformance", body="{}")
    timeline.log_response(req_id, status=200, body='{"ok":true}')
    timeline.end_scenario(passed=True)
    report = timeline.build_report()
"""

from __future__ import annotations

import itertools
import json
import time
from dataclasses import dataclass, field
from typing import Any

from scripts.lib.test_logger import configure_test_logging

__all__ = ["ScenarioTimeline"]


# ── Monotonic sequence generator ─────────────────────────────────────────

_global_seq = itertools.count(1)


def _next_seq() -> int:
    return next(_global_seq)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    """Single event in the scenario timeline."""

    seq: int
    ts: float
    kind: str
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            **self.data,
        }


@dataclass
class ScenarioReport:
    """Final report summarizing an E2E scenario run."""

    scenario_name: str
    passed: bool
    duration_secs: float
    event_count: int
    request_count: int
    process_count: int
    events: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "passed": self.passed,
            "duration_secs": round(self.duration_secs, 6),
            "event_count": self.event_count,
            "request_count": self.request_count,
            "process_count": self.process_count,
            "events": self.events,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, default=str)


# ── ScenarioTimeline ─────────────────────────────────────────────────────

class ScenarioTimeline:
    """Aggregates structured events for a single E2E scenario.

    Parameters
    ----------
    logger_name:
        Passed to ``configure_test_logging`` to set up the backing logger.
    json_mode:
        Force JSON logging.  ``None`` auto-detects from ``sys.argv``.
    """

    def __init__(self, logger_name: str, *, json_mode: bool | None = None) -> None:
        self.logger = configure_test_logging(logger_name, json_mode=json_mode)
        self._events: list[TimelineEvent] = []
        self._scenario_name: str | None = None
        self._start_time: float | None = None
        self._end_time: float | None = None
        self._passed: bool | None = None
        self._request_count = 0
        self._process_count = 0

    # ── Scenario lifecycle ───────────────────────────────────────────

    def start_scenario(self, scenario_name: str) -> None:
        """Mark the beginning of a named scenario."""
        self._scenario_name = scenario_name
        self._start_time = time.monotonic()
        evt = self._record("scenario_start", scenario_name=scenario_name)
        self.logger.info(
            "scenario started: %s", scenario_name,
            extra={"seq": evt.seq, "kind": evt.kind},
        )

    def end_scenario(self, *, passed: bool) -> None:
        """Mark the end of the current scenario."""
        self._end_time = time.monotonic()
        self._passed = passed
        verdict = "PASS" if passed else "FAIL"
        evt = self._record("scenario_end", verdict=verdict)
        self.logger.info(
            "scenario ended: %s — %s", self._scenario_name, verdict,
            extra={"seq": evt.seq, "kind": evt.kind, "passed": passed},
        )

    # ── HTTP request/response capture ────────────────────────────────

    def log_request(
        self,
        method: str,
        path: str,
        *,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> int:
        """Log an outbound HTTP request and return a ``req_id``."""
        self._request_count += 1
        req_id = self._request_count
        data: dict[str, Any] = {
            "req_id": req_id,
            "method": method,
            "path": path,
        }
        if body is not None:
            data["body"] = body[:4096]  # cap logged body size
        if headers is not None:
            data["headers"] = headers
        evt = self._record("http_request", **data)
        self.logger.debug(
            "%s %s (req_id=%d)", method, path, req_id,
            extra={"seq": evt.seq, "kind": evt.kind, "req_id": req_id},
        )
        return req_id

    def log_response(
        self,
        req_id: int,
        *,
        status: int,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Log an HTTP response paired with ``req_id``."""
        data: dict[str, Any] = {
            "req_id": req_id,
            "status": status,
        }
        if body is not None:
            data["body"] = body[:4096]
        if headers is not None:
            data["headers"] = headers
        evt = self._record("http_response", **data)
        self.logger.debug(
            "response status=%d (req_id=%d)", status, req_id,
            extra={"seq": evt.seq, "kind": evt.kind, "req_id": req_id},
        )

    # ── Process management ───────────────────────────────────────────

    def log_process_start(
        self,
        process_name: str,
        *,
        pid: int | None = None,
        cmd: list[str] | None = None,
    ) -> None:
        """Log a subprocess start event."""
        self._process_count += 1
        data: dict[str, Any] = {"process_name": process_name}
        if pid is not None:
            data["pid"] = pid
        if cmd is not None:
            data["cmd"] = cmd
        evt = self._record("process_start", **data)
        self.logger.info(
            "process started: %s (pid=%s)", process_name, pid,
            extra={"seq": evt.seq, "kind": evt.kind},
        )

    def log_process_stop(
        self,
        process_name: str,
        *,
        exit_code: int,
        pid: int | None = None,
    ) -> None:
        """Log a subprocess stop event."""
        data: dict[str, Any] = {
            "process_name": process_name,
            "exit_code": exit_code,
        }
        if pid is not None:
            data["pid"] = pid
        evt = self._record("process_stop", **data)
        level = "info" if exit_code == 0 else "warning"
        getattr(self.logger, level)(
            "process stopped: %s exit_code=%d", process_name, exit_code,
            extra={"seq": evt.seq, "kind": evt.kind},
        )

    # ── Generic event ────────────────────────────────────────────────

    def log_event(self, kind: str, **data: Any) -> int:
        """Log an arbitrary structured event. Returns the ``seq``."""
        evt = self._record(kind, **data)
        self.logger.debug("event %s seq=%d", kind, evt.seq, extra={"seq": evt.seq, "kind": kind})
        return evt.seq

    # ── Report ───────────────────────────────────────────────────────

    def build_report(self) -> ScenarioReport:
        """Build a structured summary of the scenario run."""
        duration = 0.0
        if self._start_time is not None and self._end_time is not None:
            duration = self._end_time - self._start_time
        return ScenarioReport(
            scenario_name=self._scenario_name or "(unnamed)",
            passed=self._passed if self._passed is not None else False,
            duration_secs=duration,
            event_count=len(self._events),
            request_count=self._request_count,
            process_count=self._process_count,
            events=[e.as_dict() for e in self._events],
        )

    # ── Internal ─────────────────────────────────────────────────────

    def _record(self, kind: str, **data: Any) -> TimelineEvent:
        evt = TimelineEvent(
            seq=_next_seq(),
            ts=time.time(),
            kind=kind,
            data=data,
        )
        self._events.append(evt)
        return evt


# ── Self-test ────────────────────────────────────────────────────────────

def self_test() -> None:
    """Smoke-test for the E2E scenario logger."""
    tl = ScenarioTimeline("e2e_selftest", json_mode=False)
    tl.start_scenario("smoke")
    rid = tl.log_request("GET", "/healthz")
    tl.log_response(rid, status=200, body='{"ok":true}')
    tl.log_process_start("frankenengine-node", pid=1234, cmd=["./target/debug/frankenengine-node"])
    tl.log_process_stop("frankenengine-node", exit_code=0, pid=1234)
    tl.log_event("custom", detail="something")
    tl.end_scenario(passed=True)
    report = tl.build_report()
    assert report.passed
    assert report.request_count == 1
    assert report.process_count == 1
    assert report.event_count == 7
    assert report.scenario_name == "smoke"
    # JSON round-trip
    parsed = json.loads(report.to_json())
    assert parsed["passed"] is True
    print("self_test PASSED")


if __name__ == "__main__":
    self_test()
