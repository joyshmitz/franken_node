"""Unit tests for scripts/e2e_test_server.py."""

from __future__ import annotations

import json
import logging
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.e2e_test_server import start_server


@pytest.fixture(scope="module")
def server():
    """Start a shared test server for all tests in this module."""
    srv, port = start_server()
    yield port
    srv.shutdown()


@pytest.fixture(autouse=True)
def _clean_loggers():
    yield
    manager = logging.Logger.manager
    for name in list(manager.loggerDict):
        if name.startswith("e2e_test_server"):
            logger = manager.loggerDict[name]
            if isinstance(logger, logging.Logger):
                logger.handlers.clear()


def _get(port: int, path: str) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _post(port: int, path: str, body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read())


def _delete(port: int, path: str) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="DELETE")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


class TestOperatorRoutes:
    def test_health_returns_healthy(self, server):
        data = _get(server, "/v1/operator/health")
        assert data["ok"] is True
        assert data["data"]["status"] == "healthy"

    def test_status_has_node_id(self, server):
        data = _get(server, "/v1/operator/status")
        assert data["ok"] is True
        assert "node_id" in data["data"]

    def test_config_has_test_mode(self, server):
        data = _get(server, "/v1/operator/config")
        assert data["data"]["test_mode"] is True

    def test_rollout_has_phase(self, server):
        data = _get(server, "/v1/operator/rollout")
        assert data["data"]["phase"] == "canary"


class TestVerifierRoutes:
    def test_conformance_returns_pass(self, server):
        status, data = _post(server, "/v1/verifier/conformance", {"trace_id": "t1"})
        assert data["ok"] is True
        assert data["data"]["status"] == "Pass"
        assert data["data"]["passed"] > 0

    def test_conformance_check_id_uses_trace(self, server):
        _, data = _post(server, "/v1/verifier/conformance", {"trace_id": "abc123def456"})
        assert data["data"]["check_id"].startswith("chk-abc123def456")

    def test_evidence_returns_artifact(self, server):
        data = _get(server, "/v1/verifier/evidence/chk-test")
        assert data["ok"] is True
        assert data["data"]["check_id"] == "chk-test"
        assert data["data"]["artifact_type"] == "conformance_evidence"

    def test_evidence_has_hash(self, server):
        data = _get(server, "/v1/verifier/evidence/chk-42")
        assert len(data["data"]["content_hash"]) == 64  # SHA-256 hex

    def test_audit_log_returns_empty(self, server):
        data = _get(server, "/v1/verifier/audit-log")
        assert data["ok"] is True
        assert data["data"] == []


class TestFleetRoutes:
    def test_list_leases_empty(self, server):
        data = _get(server, "/v1/fleet/leases")
        assert data["ok"] is True
        assert data["data"] == []

    def test_acquire_lease(self, server):
        status, data = _post(server, "/v1/fleet/leases")
        assert data["ok"] is True
        assert data["data"]["lease_id"].startswith("lease-")

    def test_release_lease(self, server):
        data = _delete(server, "/v1/fleet/leases/lease-abc")
        assert data["ok"] is True
        assert data["data"]["lease_id"] == "lease-abc"
        assert data["data"]["released"] is True

    def test_fence_accepted(self, server):
        status, data = _post(server, "/v1/fleet/fence")
        assert data["data"]["fenced"] is True

    def test_coordinate_accepted(self, server):
        status, data = _post(server, "/v1/fleet/coordinate")
        assert data["data"]["accepted"] is True


class TestErrorHandling:
    def test_unknown_route_returns_404(self, server):
        req = urllib.request.Request(f"http://127.0.0.1:{server}/v1/unknown")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404
            body = json.loads(e.read())
            assert body["ok"] is False


class TestSelfTest:
    def test_self_test_runs(self, capsys):
        from scripts.e2e_test_server import self_test
        self_test()
        assert "PASSED" in capsys.readouterr().out
