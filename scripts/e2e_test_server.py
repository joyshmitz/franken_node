#!/usr/bin/env python3
"""Minimal HTTP test server mirroring the frankenengine-node API surface.

This server implements the same routes defined in ``src/api/`` skeleton
handlers, returning synthetic JSON responses suitable for E2E integration
testing.  It binds to ``localhost:0`` (OS-assigned port) and prints the
actual port to stdout as JSON: ``{"port": 12345}``.

Usage:
    python3 scripts/e2e_test_server.py                 # start server
    python3 scripts/e2e_test_server.py --port 9090     # fixed port
    python3 scripts/e2e_test_server.py --self-test      # smoke test

Routes served:
    GET  /v1/operator/health       — health check (no auth)
    GET  /v1/operator/status       — node status
    GET  /v1/operator/config       — config view
    GET  /v1/operator/rollout      — rollout state
    POST /v1/verifier/conformance  — trigger conformance check
    GET  /v1/verifier/evidence/{id} — retrieve evidence
    GET  /v1/verifier/audit-log    — audit log query
    GET  /v1/fleet/leases          — list leases
    POST /v1/fleet/leases          — acquire lease
    DELETE /v1/fleet/leases/{id}   — release lease
    POST /v1/fleet/fence           — fencing op
    POST /v1/fleet/coordinate      — multi-node coordination
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
import threading
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


logger = configure_test_logging("e2e_test_server")

# ── Synthetic response builders ──────────────────────────────────────────

def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _check_id(trace_id: str = "") -> str:
    prefix = trace_id[:12] if trace_id else uuid.uuid4().hex[:12]
    return f"chk-{prefix}"


def health_response() -> dict[str, Any]:
    return {"ok": True, "data": {"status": "healthy", "uptime_secs": 42}}


def status_response() -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "node_id": "test-node-001",
            "version": "0.1.0-test",
            "status": "running",
            "started_at": "2026-01-01T00:00:00Z",
        },
    }


def config_response() -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "listen_addr": "127.0.0.1:0",
            "log_level": "debug",
            "test_mode": True,
        },
    }


def rollout_response() -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "phase": "canary",
            "progress_pct": 0,
            "target_version": "0.1.0-test",
        },
    }


def conformance_response(body: dict | None = None) -> dict[str, Any]:
    trace_id = (body or {}).get("trace_id", "")
    check_id = _check_id(trace_id)
    return {
        "ok": True,
        "data": {
            "check_id": check_id,
            "status": "Pass",
            "total_checks": 2,
            "passed": 2,
            "failed": 0,
            "skipped": 0,
            "findings": [
                {
                    "check_name": "trust_card_schema",
                    "status": "Pass",
                    "detail": "validates against contract",
                    "severity": "info",
                },
                {
                    "check_name": "error_code_coverage",
                    "status": "Pass",
                    "detail": "all FRANKEN_* codes mapped",
                    "severity": "info",
                },
            ],
            "triggered_at": _utc_now(),
        },
    }


def evidence_response(check_id: str) -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "check_id": check_id,
            "artifact_type": "conformance_evidence",
            "content_hash": hashlib.sha256(check_id.encode()).hexdigest(),
            "size_bytes": 128,
            "created_at": _utc_now(),
            "content": {"skeleton": True, "check_id": check_id},
        },
    }


def audit_log_response() -> dict[str, Any]:
    return {"ok": True, "data": [], "page": None}


def leases_list_response() -> dict[str, Any]:
    return {"ok": True, "data": [], "page": None}


def lease_acquire_response() -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "lease_id": f"lease-{uuid.uuid4().hex[:8]}",
            "holder": "test-holder",
            "acquired_at": _utc_now(),
            "ttl_secs": 300,
        },
    }


def lease_release_response(lease_id: str) -> dict[str, Any]:
    return {"ok": True, "data": {"lease_id": lease_id, "released": True}}


def fence_response() -> dict[str, Any]:
    return {"ok": True, "data": {"fenced": True, "epoch": 1}}


def coordinate_response() -> dict[str, Any]:
    return {"ok": True, "data": {"accepted": True, "participants": 1}}


# ── Node lifecycle routes ────────────────────────────────────────────────

def config_reload_response() -> dict[str, Any]:
    return {"ok": True, "data": {"reloaded": True, "version": "0.1.0-test"}}


def shutdown_response() -> dict[str, Any]:
    return {"ok": True, "data": {"graceful": True, "drain_secs": 5}}


# ── Connector handshake routes ───────────────────────────────────────────

def connector_register_response(body: dict | None = None) -> dict[str, Any]:
    cid = (body or {}).get("connector_id", f"conn-{uuid.uuid4().hex[:8]}")
    return {"ok": True, "data": {"connector_id": cid, "registered": True, "version": "1.0"}}


def connector_negotiate_response() -> dict[str, Any]:
    return {"ok": True, "data": {"protocol_version": "1.0", "capabilities": ["fencing", "health"]}}


def connector_activate_response() -> dict[str, Any]:
    return {"ok": True, "data": {"active": True, "state": "active"}}


# ── Security pipeline routes ─────────────────────────────────────────────

def intent_classify_response(body: dict | None = None) -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "classification": "allowed",
            "confidence": 0.95,
            "intent_id": f"int-{uuid.uuid4().hex[:8]}",
        },
    }


def firewall_evaluate_response() -> dict[str, Any]:
    return {"ok": True, "data": {"verdict": "allow", "rationale": "trusted origin"}}


def quarantine_status_response() -> dict[str, Any]:
    return {"ok": True, "data": {"quarantined": [], "count": 0}}


def sybil_check_response() -> dict[str, Any]:
    return {"ok": True, "data": {"is_sybil": False, "trust_weight": 1.0}}


# ── Migration workflow routes ────────────────────────────────────────────

def migration_plan_response() -> dict[str, Any]:
    return {
        "ok": True,
        "data": {
            "plan_id": f"plan-{uuid.uuid4().hex[:8]}",
            "phase": "admission",
            "verdict": "allow",
        },
    }


def migration_validate_response() -> dict[str, Any]:
    return {"ok": True, "data": {"valid": True, "checks_passed": 5, "checks_failed": 0}}


def migration_execute_response() -> dict[str, Any]:
    return {"ok": True, "data": {"status": "completed", "rollback_needed": False}}


def migration_rollback_response() -> dict[str, Any]:
    return {"ok": True, "data": {"rolled_back": True, "to_version": "v0.9.0"}}


# ── Verifier economy routes ──────────────────────────────────────────────

def verifier_register_response() -> dict[str, Any]:
    return {"ok": True, "data": {"verifier_id": f"ver-{uuid.uuid4().hex[:8]}", "registered": True}}


def staking_deposit_response() -> dict[str, Any]:
    return {"ok": True, "data": {"staked": True, "amount": 1000, "epoch": 1}}


def challenge_submit_response() -> dict[str, Any]:
    return {"ok": True, "data": {"challenge_id": f"ch-{uuid.uuid4().hex[:8]}", "accepted": True}}


def reward_claim_response() -> dict[str, Any]:
    return {"ok": True, "data": {"claimed": True, "amount": 50, "epoch": 1}}


def slash_report_response() -> dict[str, Any]:
    return {"ok": True, "data": {"slashed": True, "amount": 100, "reason": "invalid_proof"}}


# ── HTTP Handler ─────────────────────────────────────────────────────────

class TestAPIHandler(BaseHTTPRequestHandler):
    """Routes requests to synthetic response builders."""

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        routes: dict[str, tuple[int, dict]] = {
            "/v1/operator/health": (200, health_response()),
            "/v1/operator/status": (200, status_response()),
            "/v1/operator/config": (200, config_response()),
            "/v1/operator/rollout": (200, rollout_response()),
            "/v1/verifier/audit-log": (200, audit_log_response()),
            "/v1/fleet/leases": (200, leases_list_response()),
            "/v1/security/quarantine": (200, quarantine_status_response()),
        }

        if path in routes:
            status, body = routes[path]
            self._send_json(status, body)
            return

        if path.startswith("/v1/verifier/evidence/"):
            check_id = path.split("/")[-1]
            self._send_json(200, evidence_response(check_id))
            return

        self._send_json(404, {"ok": False, "error": f"not found: {path}"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        body = self._read_body()

        routes: dict[str, tuple[int, dict]] = {
            "/v1/verifier/conformance": (200, conformance_response(body)),
            "/v1/fleet/leases": (201, lease_acquire_response()),
            "/v1/fleet/fence": (200, fence_response()),
            "/v1/fleet/coordinate": (200, coordinate_response()),
            # Node lifecycle
            "/v1/operator/config/reload": (200, config_reload_response()),
            "/v1/operator/shutdown": (200, shutdown_response()),
            # Connector handshake
            "/v1/connector/register": (200, connector_register_response(body)),
            "/v1/connector/negotiate": (200, connector_negotiate_response()),
            "/v1/connector/activate": (200, connector_activate_response()),
            # Security pipeline
            "/v1/security/intent/classify": (200, intent_classify_response(body)),
            "/v1/security/firewall/evaluate": (200, firewall_evaluate_response()),
            "/v1/security/sybil/check": (200, sybil_check_response()),
            # Migration workflow
            "/v1/migration/plan": (200, migration_plan_response()),
            "/v1/migration/validate": (200, migration_validate_response()),
            "/v1/migration/execute": (200, migration_execute_response()),
            "/v1/migration/rollback": (200, migration_rollback_response()),
            # Verifier economy
            "/v1/verifier/register": (200, verifier_register_response()),
            "/v1/staking/deposit": (200, staking_deposit_response()),
            "/v1/challenge/submit": (200, challenge_submit_response()),
            "/v1/reward/claim": (200, reward_claim_response()),
            "/v1/slash/report": (200, slash_report_response()),
        }

        if path in routes:
            status, resp = routes[path]
            self._send_json(status, resp)
            return

        self._send_json(404, {"ok": False, "error": f"not found: {path}"})

    def do_DELETE(self) -> None:
        path = self.path.split("?")[0]
        if path.startswith("/v1/fleet/leases/"):
            lease_id = path.split("/")[-1]
            self._send_json(200, lease_release_response(lease_id))
            return
        self._send_json(404, {"ok": False, "error": f"not found: {path}"})


# ── Server lifecycle ─────────────────────────────────────────────────────

def start_server(port: int = 0) -> tuple[HTTPServer, int]:
    """Start the test server and return (server, actual_port)."""
    server = HTTPServer(("127.0.0.1", port), TestAPIHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port


# ── Self-test ────────────────────────────────────────────────────────────

def self_test() -> None:
    """Smoke-test: start server, hit all endpoints, verify JSON responses."""
    import urllib.request

    server, port = start_server()
    base = f"http://127.0.0.1:{port}"
    checks = 0
    passed = 0

    def get(path: str) -> dict:
        nonlocal checks, passed
        checks += 1
        req = urllib.request.Request(f"{base}{path}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert data.get("ok") is True, f"GET {path}: ok != True"
            passed += 1
            return data

    def post(path: str, body: dict | None = None) -> dict:
        nonlocal checks, passed
        checks += 1
        payload = json.dumps(body or {}).encode()
        req = urllib.request.Request(
            f"{base}{path}", data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert data.get("ok") is True, f"POST {path}: ok != True"
            passed += 1
            return data

    def delete(path: str) -> dict:
        nonlocal checks, passed
        checks += 1
        req = urllib.request.Request(f"{base}{path}", method="DELETE")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert data.get("ok") is True, f"DELETE {path}: ok != True"
            passed += 1
            return data

    # Operator routes
    h = get("/v1/operator/health")
    assert h["data"]["status"] == "healthy"
    get("/v1/operator/status")
    get("/v1/operator/config")
    get("/v1/operator/rollout")

    # Verifier routes
    conf = post("/v1/verifier/conformance", {"trace_id": "test-trace"})
    assert conf["data"]["status"] == "Pass"
    check_id = conf["data"]["check_id"]
    ev = get(f"/v1/verifier/evidence/{check_id}")
    assert ev["data"]["check_id"] == check_id
    get("/v1/verifier/audit-log")

    # Fleet routes
    get("/v1/fleet/leases")
    lease = post("/v1/fleet/leases")
    lease_id = lease["data"]["lease_id"]
    delete(f"/v1/fleet/leases/{lease_id}")
    post("/v1/fleet/fence")
    post("/v1/fleet/coordinate")

    # Node lifecycle routes
    post("/v1/operator/config/reload")
    post("/v1/operator/shutdown")

    # Connector routes
    cr = post("/v1/connector/register", {"connector_id": "conn-test"})
    assert cr["data"]["registered"] is True
    post("/v1/connector/negotiate")
    post("/v1/connector/activate")

    # Security routes
    ic = post("/v1/security/intent/classify", {"effect_id": "e-1"})
    assert ic["data"]["classification"] == "allowed"
    post("/v1/security/firewall/evaluate")
    get("/v1/security/quarantine")
    post("/v1/security/sybil/check")

    # Migration routes
    post("/v1/migration/plan")
    post("/v1/migration/validate")
    post("/v1/migration/execute")
    post("/v1/migration/rollback")

    # Verifier economy routes
    post("/v1/verifier/register")
    post("/v1/staking/deposit")
    post("/v1/challenge/submit")
    post("/v1/reward/claim")
    post("/v1/slash/report")

    server.shutdown()
    print(f"self_test PASSED ({passed}/{checks} checks)")


def main() -> None:
    parser = argparse.ArgumentParser(description="E2E test API server")
    parser.add_argument("--port", type=int, default=0, help="Port to listen on (0=auto)")
    parser.add_argument("--self-test", action="store_true", help="Run smoke test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    server, port = start_server(args.port)
    # Machine-readable port announcement
    print(json.dumps({"port": port}), flush=True)
    logger.info("test server listening on 127.0.0.1:%d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
