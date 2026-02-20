#!/usr/bin/env python3
"""Verification script for bd-2f5l: fastapi_rust service skeleton.

Usage:
    python3 scripts/check_fastapi_skeleton.py          # human-readable
    python3 scripts/check_fastapi_skeleton.py --json   # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IMPL = ROOT / "tests" / "integration" / "fastapi_control_plane_endpoints.rs"
REPORT = ROOT / "artifacts" / "10.16" / "fastapi_endpoint_report.json"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-2f5l_contract.md"

# -- Constants ---------------------------------------------------------------

ENDPOINT_PATHS = [
    "/v1/operator/status",
    "/v1/operator/health",
    "/v1/operator/config",
    "/v1/operator/rollout",
    "/v1/verifier/conformance",
    "/v1/verifier/evidence",
    "/v1/verifier/audit-log",
    "/v1/fleet/lease",
    "/v1/fleet/fence",
    "/v1/fleet/coordinate",
]

EVENT_CODES = [
    "FASTAPI_SKELETON_INIT",
    "FASTAPI_ENDPOINT_REGISTERED",
    "FASTAPI_MIDDLEWARE_WIRED",
    "FASTAPI_AUTH_REJECT",
    "FASTAPI_RATE_LIMIT_HIT",
    "FASTAPI_ERROR_RESPONSE",
]

INVARIANTS = [
    "INV-FAS-ENDPOINTS",
    "INV-FAS-MIDDLEWARE",
    "INV-FAS-AUTH",
    "INV-FAS-ERRORS",
]

MIDDLEWARE_LAYERS = [
    "TraceContext",
    "Authentication",
    "Authorization",
    "RateLimit",
    "ErrorFormatting",
    "Telemetry",
]

REQUIRED_TYPES = [
    "EndpointLifecycle",
    "EndpointGroup",
    "HttpMethod",
    "AuthMethod",
    "MiddlewareLayer",
    "EndpointDef",
    "ServiceEvent",
    "FastapiSkeletonGate",
    "SkeletonSummary",
]

REQUIRED_METHODS = [
    "fn all()",
    "fn label(",
    "fn is_active(",
    "fn new()",
    "fn register_endpoint(",
    "fn wire_middleware(",
    "fn gate_pass(",
    "fn summary(",
    "fn endpoints(",
    "fn events(",
    "fn take_events(",
    "fn to_report(",
]

REQUIRED_TESTS = [
    "test_lifecycle_all_count",
    "test_lifecycle_labels",
    "test_lifecycle_is_active",
    "test_lifecycle_serde_roundtrip",
    "test_endpoint_group_all_count",
    "test_endpoint_group_labels",
    "test_endpoint_group_serde_roundtrip",
    "test_middleware_all_count",
    "test_middleware_labels",
    "test_canonical_endpoint_count",
    "test_canonical_operator_count",
    "test_canonical_verifier_count",
    "test_canonical_fleet_control_count",
    "test_canonical_all_stable",
    "test_canonical_all_traced",
    "test_canonical_unique_paths",
    "test_gate_empty_fails",
    "test_gate_all_wired_passes",
    "test_gate_missing_middleware_fails",
    "test_gate_missing_group_fails",
    "test_register_endpoint_emits_event",
    "test_wire_middleware_emits_event",
    "test_init_emits_event",
    "test_take_events_drains",
    "test_summary_counts",
    "test_report_structure",
    "test_report_pass_verdict",
    "test_report_fail_verdict_empty",
    "test_report_endpoints_count",
    "test_invariant_constants_defined",
    "test_event_code_constants_defined",
    "test_determinism_same_input_same_report",
    "test_endpoint_def_serde_roundtrip",
    "test_service_event_serde_roundtrip",
    "test_auth_methods_by_group",
    "test_fleet_control_uses_fleet_mutate_hook",
    "test_all_endpoints_have_status_codes",
    "test_all_versioned_paths",
]


# -- Helpers -----------------------------------------------------------------

def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"File exists: {label}",
        "pass": ok,
        "detail": str(path.relative_to(ROOT)) if ok else f"Missing: {path}",
    }


def check_content(path: Path, needles: list[str], category: str) -> list[dict]:
    results = []
    if not path.exists():
        for n in needles:
            results.append({"check": f"{category}: {n}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for n in needles:
        found = n in text
        results.append({
            "check": f"{category}: {n}",
            "pass": found,
            "detail": "found" if found else "not found",
        })
    return results


def check_impl_test_count() -> dict:
    if not IMPL.exists():
        return {"check": "Rust test count >= 35", "pass": False, "detail": "file missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    return {
        "check": "Rust test count >= 35",
        "pass": count >= 35,
        "detail": f"{count} tests found",
    }


def check_report() -> list[dict]:
    results = []
    if not REPORT.exists():
        results.append({"check": "Report exists", "pass": False, "detail": "file missing"})
        return results
    data = json.loads(REPORT.read_text())

    # gate verdict
    results.append({
        "check": "Report: gate verdict PASS",
        "pass": data.get("gate_verdict") == "PASS",
        "detail": data.get("gate_verdict", "missing"),
    })

    # endpoint count
    eps = data.get("endpoints", [])
    results.append({
        "check": "Report: 10 endpoints",
        "pass": len(eps) == 10,
        "detail": f"{len(eps)} endpoints",
    })

    # all conformance pass
    all_pass = all(e.get("conformance_status") == "pass" for e in eps)
    results.append({
        "check": "Report: all conformance pass",
        "pass": all_pass,
        "detail": "all pass" if all_pass else "some fail",
    })

    # group counts
    groups = {}
    for e in eps:
        g = e.get("group", "unknown")
        groups[g] = groups.get(g, 0) + 1
    results.append({
        "check": "Report: 4 operator endpoints",
        "pass": groups.get("operator") == 4,
        "detail": f"{groups.get('operator', 0)} operator",
    })
    results.append({
        "check": "Report: 3 verifier endpoints",
        "pass": groups.get("verifier") == 3,
        "detail": f"{groups.get('verifier', 0)} verifier",
    })
    results.append({
        "check": "Report: 3 fleet_control endpoints",
        "pass": groups.get("fleet_control") == 3,
        "detail": f"{groups.get('fleet_control', 0)} fleet_control",
    })

    # all traced
    all_traced = all(e.get("trace_propagation") is True for e in eps)
    results.append({
        "check": "Report: all endpoints traced",
        "pass": all_traced,
        "detail": "all traced" if all_traced else "some untraced",
    })

    # middleware coverage
    mw = data.get("middleware_coverage", {})
    all_mw = all(mw.get(k) is True for k in [
        "trace_context", "authentication", "authorization",
        "rate_limit", "error_formatting", "telemetry",
    ])
    results.append({
        "check": "Report: all middleware covered",
        "pass": all_mw,
        "detail": "all covered" if all_mw else "gaps",
    })

    # endpoint paths
    for path in ENDPOINT_PATHS:
        found = any(e.get("path") == path for e in eps)
        results.append({
            "check": f"Report: endpoint {path}",
            "pass": found,
            "detail": "found" if found else "missing",
        })

    # auth by group
    operator_auth = all(
        e.get("auth_method") == "api_key"
        for e in eps if e.get("group") == "operator"
    )
    results.append({
        "check": "Report: operator auth = api_key",
        "pass": operator_auth,
        "detail": "correct" if operator_auth else "wrong auth",
    })
    verifier_auth = all(
        e.get("auth_method") == "bearer_token"
        for e in eps if e.get("group") == "verifier"
    )
    results.append({
        "check": "Report: verifier auth = bearer_token",
        "pass": verifier_auth,
        "detail": "correct" if verifier_auth else "wrong auth",
    })
    fleet_auth = all(
        e.get("auth_method") == "mtls_cert"
        for e in eps if e.get("group") == "fleet_control"
    )
    results.append({
        "check": "Report: fleet_control auth = mtls_cert",
        "pass": fleet_auth,
        "detail": "correct" if fleet_auth else "wrong auth",
    })

    # all versioned
    all_versioned = all(e.get("path", "").startswith("/v1/") for e in eps)
    results.append({
        "check": "Report: all paths versioned /v1/",
        "pass": all_versioned,
        "detail": "all versioned" if all_versioned else "some unversioned",
    })

    # all have status codes
    all_codes = all(len(e.get("status_codes", [])) > 0 for e in eps)
    results.append({
        "check": "Report: all endpoints have status codes",
        "pass": all_codes,
        "detail": "all have codes" if all_codes else "some empty",
    })

    return results


def check_spec() -> list[dict]:
    results = []
    if not SPEC.exists():
        results.append({"check": "Spec doc exists", "pass": False, "detail": "file missing"})
        return results
    text = SPEC.read_text()
    for section in ["Types", "Methods", "Event Codes", "Invariants", "Acceptance Criteria"]:
        found = f"## {section}" in text
        results.append({
            "check": f"Spec: has {section}",
            "pass": found,
            "detail": "found" if found else "missing",
        })
    return results


# -- Main --------------------------------------------------------------------

def run_checks() -> dict:
    checks = []

    # File existence
    checks.append(check_file(IMPL, "integration tests"))
    checks.append(check_file(REPORT, "endpoint report"))
    checks.append(check_file(SPEC, "spec doc"))

    # Rust test count
    checks.append(check_impl_test_count())

    # Serde derives
    checks.extend(check_content(IMPL, ["Serialize", "Deserialize"], "serde"))

    # Types
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))

    # Methods
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))

    # Event codes
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))

    # Invariants
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))

    # Middleware layers
    checks.extend(check_content(IMPL, MIDDLEWARE_LAYERS, "middleware"))

    # Test names
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Report
    checks.extend(check_report())

    # Spec
    checks.extend(check_spec())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-2f5l",
        "title": "fastapi_rust service skeleton",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test() -> tuple[bool, str]:
    result = run_checks()
    if result["overall_pass"]:
        return True, f"All {result['summary']['total']} checks pass"
    fails = [c["check"] for c in result["checks"] if not c["pass"]]
    return False, f"{len(fails)} failing: {'; '.join(fails[:5])}"


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
        print()
        s = result["summary"]
        print(f"Result: {result['verdict']} ({s['passing']}/{s['total']} checks pass)")

    sys.exit(0 if result["overall_pass"] else 1)
