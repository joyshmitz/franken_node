#!/usr/bin/env python3
"""Validate fastapi_rust integration contract completeness and error mapping coverage (bd-3ndj)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

CONTRACT_PATH = ROOT / "docs" / "specs" / "fastapi_rust_integration_contract.md"
CHECKLIST_PATH = ROOT / "artifacts" / "10.16" / "fastapi_contract_checklist.json"
ERROR_REGISTRY_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "error_code_registry.rs"

REQUIRED_DOC_SECTIONS = [
    "## Endpoint Lifecycle Definition",
    "## Endpoint Groups",
    "## Auth and Policy Hooks",
    "## Error Contract Mapping",
    "## Observability Requirements",
    "## Rate Limiting and Anti-Amplification",
    "## Event Codes",
]

REQUIRED_ENDPOINT_GROUPS = {"operator", "verifier", "fleet_control"}
REQUIRED_EVENT_CODES = {
    "FASTAPI_CONTRACT_LOADED",
    "FASTAPI_ENDPOINT_UNMAPPED",
    "FASTAPI_ERROR_MAPPING_INCOMPLETE",
    "FASTAPI_AUTH_UNDEFINED",
}
ALLOWED_LIFECYCLE_STATES = {"experimental", "stable", "deprecated", "removed"}
ALLOWED_CHECKLIST_STATUS = {"defined", "pending", "waived"}

ERROR_CODE_RE = re.compile(r"FRANKEN_[A-Z_]+")


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path = ROOT) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_registry_error_codes(registry_path: Path = ERROR_REGISTRY_PATH) -> set[str]:
    if not registry_path.is_file():
        raise FileNotFoundError(f"missing error registry source: {registry_path}")
    text = registry_path.read_text(encoding="utf-8")
    return set(ERROR_CODE_RE.findall(text))


def evaluate_contract(
    checklist: dict[str, Any],
    contract_text: str,
    registry_codes: set[str],
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    trace = _trace_id(checklist)
    events.append(
        {
            "event_code": "FASTAPI_CONTRACT_LOADED",
            "severity": "info",
            "trace_correlation": trace,
            "message": "Loaded fastapi integration checklist.",
        }
    )

    for section in REQUIRED_DOC_SECTIONS:
        if section not in contract_text:
            errors.append(f"contract missing section: {section}")

    event_codes = set(checklist.get("event_codes", []))
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - event_codes)
    if missing_event_codes:
        errors.append(f"missing required event codes: {', '.join(missing_event_codes)}")

    lifecycle_policy = checklist.get("lifecycle_policy")
    if not isinstance(lifecycle_policy, dict):
        errors.append("lifecycle_policy must be an object")
    else:
        states = lifecycle_policy.get("states")
        if not isinstance(states, list) or set(states) != ALLOWED_LIFECYCLE_STATES:
            errors.append(
                "lifecycle_policy.states must contain experimental/stable/deprecated/removed"
            )
        min_days = lifecycle_policy.get("min_deprecation_days")
        if not isinstance(min_days, int) or min_days <= 0:
            errors.append("lifecycle_policy.min_deprecation_days must be a positive integer")

    endpoint_groups = checklist.get("endpoint_groups")
    if not isinstance(endpoint_groups, list) or not endpoint_groups:
        errors.append("endpoint_groups must be a non-empty list")
        endpoint_groups = []

    seen_groups: set[str] = set()
    for idx, group in enumerate(endpoint_groups):
        if not isinstance(group, dict):
            errors.append(f"endpoint_groups[{idx}] must be an object")
            continue

        group_name = group.get("group_name")
        endpoints = group.get("endpoints")
        lifecycle_state = group.get("lifecycle_state")
        auth_method = group.get("auth_method")
        policy_hook = group.get("policy_hook")

        if not isinstance(group_name, str) or not group_name:
            errors.append(f"endpoint_groups[{idx}].group_name must be a non-empty string")
            continue
        seen_groups.add(group_name)

        if lifecycle_state not in ALLOWED_LIFECYCLE_STATES:
            errors.append(f"{group_name}: invalid lifecycle_state `{lifecycle_state}`")

        if not isinstance(endpoints, list) or not endpoints:
            errors.append(f"{group_name}: endpoints must be a non-empty list")

        if not isinstance(auth_method, str) or not auth_method:
            message = f"{group_name}: auth_method is required"
            errors.append(message)
            events.append(
                {
                    "event_code": "FASTAPI_AUTH_UNDEFINED",
                    "severity": "error",
                    "trace_correlation": trace,
                    "group": group_name,
                    "message": message,
                }
            )

        if not isinstance(policy_hook, str) or not policy_hook:
            message = f"{group_name}: policy_hook is required"
            errors.append(message)
            events.append(
                {
                    "event_code": "FASTAPI_AUTH_UNDEFINED",
                    "severity": "error",
                    "trace_correlation": trace,
                    "group": group_name,
                    "message": message,
                }
            )

    missing_groups = sorted(REQUIRED_ENDPOINT_GROUPS - seen_groups)
    for group_name in missing_groups:
        message = f"required endpoint group missing from checklist: {group_name}"
        errors.append(message)
        events.append(
            {
                "event_code": "FASTAPI_ENDPOINT_UNMAPPED",
                "severity": "error",
                "trace_correlation": trace,
                "group": group_name,
                "message": message,
            }
        )

    error_mapping = checklist.get("error_mapping")
    if not isinstance(error_mapping, list) or not error_mapping:
        errors.append("error_mapping must be a non-empty list")
        error_mapping = []

    mapped_codes: set[str] = set()
    for idx, row in enumerate(error_mapping):
        if not isinstance(row, dict):
            errors.append(f"error_mapping[{idx}] must be an object")
            continue
        code = row.get("franken_node_error_code")
        status = row.get("http_status")
        schema = row.get("response_schema")

        if not isinstance(code, str) or not code:
            errors.append(f"error_mapping[{idx}].franken_node_error_code must be non-empty string")
            continue
        mapped_codes.add(code)

        if not isinstance(status, int) or status < 100 or status > 599:
            errors.append(f"{code}: http_status must be valid HTTP status code")

        if schema != "rfc7807":
            errors.append(f"{code}: response_schema must be `rfc7807`")

    missing_codes = sorted(registry_codes - mapped_codes)
    for code in missing_codes:
        message = f"error code missing HTTP mapping: {code}"
        errors.append(message)
        events.append(
            {
                "event_code": "FASTAPI_ERROR_MAPPING_INCOMPLETE",
                "severity": "error",
                "trace_correlation": trace,
                "error_code": code,
                "message": message,
            }
        )

    checklist_items = checklist.get("checklist")
    if not isinstance(checklist_items, list) or not checklist_items:
        errors.append("checklist must be a non-empty list")
    else:
        pending = []
        for idx, item in enumerate(checklist_items):
            if not isinstance(item, dict):
                errors.append(f"checklist[{idx}] must be an object")
                continue
            status = item.get("status")
            if status not in ALLOWED_CHECKLIST_STATUS:
                errors.append(f"checklist[{idx}] has invalid status `{status}`")
                continue
            if status == "pending":
                pending.append(item.get("requirement", f"item_{idx}"))
        if pending:
            errors.append(f"pending checklist requirements: {', '.join(pending)}")

    observability = checklist.get("observability_requirements")
    if not isinstance(observability, dict):
        errors.append("observability_requirements must be an object")
    else:
        for key in ("tracing", "metrics", "logging"):
            if not isinstance(observability.get(key), dict):
                errors.append(f"observability_requirements.{key} must be an object")

    rate_limiting = checklist.get("rate_limiting")
    if not isinstance(rate_limiting, dict):
        errors.append("rate_limiting must be an object")
    else:
        module = rate_limiting.get("anti_amplification_module")
        if not isinstance(module, str) or "anti_amplification.rs" not in module:
            errors.append(
                "rate_limiting.anti_amplification_module must reference anti_amplification.rs"
            )

    success = len(errors) == 0
    report = {
        "ok": success,
        "trace_correlation": trace,
        "required_group_count": len(REQUIRED_ENDPOINT_GROUPS),
        "mapped_group_count": len(seen_groups),
        "missing_groups": missing_groups,
        "registry_error_code_count": len(registry_codes),
        "mapped_error_code_count": len(mapped_codes),
        "missing_error_codes": missing_codes,
        "errors": errors,
        "warnings": warnings,
        "events": events,
    }
    return success, report


def run_checks(
    checklist_path: Path = CHECKLIST_PATH,
    contract_path: Path = CONTRACT_PATH,
    registry_path: Path = ERROR_REGISTRY_PATH,
) -> tuple[bool, dict[str, Any]]:
    if not checklist_path.is_file():
        raise FileNotFoundError(f"missing fastapi checklist artifact: {checklist_path}")
    if not contract_path.is_file():
        raise FileNotFoundError(f"missing fastapi contract doc: {contract_path}")

    checklist = json.loads(checklist_path.read_text(encoding="utf-8"))
    contract_text = contract_path.read_text(encoding="utf-8")
    registry_codes = extract_registry_error_codes(registry_path)

    ok, report = evaluate_contract(checklist, contract_text, registry_codes)
    result = {
        "bead_id": "bd-3ndj",
        "contract": _rel(contract_path),
        "checklist": _rel(checklist_path),
        "error_registry": _rel(registry_path),
        **report,
    }
    return ok, result


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="fastapi-contract-selftest-") as tmp:
        root = Path(tmp)

        contract = root / "contract.md"
        contract.write_text("\n".join(REQUIRED_DOC_SECTIONS), encoding="utf-8")

        registry = root / "registry.rs"
        registry.write_text(
            'let _ = "FRANKEN_PROTOCOL_A";\nlet _ = "FRANKEN_SECURITY_B";\n',
            encoding="utf-8",
        )

        checklist = {
            "lifecycle_policy": {
                "states": ["experimental", "stable", "deprecated", "removed"],
                "min_deprecation_days": 30,
            },
            "endpoint_groups": [
                {
                    "group_name": "operator",
                    "endpoints": ["GET /v1/op"],
                    "lifecycle_state": "stable",
                    "auth_method": "token",
                    "policy_hook": "policy.op",
                },
                {
                    "group_name": "verifier",
                    "endpoints": ["GET /v1/ver"],
                    "lifecycle_state": "stable",
                    "auth_method": "token",
                    "policy_hook": "policy.ver",
                },
                {
                    "group_name": "fleet_control",
                    "endpoints": ["POST /v1/fleet"],
                    "lifecycle_state": "stable",
                    "auth_method": "mtls",
                    "policy_hook": "policy.fleet",
                },
            ],
            "error_mapping": [
                {
                    "franken_node_error_code": "FRANKEN_PROTOCOL_A",
                    "http_status": 400,
                    "response_schema": "rfc7807",
                },
                {
                    "franken_node_error_code": "FRANKEN_SECURITY_B",
                    "http_status": 403,
                    "response_schema": "rfc7807",
                },
            ],
            "observability_requirements": {
                "tracing": {},
                "metrics": {},
                "logging": {},
            },
            "rate_limiting": {
                "anti_amplification_module": "crates/franken-node/src/connector/anti_amplification.rs"
            },
            "event_codes": sorted(REQUIRED_EVENT_CODES),
            "checklist": [{"requirement": "complete", "status": "defined"}],
        }

        codes = extract_registry_error_codes(registry)
        ok, report = evaluate_contract(checklist, contract.read_text(encoding="utf-8"), codes)
        assert ok, f"self_test expected pass but got errors: {report['errors']}"

        # Integration behavior: new registry code should fail if not mapped.
        registry.write_text(
            'let _ = "FRANKEN_PROTOCOL_A";\nlet _ = "FRANKEN_SECURITY_B";\nlet _ = "FRANKEN_RUNTIME_C";\n',
            encoding="utf-8",
        )
        ok_missing, report_missing = evaluate_contract(
            checklist,
            contract.read_text(encoding="utf-8"),
            extract_registry_error_codes(registry),
        )
        assert not ok_missing
        assert any("missing HTTP mapping" in e for e in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_fastapi_contract")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="run internal self-test")
    args = parser.parse_args()

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            ok, payload = run_checks()
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        payload = {"ok": False, "error": str(exc)}
        ok = False

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if ok:
            print("PASS")
        else:
            print("FAIL")
            for err in payload.get("errors", [payload.get("error", "unknown error")]):
                print(f"- {err}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
