#!/usr/bin/env python3
"""Validate adjacent-substrate waiver workflow artifacts for bd-159q."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
BEAD_ID = "bd-159q"
SECTION = "10.16"

WAIVER_REGISTRY = ROOT / "artifacts" / "10.16" / "waiver_registry.json"
SUBSTRATE_MANIFEST = ROOT / "artifacts" / "10.16" / "substrate_dependency_matrix.json"
POLICY_DOC = ROOT / "docs" / "policy" / "adjacent_substrate_waiver_process.md"

STATUS_VALUES = {"active", "expired", "revoked"}
MAX_DURATION_DAYS_DEFAULT = 90

REQUIRED_WAIVER_FIELDS = [
    "waiver_id",
    "module",
    "substrate",
    "rules_waived",
    "risk_analysis",
    "scope_description",
    "owner",
    "approved_by",
    "granted_at",
    "expires_at",
    "remediation_plan",
    "status",
]


def _now_utc() -> datetime:
    override = os.getenv("WAIVER_CHECK_NOW")
    if override:
        return _parse_rfc3339(override)
    return datetime.now(timezone.utc)


def _parse_rfc3339(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "pass": passed, "detail": detail}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_manifest_index(manifest: dict[str, Any]) -> dict[str, set[str]]:
    modules = manifest.get("modules", [])
    if not isinstance(modules, list):
        raise ValueError("manifest.modules must be a list")

    module_paths: set[str] = set()
    rule_ids: set[str] = {"adjacent-substrate.module-listed"}
    substrate_names: set[str] = set()

    for module_entry in modules:
        if not isinstance(module_entry, dict):
            continue
        module_path = module_entry.get("path")
        if isinstance(module_path, str) and module_path:
            module_paths.add(_norm(module_path))

        substrates = module_entry.get("substrates", [])
        if not isinstance(substrates, list):
            continue

        for substrate_entry in substrates:
            if not isinstance(substrate_entry, dict):
                continue
            substrate_name = substrate_entry.get("name")
            integration_type = substrate_entry.get("integration_type")
            if isinstance(substrate_name, str) and substrate_name:
                substrate_names.add(substrate_name)
            if (
                isinstance(substrate_name, str)
                and substrate_name
                and isinstance(integration_type, str)
                and integration_type
            ):
                rule_ids.add(f"adjacent-substrate.{integration_type}.{substrate_name}")

    return {
        "module_paths": module_paths,
        "rule_ids": rule_ids,
        "substrate_names": substrate_names,
    }


def evaluate_registry(
    registry: dict[str, Any], manifest: dict[str, Any], now: datetime
) -> tuple[bool, dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    errors: list[str] = []

    trace_input = json.dumps(
        {"registry": registry, "manifest": manifest}, sort_keys=True, separators=(",", ":")
    )
    trace_id = hashlib.sha256(trace_input.encode("utf-8")).hexdigest()[:16]

    schema_version = registry.get("schema_version")
    checks.append(
        _check(
            "registry schema_version present",
            isinstance(schema_version, str) and bool(schema_version.strip()),
            f"schema_version={schema_version!r}",
        )
    )

    max_duration_days = registry.get("max_waiver_duration_days", MAX_DURATION_DAYS_DEFAULT)
    checks.append(
        _check(
            "max waiver duration <= 90 days",
            isinstance(max_duration_days, int) and 1 <= max_duration_days <= MAX_DURATION_DAYS_DEFAULT,
            f"max_waiver_duration_days={max_duration_days!r}",
        )
    )

    waivers = registry.get("waivers")
    checks.append(
        _check(
            "waivers is a list",
            isinstance(waivers, list),
            f"type={type(waivers).__name__}",
        )
    )

    try:
        manifest_index = build_manifest_index(manifest)
    except Exception as exc:  # pragma: no cover - defensive path
        errors.append(f"manifest parse error: {exc}")
        manifest_index = {"module_paths": set(), "rule_ids": set(), "substrate_names": set()}

    checks.append(
        _check(
            "substrate manifest has modules",
            bool(manifest_index["module_paths"]),
            f"module_count={len(manifest_index['module_paths'])}",
        )
    )
    checks.append(
        _check(
            "substrate manifest has rule ids",
            bool(manifest_index["rule_ids"]),
            f"rule_count={len(manifest_index['rule_ids'])}",
        )
    )

    if not isinstance(waivers, list):
        errors.append("registry.waivers must be a list")
        waivers = []

    for waiver in waivers:
        waiver_id = waiver.get("waiver_id") if isinstance(waiver, dict) else "<invalid-waiver-object>"
        if not isinstance(waiver, dict):
            errors.append("waiver entry must be an object")
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": "waiver entry must be an object",
                }
            )
            continue

        missing_fields = [
            field
            for field in REQUIRED_WAIVER_FIELDS
            if field not in waiver or waiver.get(field) in (None, "")
        ]
        if missing_fields:
            msg = f"{waiver_id}: missing fields {missing_fields}"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )
            continue

        status = waiver["status"]
        if status not in STATUS_VALUES:
            msg = f"{waiver_id}: invalid status `{status}`"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )
            continue

        try:
            granted_at = _parse_rfc3339(str(waiver["granted_at"]))
            expires_at = _parse_rfc3339(str(waiver["expires_at"]))
        except ValueError as exc:
            msg = f"{waiver_id}: invalid timestamp ({exc})"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )
            continue

        if expires_at <= granted_at:
            msg = f"{waiver_id}: expires_at must be after granted_at"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )

        duration_days = (expires_at - granted_at).total_seconds() / 86400.0
        if duration_days > float(max_duration_days):
            msg = (
                f"{waiver_id}: duration {duration_days:.2f}d exceeds max "
                f"{max_duration_days}d"
            )
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )

        module = _norm(str(waiver["module"]))
        if module not in manifest_index["module_paths"]:
            msg = f"{waiver_id}: unknown module `{module}`"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_CROSS_REF_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )

        substrate = str(waiver["substrate"])
        if substrate not in manifest_index["substrate_names"]:
            msg = f"{waiver_id}: unknown substrate `{substrate}`"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_CROSS_REF_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )

        rules_waived = waiver["rules_waived"]
        if not isinstance(rules_waived, list) or not rules_waived:
            msg = f"{waiver_id}: rules_waived must be a non-empty list"
            errors.append(msg)
            events.append(
                {
                    "event_code": "WAIVER_VALIDATION_FAIL",
                    "severity": "error",
                    "waiver_id": str(waiver_id),
                    "trace_id": trace_id,
                    "detail": msg,
                }
            )
        else:
            for rule_id in rules_waived:
                if not isinstance(rule_id, str) or not rule_id:
                    msg = f"{waiver_id}: invalid rule id value `{rule_id}`"
                    errors.append(msg)
                    events.append(
                        {
                            "event_code": "WAIVER_VALIDATION_FAIL",
                            "severity": "error",
                            "waiver_id": str(waiver_id),
                            "trace_id": trace_id,
                            "detail": msg,
                        }
                    )
                    continue
                if rule_id not in manifest_index["rule_ids"]:
                    msg = f"{waiver_id}: unknown rule id `{rule_id}`"
                    errors.append(msg)
                    events.append(
                        {
                            "event_code": "WAIVER_CROSS_REF_FAIL",
                            "severity": "error",
                            "waiver_id": str(waiver_id),
                            "trace_id": trace_id,
                            "detail": msg,
                        }
                    )

        if status == "active":
            events.append(
                {
                    "event_code": "WAIVER_GRANTED",
                    "severity": "info",
                    "waiver_id": str(waiver_id),
                    "module": module,
                    "trace_id": trace_id,
                }
            )
            if expires_at <= now:
                msg = f"{waiver_id}: active waiver is expired at {expires_at.isoformat()}"
                errors.append(msg)
                events.append(
                    {
                        "event_code": "WAIVER_EXPIRED",
                        "severity": "warning",
                        "waiver_id": str(waiver_id),
                        "module": module,
                        "trace_id": trace_id,
                        "detail": msg,
                    }
                )
        elif status == "expired":
            events.append(
                {
                    "event_code": "WAIVER_EXPIRED",
                    "severity": "warning",
                    "waiver_id": str(waiver_id),
                    "module": module,
                    "trace_id": trace_id,
                }
            )
            if expires_at > now:
                msg = f"{waiver_id}: status is expired but expires_at is in the future"
                errors.append(msg)
                events.append(
                    {
                        "event_code": "WAIVER_VALIDATION_FAIL",
                        "severity": "error",
                        "waiver_id": str(waiver_id),
                        "module": module,
                        "trace_id": trace_id,
                        "detail": msg,
                    }
                )
        elif status == "revoked":
            events.append(
                {
                    "event_code": "WAIVER_REVOKED",
                    "severity": "info",
                    "waiver_id": str(waiver_id),
                    "module": module,
                    "trace_id": trace_id,
                }
            )

    checks.append(
        _check(
            "no active waiver is expired",
            all(
                not (
                    isinstance(w, dict)
                    and w.get("status") == "active"
                    and _parse_rfc3339(str(w["expires_at"])) <= now
                )
                for w in waivers
                if isinstance(w, dict) and "expires_at" in w
            ),
            f"now={now.isoformat()}",
        )
    )

    checks.append(
        _check(
            "all waived modules exist in substrate manifest",
            not any("unknown module" in error for error in errors),
            "cross-reference complete" if not any("unknown module" in error for error in errors) else "missing module references",
        )
    )

    checks.append(
        _check(
            "all waived rules exist in substrate manifest",
            not any("unknown rule id" in error for error in errors),
            "cross-reference complete" if not any("unknown rule id" in error for error in errors) else "missing rule references",
        )
    )

    checks.append(
        _check(
            "all active waivers include required risk/scope/owner/remediation fields",
            not any("missing fields" in error for error in errors),
            "required fields present" if not any("missing fields" in error for error in errors) else "missing required fields found",
        )
    )

    checks_pass = all(check["pass"] for check in checks)
    success = checks_pass and len(errors) == 0

    report = {
        "bead_id": BEAD_ID,
        "title": "Adjacent substrate waiver workflow",
        "section": SECTION,
        "timestamp": now.isoformat(),
        "trace_id": trace_id,
        "overall_pass": success,
        "verdict": "PASS" if success else "FAIL",
        "summary": {
            "waiver_count": len(waivers),
            "passing_checks": sum(1 for check in checks if check["pass"]),
            "failing_checks": sum(1 for check in checks if not check["pass"]),
            "errors": len(errors),
            "events": len(events),
        },
        "checks": checks,
        "errors": errors,
        "events": events,
        "manifest_stats": {
            "module_count": len(manifest_index["module_paths"]),
            "rule_count": len(manifest_index["rule_ids"]),
            "substrate_count": len(manifest_index["substrate_names"]),
        },
    }
    return success, report


def run_checks(now: datetime | None = None) -> tuple[bool, dict[str, Any]]:
    effective_now = now or _now_utc()

    checks: list[dict[str, Any]] = []
    missing = False
    for path, label in [
        (WAIVER_REGISTRY, "waiver registry"),
        (SUBSTRATE_MANIFEST, "substrate manifest"),
        (POLICY_DOC, "waiver policy doc"),
    ]:
        exists = path.exists()
        checks.append(
            _check(
                f"file exists: {label}",
                exists,
                str(path.relative_to(ROOT)),
            )
        )
        if not exists:
            missing = True

    if missing:
        report = {
            "bead_id": BEAD_ID,
            "title": "Adjacent substrate waiver workflow",
            "section": SECTION,
            "timestamp": effective_now.isoformat(),
            "overall_pass": False,
            "verdict": "FAIL",
            "summary": {
                "waiver_count": 0,
                "passing_checks": sum(1 for check in checks if check["pass"]),
                "failing_checks": sum(1 for check in checks if not check["pass"]),
                "errors": sum(1 for check in checks if not check["pass"]),
                "events": 0,
            },
            "checks": checks,
            "errors": [check["detail"] for check in checks if not check["pass"]],
            "events": [],
            "manifest_stats": {"module_count": 0, "rule_count": 0, "substrate_count": 0},
        }
        return False, report

    registry = load_json(WAIVER_REGISTRY)
    manifest = load_json(SUBSTRATE_MANIFEST)
    ok, report = evaluate_registry(registry, manifest, effective_now)

    report["checks"] = checks + report["checks"]
    report["summary"]["passing_checks"] = sum(1 for check in report["checks"] if check["pass"])
    report["summary"]["failing_checks"] = sum(1 for check in report["checks"] if not check["pass"])
    report["overall_pass"] = ok and report["summary"]["failing_checks"] == 0
    report["verdict"] = "PASS" if report["overall_pass"] else "FAIL"
    return report["overall_pass"], report


def self_test() -> tuple[bool, list[str]]:
    messages: list[str] = []
    now = _parse_rfc3339("2026-02-20T00:00:00Z")

    manifest = {
        "modules": [
            {
                "path": "crates/franken-node/src/connector",
                "substrates": [
                    {"name": "frankensqlite", "integration_type": "mandatory"},
                    {"name": "fastapi_rust", "integration_type": "should_use"},
                ],
            }
        ]
    }

    valid_registry = {
        "schema_version": "1.0.0",
        "max_waiver_duration_days": 90,
        "waivers": [
            {
                "waiver_id": "waiver-valid",
                "module": "crates/franken-node/src/connector",
                "substrate": "frankensqlite",
                "rules_waived": ["adjacent-substrate.mandatory.frankensqlite"],
                "risk_analysis": "bounded risk",
                "scope_description": "single module for migration window",
                "owner": "owner-a",
                "approved_by": "approver-a",
                "granted_at": "2026-02-01T00:00:00Z",
                "expires_at": "2026-03-01T00:00:00Z",
                "remediation_plan": "complete adapter migration",
                "status": "active",
            }
        ],
    }
    ok_valid, _ = evaluate_registry(valid_registry, manifest, now)
    messages.append(f"valid registry -> {'PASS' if ok_valid else 'FAIL'}")

    expired_active = json.loads(json.dumps(valid_registry))
    expired_active["waivers"][0]["expires_at"] = "2026-02-10T00:00:00Z"
    ok_expired, _ = evaluate_registry(expired_active, manifest, now)
    messages.append(f"active expired waiver rejected -> {'PASS' if not ok_expired else 'FAIL'}")

    missing_field = json.loads(json.dumps(valid_registry))
    del missing_field["waivers"][0]["risk_analysis"]
    ok_missing, _ = evaluate_registry(missing_field, manifest, now)
    messages.append(f"missing field rejected -> {'PASS' if not ok_missing else 'FAIL'}")

    unknown_refs = json.loads(json.dumps(valid_registry))
    unknown_refs["waivers"][0]["module"] = "crates/franken-node/src/nope"
    unknown_refs["waivers"][0]["rules_waived"] = ["adjacent-substrate.mandatory.nope"]
    ok_unknown, _ = evaluate_registry(unknown_refs, manifest, now)
    messages.append(f"unknown module/rule rejected -> {'PASS' if not ok_unknown else 'FAIL'}")

    empty_registry = {
        "schema_version": "1.0.0",
        "max_waiver_duration_days": 90,
        "waivers": [],
    }
    ok_empty, _ = evaluate_registry(empty_registry, manifest, now)
    messages.append(f"empty registry accepted -> {'PASS' if ok_empty else 'FAIL'}")

    success = all(message.endswith("PASS") for message in messages)
    return success, messages


def main() -> int:
    logger = configure_test_logging("check_waiver_workflow")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run internal self tests")
    args = parser.parse_args()

    if args.self_test:
        ok, messages = self_test()
        payload = {
            "bead_id": BEAD_ID,
            "self_test_pass": ok,
            "checks": messages,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for message in messages:
                print(message)
        return 0 if ok else 1

    ok, report = run_checks()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        if report["errors"]:
            print("\nErrors:")
            for error in report["errors"]:
                print(f"- {error}")
        print(
            f"\n{report['summary']['passing_checks']}/{len(report['checks'])} checks pass\n"
            f"Verdict: {report['verdict']}"
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
