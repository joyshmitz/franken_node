#!/usr/bin/env python3
"""Compatibility checker for bd-13q stable error namespace policy."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
DEFAULT_REGISTRY = ROOT / "artifacts" / "section_10_13" / "bd-novi" / "error_code_registry.json"

CATEGORY_BY_SEVERITY = {
    "transient": "TRANSIENT",
    "fatal": "PERMANENT",
    "degraded": "CONFIGURATION",
}


def _load_registry(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    codes = data.get("error_codes", [])
    if not isinstance(codes, list):
        raise ValueError("error_codes must be a list")
    return codes


def _category(entry: dict[str, Any]) -> str:
    severity = str(entry.get("severity", "")).lower()
    return CATEGORY_BY_SEVERITY.get(severity, "UNKNOWN")


def _code_map(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(entry.get("code", "")): entry for entry in entries if entry.get("code")}


def compatibility_report(
    old_entries: list[dict[str, Any]],
    new_entries: list[dict[str, Any]],
    min_hint_len: int = 20,
) -> dict[str, Any]:
    old_map = _code_map(old_entries)
    new_map = _code_map(new_entries)

    old_codes = set(old_map.keys())
    new_codes = set(new_map.keys())

    added = sorted(new_codes - old_codes)
    removed = sorted(old_codes - new_codes)
    unchanged = sorted(old_codes & new_codes)

    category_changes: list[dict[str, str]] = []
    retryable_changes: list[dict[str, Any]] = []
    metadata_violations: list[dict[str, str]] = []

    for code in unchanged:
        old_entry = old_map[code]
        new_entry = new_map[code]
        old_category = _category(old_entry)
        new_category = _category(new_entry)
        if old_category != new_category:
            category_changes.append(
                {"code": code, "old_category": old_category, "new_category": new_category}
            )

        old_retryable = bool(old_entry.get("retryable", False))
        new_retryable = bool(new_entry.get("retryable", False))
        if old_retryable != new_retryable:
            retryable_changes.append(
                {
                    "code": code,
                    "old_retryable": old_retryable,
                    "new_retryable": new_retryable,
                }
            )

    for code in added:
        entry = new_map[code]
        if not str(entry.get("description", "")).strip():
            metadata_violations.append(
                {"code": code, "reason": "new code missing description"}
            )
        if not str(entry.get("severity", "")).strip():
            metadata_violations.append(
                {"code": code, "reason": "new code missing severity tag"}
            )
        severity = str(entry.get("severity", "")).lower()
        if severity != "fatal":
            hint = str(entry.get("recovery_hint", ""))
            if len(hint.strip()) < min_hint_len:
                metadata_violations.append(
                    {
                        "code": code,
                        "reason": f"recovery_hint shorter than {min_hint_len} chars",
                    }
                )

    violations = {
        "removed": removed,
        "category_changes": category_changes,
        "retryable_changes": retryable_changes,
        "metadata_violations": metadata_violations,
    }
    is_compatible = not (
        removed or category_changes or retryable_changes or metadata_violations
    )

    return {
        "bead_id": "bd-13q",
        "check": "error_compatibility_policy",
        "verdict": "PASS" if is_compatible else "FAIL",
        "added": added,
        "unchanged": unchanged,
        "violations": violations,
        "summary": {
            "added": len(added),
            "unchanged": len(unchanged),
            "removed": len(removed),
            "category_changes": len(category_changes),
            "retryable_changes": len(retryable_changes),
            "metadata_violations": len(metadata_violations),
        },
    }


def self_test() -> bool:
    old_entries = [
        {
            "code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "severity": "transient",
            "retryable": True,
            "recovery_hint": "Re-authenticate with fresh credentials and retry request",
            "description": "auth failed",
        },
        {
            "code": "FRANKEN_CONNECTOR_LEASE_EXPIRED",
            "severity": "transient",
            "retryable": True,
            "recovery_hint": "Re-negotiate lease with coordinator before issuing writes",
            "description": "lease expired",
        },
    ]

    compatible_new = old_entries + [
        {
            "code": "FRANKEN_EGRESS_TIMEOUT",
            "severity": "transient",
            "retryable": True,
            "recovery_hint": "Retry egress call with exponential backoff and jitter",
            "description": "egress timeout",
        }
    ]
    fail_new = [
        {
            "code": "FRANKEN_PROTOCOL_AUTH_FAILED",
            "severity": "fatal",
            "retryable": False,
            "recovery_hint": "",
            "description": "auth failed",
        }
    ]

    pass_report = compatibility_report(old_entries, compatible_new)
    fail_report = compatibility_report(old_entries, fail_new)

    return pass_report["verdict"] == "PASS" and fail_report["verdict"] == "FAIL"


def main() -> int:
    logger = configure_test_logging("check_error_compat")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--new-registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        report = {"bead_id": "bd-13q", "check": "self_test", "verdict": "PASS" if ok else "FAIL"}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"self_test verdict: {report['verdict']}")
        return 0 if ok else 1

    try:
        old_entries = _load_registry(args.old_registry)
        new_entries = _load_registry(args.new_registry)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {
            "bead_id": "bd-13q",
            "check": "error_compatibility_policy",
            "verdict": "FAIL",
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"FAIL: {exc}")
        return 1

    report = compatibility_report(old_entries, new_entries)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"verdict: {report['verdict']}")
        print(f"added: {report['summary']['added']}")
        print(f"removed: {report['summary']['removed']}")
        print(f"category_changes: {report['summary']['category_changes']}")
        print(f"retryable_changes: {report['summary']['retryable_changes']}")
        print(f"metadata_violations: {report['summary']['metadata_violations']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
