#!/usr/bin/env python3
"""Coverage/audit checker for bd-13q stable error namespace."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "artifacts" / "section_10_13" / "bd-novi" / "error_code_registry.json"
AUDIT_PATH = ROOT / "artifacts" / "section_10_10" / "bd-13q" / "error_audit.json"
IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "error_surface.rs"

REQUIRED_SURFACES = {"cli", "json_api", "protocol", "log", "sdk"}
REQUIRED_PREFIXES = {"FN-CTRL-", "FN-MIG-", "FN-AUTH-", "FN-POL-", "FN-ZON-", "FN-TOK-"}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _check_impl_prefix_registry() -> tuple[bool, str]:
    if not IMPL_PATH.is_file():
        return False, f"missing implementation file: {IMPL_PATH.relative_to(ROOT)}"
    content = IMPL_PATH.read_text()
    missing = [prefix for prefix in REQUIRED_PREFIXES if prefix not in content]
    if missing:
        return False, f"missing prefixes in implementation: {', '.join(sorted(missing))}"
    if "error.code" not in content:
        return False, "implementation missing telemetry error.code dimension"
    return True, "all prefixes and telemetry dimension found in implementation"


def coverage_report(audit_data: dict[str, Any], registry_data: dict[str, Any]) -> dict[str, Any]:
    registry_codes = {
        entry.get("code")
        for entry in registry_data.get("error_codes", [])
        if isinstance(entry, dict) and entry.get("code")
    }
    surfaces = audit_data.get("surfaces", [])

    checks: list[dict[str, Any]] = []

    seen_surfaces = {item.get("surface") for item in surfaces if isinstance(item, dict)}
    missing_surfaces = sorted(REQUIRED_SURFACES - seen_surfaces)
    checks.append(
        {
            "check": "required_surfaces_present",
            "pass": not missing_surfaces,
            "detail": "all required surfaces present"
            if not missing_surfaces
            else f"missing surfaces: {', '.join(missing_surfaces)}",
        }
    )

    unmapped_total = 0
    invalid_codes: list[str] = []
    invalid_surface_codes: list[str] = []
    mapped_total = 0

    for item in surfaces:
        if not isinstance(item, dict):
            continue
        unmapped = item.get("unmapped_errors", [])
        unmapped_total += len(unmapped) if isinstance(unmapped, list) else 0

        mapped = item.get("mapped_errors", [])
        if not isinstance(mapped, list):
            continue
        mapped_total += len(mapped)
        for entry in mapped:
            if not isinstance(entry, dict):
                continue
            canonical_code = entry.get("canonical_code")
            surface_code = str(entry.get("surface_code", ""))
            if canonical_code not in registry_codes:
                invalid_codes.append(str(canonical_code))
            if not any(surface_code.startswith(prefix) for prefix in REQUIRED_PREFIXES):
                invalid_surface_codes.append(surface_code)

    checks.append(
        {
            "check": "zero_unmapped_errors",
            "pass": unmapped_total == 0,
            "detail": "no unmapped surfaced errors" if unmapped_total == 0 else f"{unmapped_total} unmapped errors",
        }
    )
    checks.append(
        {
            "check": "canonical_code_registry_coverage",
            "pass": not invalid_codes,
            "detail": "all canonical codes are registry-backed"
            if not invalid_codes
            else f"invalid canonical codes: {sorted(set(invalid_codes))}",
        }
    )
    checks.append(
        {
            "check": "surface_code_prefix_coverage",
            "pass": not invalid_surface_codes,
            "detail": "all surface codes use FN-* prefixes"
            if not invalid_surface_codes
            else f"invalid surface codes: {sorted(set(invalid_surface_codes))}",
        }
    )

    impl_ok, impl_detail = _check_impl_prefix_registry()
    checks.append({"check": "implementation_prefix_registry", "pass": impl_ok, "detail": impl_detail})

    passed = sum(1 for item in checks if item["pass"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"
    return {
        "bead_id": "bd-13q",
        "check": "error_coverage_audit",
        "verdict": verdict,
        "summary": {
            "total_checks": total,
            "passed": passed,
            "failed": total - passed,
            "mapped_error_count": mapped_total,
            "unmapped_error_count": unmapped_total,
        },
        "checks": checks,
    }


def self_test() -> bool:
    mock_registry = {
        "error_codes": [
            {"code": "FRANKEN_PROTOCOL_AUTH_FAILED"},
            {"code": "FRANKEN_CONNECTOR_LEASE_EXPIRED"},
        ]
    }
    mock_audit_pass = {
        "surfaces": [
            {
                "surface": "cli",
                "mapped_errors": [
                    {
                        "canonical_code": "FRANKEN_PROTOCOL_AUTH_FAILED",
                        "surface_code": "FN-CTRL-FRANKEN_PROTOCOL_AUTH_FAILED",
                    }
                ],
                "unmapped_errors": [],
            },
            {
                "surface": "json_api",
                "mapped_errors": [
                    {
                        "canonical_code": "FRANKEN_CONNECTOR_LEASE_EXPIRED",
                        "surface_code": "FN-AUTH-FRANKEN_CONNECTOR_LEASE_EXPIRED",
                    }
                ],
                "unmapped_errors": [],
            },
            {"surface": "protocol", "mapped_errors": [], "unmapped_errors": []},
            {"surface": "log", "mapped_errors": [], "unmapped_errors": []},
            {"surface": "sdk", "mapped_errors": [], "unmapped_errors": []},
        ]
    }
    mock_audit_fail = {
        "surfaces": [
            {
                "surface": "cli",
                "mapped_errors": [
                    {"canonical_code": "UNKNOWN_CODE", "surface_code": "BAD-CODE"}
                ],
                "unmapped_errors": ["oops"],
            }
        ]
    }
    pass_report = coverage_report(mock_audit_pass, mock_registry)
    fail_report = coverage_report(mock_audit_fail, mock_registry)
    return pass_report["verdict"] == "PASS" and fail_report["verdict"] == "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
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
        audit_data = _load_json(args.audit)
        registry_data = _load_json(args.registry)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        report = {
            "bead_id": "bd-13q",
            "check": "error_coverage_audit",
            "verdict": "FAIL",
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"FAIL: {exc}")
        return 1

    report = coverage_report(audit_data, registry_data)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"verdict: {report['verdict']}")
        for check in report["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
