#!/usr/bin/env python3
"""Build and validate the bd-3u2o adjacent substrate conformance gate report."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-3u2o"
SECTION = "10.16"
TITLE = "Adjacent substrate conformance gate"

MANIFEST_PATH = ROOT / "artifacts" / "10.16" / "adjacent_substrate_policy_manifest.json"
WAIVER_REGISTRY_PATH = ROOT / "artifacts" / "10.16" / "waiver_registry.json"
REPORT_PATH = ROOT / "artifacts" / "10.16" / "adjacent_substrate_gate_report.json"

EVENT_START = "SUBSTRATE_GATE_START"
EVENT_VIOLATION = "SUBSTRATE_GATE_VIOLATION"
EVENT_WAIVED = "SUBSTRATE_GATE_WAIVED"
EVENT_WAIVER_EXPIRED = "SUBSTRATE_GATE_WAIVER_EXPIRED"
EVENT_PASS = "SUBSTRATE_GATE_PASS"
EVENT_FAIL = "SUBSTRATE_GATE_FAIL"
EXPECTED_EVENTS = [
    EVENT_START,
    EVENT_VIOLATION,
    EVENT_WAIVED,
    EVENT_WAIVER_EXPIRED,
    EVENT_PASS,
    EVENT_FAIL,
]

TIER_KEYS = ("mandatory_modules", "should_use_modules", "optional_modules")
STATUSES = {"pass", "fail", "waived"}
MODULE_ROOT_FALLBACK = "crates/franken-node/src"


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "pass": bool(passed), "detail": detail}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    if path.parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _git_changed_files() -> list[str]:
    base_ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    diff_cmd = ["git", "diff", "--name-only"]
    if base_ref:
        candidate = f"origin/{base_ref}"
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", candidate],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            diff_cmd = ["git", "diff", "--name-only", f"{candidate}...HEAD"]

    proc = subprocess.run(
        diff_cmd,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    return sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})


def _normalize_changed_modules(changed_modules: list[str], module_root: str) -> list[str]:
    root = module_root.rstrip("/") + "/"
    out = []
    for path in changed_modules:
        normalized = path.replace("\\", "/")
        if normalized.startswith(root) and normalized.endswith(".rs"):
            out.append(normalized)
    return sorted(set(out))


def _detect_changed_modules(module_root: str) -> list[str]:
    return _normalize_changed_modules(_git_changed_files(), module_root)


def _classify_module(module_path: str, substrate: dict[str, Any]) -> str | None:
    for tier_key in TIER_KEYS:
        patterns = substrate.get(tier_key, [])
        if not isinstance(patterns, list):
            continue
        for pattern in patterns:
            if isinstance(pattern, str) and fnmatch.fnmatchcase(module_path, pattern):
                return tier_key
    return None


def _parse_waiver_registry() -> list[dict[str, Any]]:
    payload = _load_json(WAIVER_REGISTRY_PATH)
    if payload is None:
        return []
    waivers = payload.get("waivers")
    if not isinstance(waivers, list):
        return []
    return [entry for entry in waivers if isinstance(entry, dict)]


def _waiver_for_rule(
    waivers: list[dict[str, Any]],
    module_path: str,
    substrate: str,
    rule_id: str,
    now_utc: dt.datetime,
) -> tuple[str | None, bool]:
    """
    Returns:
      waiver_id if valid waiver exists
      expired flag for matching but expired waivers
    """
    for waiver in waivers:
        module_pattern = waiver.get("module")
        waiver_substrate = waiver.get("substrate")
        status = str(waiver.get("status", "")).lower()
        rules = waiver.get("rules_waived", [])
        expires_at = waiver.get("expires_at")
        waiver_id = str(waiver.get("waiver_id", ""))

        if not isinstance(module_pattern, str) or not module_pattern:
            continue
        if not fnmatch.fnmatchcase(module_path, module_pattern):
            continue
        if waiver_substrate != substrate:
            continue
        if not isinstance(rules, list) or rule_id not in rules:
            continue
        if status not in {"active", "approved"}:
            continue

        if isinstance(expires_at, str) and expires_at:
            try:
                expiry = dt.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=dt.timezone.utc)
                expiry = expiry.astimezone(dt.timezone.utc)
                if expiry <= now_utc:
                    return None, True
            except ValueError:
                return None, True
        return waiver_id or None, False
    return None, False


def _rule_result(
    module: str,
    substrate: str,
    rule_id: str,
    passed: bool,
    remediation_hint: str,
    waivers: list[dict[str, Any]],
    events: list[dict[str, Any]],
    now_utc: dt.datetime,
) -> dict[str, Any]:
    status = "pass"
    waiver_id = ""

    if not passed:
        waiver_id, expired = _waiver_for_rule(waivers, module, substrate, rule_id, now_utc)
        if waiver_id:
            status = "waived"
            events.append(
                {
                    "code": EVENT_WAIVED,
                    "module": module,
                    "substrate": substrate,
                    "rule": rule_id,
                    "detail": f"covered by waiver {waiver_id}",
                }
            )
        else:
            status = "fail"
            code = EVENT_WAIVER_EXPIRED if expired else EVENT_VIOLATION
            events.append(
                {
                    "code": code,
                    "module": module,
                    "substrate": substrate,
                    "rule": rule_id,
                    "detail": remediation_hint,
                }
            )

    return {
        "module": module,
        "substrate": substrate,
        "rule": rule_id,
        "status": status,
        "remediation_hint": remediation_hint,
        "waiver_id": waiver_id,
    }


def _evaluate_mandatory_rules(
    module_path: str,
    substrate: str,
    source_text: str,
    waivers: list[dict[str, Any]],
    events: list[dict[str, Any]],
    now_utc: dt.datetime,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    if substrate == "frankentui":
        has_raw_print = re.search(r"\b(?:e?println!)\s*!", source_text) is not None
        checks.append(
            _rule_result(
                module_path,
                substrate,
                "adjacent-substrate.mandatory.frankentui.raw-output",
                not has_raw_print,
                "Replace raw println!/eprintln! usage with frankentui rendering primitives.",
                waivers,
                events,
                now_utc,
            )
        )
        has_ansi_literal = "\\x1b[" in source_text or "\\u001b[" in source_text
        checks.append(
            _rule_result(
                module_path,
                substrate,
                "adjacent-substrate.mandatory.frankentui.ansi-literal",
                not has_ansi_literal,
                "Remove raw ANSI escape literals and route presentation through frankentui theming.",
                waivers,
                events,
                now_utc,
            )
        )

    elif substrate == "frankensqlite":
        has_direct_fs = re.search(
            r"std::fs::|File::|OpenOptions|create_dir|remove_file|remove_dir",
            source_text,
        )
        checks.append(
            _rule_result(
                module_path,
                substrate,
                "adjacent-substrate.mandatory.frankensqlite.direct-fs-state",
                has_direct_fs is None,
                "Persist state through the frankensqlite adapter; avoid direct std::fs state I/O in mandatory modules.",
                waivers,
                events,
                now_utc,
            )
        )

    elif substrate == "sqlmodel_rust":
        has_raw_sql = re.search(
            r"\"(?:[^\"\\]|\\.)*\b(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE|DROP\s+TABLE)\b",
            source_text,
            flags=re.IGNORECASE,
        )
        checks.append(
            _rule_result(
                module_path,
                substrate,
                "adjacent-substrate.mandatory.sqlmodel.raw-sql",
                has_raw_sql is None,
                "Use sqlmodel_rust typed models/query builders instead of raw SQL string literals.",
                waivers,
                events,
                now_utc,
            )
        )

    elif substrate == "fastapi_rust":
        has_pipeline_marker = (
            "middleware" in source_text
            or "TraceContext" in source_text
            or "session_auth" in source_text
        )
        checks.append(
            _rule_result(
                module_path,
                substrate,
                "adjacent-substrate.mandatory.fastapi.middleware-pipeline",
                has_pipeline_marker,
                "Route endpoint handling through the fastapi_rust middleware pipeline and preserve trace context.",
                waivers,
                events,
                now_utc,
            )
        )

    return checks


def build_gate_report(changed_modules: list[str] | None = None) -> dict[str, Any]:
    manifest = _load_json(MANIFEST_PATH)
    if manifest is None:
        return {
            "schema_version": "1.0.0",
            "bead_id": BEAD_ID,
            "gate_verdict": "fail",
            "error": f"missing or invalid manifest: {MANIFEST_PATH}",
            "checks": [],
            "summary": {"total_checks": 0, "passed": 0, "failed": 1, "waived": 0},
            "events": [{"code": EVENT_FAIL, "detail": "manifest load failed"}],
        }

    module_root = str(manifest.get("module_root") or MODULE_ROOT_FALLBACK)
    modules = (
        sorted(set(changed_modules))
        if changed_modules is not None
        else _detect_changed_modules(module_root)
    )
    modules = _normalize_changed_modules(modules, module_root)

    waivers = _parse_waiver_registry()
    events: list[dict[str, Any]] = [
        {
            "code": EVENT_START,
            "detail": f"evaluating {len(modules)} changed modules",
        }
    ]

    checks: list[dict[str, Any]] = []
    now_utc = _now_utc()
    substrates = [item for item in manifest.get("substrates", []) if isinstance(item, dict)]

    for module_path in modules:
        source_path = ROOT / module_path
        if not source_path.is_file():
            checks.append(
                {
                    "module": module_path,
                    "substrate": "n/a",
                    "rule": "adjacent-substrate.module.exists",
                    "status": "fail",
                    "remediation_hint": "Ensure changed module path resolves to an existing source file.",
                    "waiver_id": "",
                }
            )
            events.append(
                {
                    "code": EVENT_VIOLATION,
                    "module": module_path,
                    "substrate": "n/a",
                    "rule": "adjacent-substrate.module.exists",
                    "detail": "changed module path missing on disk",
                }
            )
            continue

        source_text = source_path.read_text(encoding="utf-8")
        for substrate_entry in substrates:
            substrate_name = str(substrate_entry.get("name", ""))
            tier = _classify_module(module_path, substrate_entry)
            if tier != "mandatory_modules":
                continue
            checks.extend(
                _evaluate_mandatory_rules(
                    module_path,
                    substrate_name,
                    source_text,
                    waivers,
                    events,
                    now_utc,
                )
            )

    checks.sort(key=lambda item: (item["module"], item["substrate"], item["rule"]))
    passed = sum(1 for item in checks if item["status"] == "pass")
    failed = sum(1 for item in checks if item["status"] == "fail")
    waived = sum(1 for item in checks if item["status"] == "waived")
    verdict = "pass" if failed == 0 else "fail"

    events.append(
        {
            "code": EVENT_PASS if verdict == "pass" else EVENT_FAIL,
            "detail": f"gate_verdict={verdict}",
        }
    )

    generated_at = (
        str(manifest.get("metadata", {}).get("created_at"))
        if isinstance(manifest.get("metadata"), dict)
        else "1970-01-01T00:00:00Z"
    )
    if not generated_at:
        generated_at = "1970-01-01T00:00:00Z"

    return {
        "schema_version": "1.0.0",
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "generated_at": generated_at,
        "policy_manifest": str(MANIFEST_PATH.relative_to(ROOT)),
        "waiver_registry": str(WAIVER_REGISTRY_PATH.relative_to(ROOT)),
        "changed_modules": modules,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
            "waived": waived,
        },
        "gate_verdict": verdict,
        "events": events,
    }


def validate_gate_report(report: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    required_top = [
        "schema_version",
        "bead_id",
        "checks",
        "summary",
        "gate_verdict",
        "events",
        "changed_modules",
    ]
    missing_top = [key for key in required_top if key not in report]
    checks.append(
        _check(
            "report_required_fields",
            len(missing_top) == 0,
            "missing: " + ", ".join(missing_top) if missing_top else "ok",
        )
    )

    report_checks = report.get("checks")
    checks.append(
        _check(
            "checks_array",
            isinstance(report_checks, list),
            f"type={type(report_checks).__name__}",
        )
    )

    detail_errors: list[str] = []
    fail_without_hint = 0
    waived_without_id = 0
    if isinstance(report_checks, list):
        for idx, entry in enumerate(report_checks):
            if not isinstance(entry, dict):
                detail_errors.append(f"checks[{idx}] is not object")
                continue
            for field in ("module", "substrate", "rule", "status", "remediation_hint", "waiver_id"):
                if field not in entry:
                    detail_errors.append(f"checks[{idx}] missing {field}")
            status = entry.get("status")
            if status not in STATUSES:
                detail_errors.append(f"checks[{idx}] invalid status {status}")
            if status == "fail" and not str(entry.get("remediation_hint", "")).strip():
                fail_without_hint += 1
            if status == "waived" and not str(entry.get("waiver_id", "")).strip():
                waived_without_id += 1

    checks.append(
        _check(
            "check_entry_schema",
            len(detail_errors) == 0,
            "errors=" + str(detail_errors) if detail_errors else "ok",
        )
    )
    checks.append(
        _check(
            "failure_remediation_hints_present",
            fail_without_hint == 0,
            f"failures_without_hint={fail_without_hint}",
        )
    )
    checks.append(
        _check(
            "waived_checks_have_waiver_id",
            waived_without_id == 0,
            f"waived_without_id={waived_without_id}",
        )
    )

    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    passed = sum(1 for entry in report_checks or [] if isinstance(entry, dict) and entry.get("status") == "pass")
    failed = sum(1 for entry in report_checks or [] if isinstance(entry, dict) and entry.get("status") == "fail")
    waived = sum(1 for entry in report_checks or [] if isinstance(entry, dict) and entry.get("status") == "waived")
    total = len(report_checks or []) if isinstance(report_checks, list) else 0
    summary_match = (
        summary.get("total_checks") == total
        and summary.get("passed") == passed
        and summary.get("failed") == failed
        and summary.get("waived") == waived
    )
    checks.append(
        _check(
            "summary_matches_checks",
            summary_match,
            (
                f"summary={summary} computed={{'total_checks': {total}, 'passed': {passed}, "
                f"'failed': {failed}, 'waived': {waived}}}"
            ),
        )
    )

    expected_verdict = "pass" if failed == 0 else "fail"
    checks.append(
        _check(
            "gate_verdict_consistent",
            report.get("gate_verdict") == expected_verdict,
            f"expected={expected_verdict} actual={report.get('gate_verdict')}",
        )
    )

    changed_modules = report.get("changed_modules")
    changed_ok = isinstance(changed_modules, list) and all(
        isinstance(item, str) and item.startswith(MODULE_ROOT_FALLBACK) for item in (changed_modules or [])
    )
    checks.append(
        _check(
            "changed_modules_normalized",
            changed_ok,
            f"count={len(changed_modules) if isinstance(changed_modules, list) else 'invalid'}",
        )
    )

    event_codes = {
        item.get("code")
        for item in (report.get("events") or [])
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    }
    checks.append(
        _check(
            "event_codes_from_expected_set",
            event_codes.issubset(set(EXPECTED_EVENTS)),
            f"event_codes={sorted(event_codes)}",
        )
    )

    passed_checks = sum(1 for item in checks if item["pass"])
    failed_checks = len(checks) - passed_checks
    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "total": len(checks),
        "passed": passed_checks,
        "failed": failed_checks,
        "overall_pass": failed_checks == 0,
        "verdict": "PASS" if failed_checks == 0 else "FAIL",
        "status": "pass" if failed_checks == 0 else "fail",
        "metrics": {
            "report_check_count": len(report_checks) if isinstance(report_checks, list) else 0,
            "expected_event_codes": EXPECTED_EVENTS,
        },
    }


def run_all(build_report: bool, changed_modules: list[str] | None) -> dict[str, Any]:
    if build_report:
        report = build_gate_report(changed_modules)
        _write_json(REPORT_PATH, report)
    else:
        report = _load_json(REPORT_PATH)
        if report is None:
            return {
                "bead_id": BEAD_ID,
                "section": SECTION,
                "title": TITLE,
                "checks": [
                    _check(
                        "report_exists",
                        False,
                        f"missing or invalid report: {REPORT_PATH}",
                    )
                ],
                "total": 1,
                "passed": 0,
                "failed": 1,
                "overall_pass": False,
                "verdict": "FAIL",
                "status": "fail",
                "metrics": {},
            }

    return validate_gate_report(report)


def self_test() -> bool:
    live_report = build_gate_report(["crates/franken-node/src/cli.rs"])
    assert "checks" in live_report and isinstance(live_report["checks"], list)

    validation = validate_gate_report(live_report)
    assert validation["verdict"] in {"PASS", "FAIL"}

    tampered = dict(live_report)
    tampered["summary"] = {"total_checks": 999, "passed": 0, "failed": 0, "waived": 0}
    invalid = validate_gate_report(tampered)
    assert any(
        check["check"] == "summary_matches_checks" and not check["pass"]
        for check in invalid["checks"]
    )

    broken = {
        "schema_version": "1.0.0",
        "bead_id": BEAD_ID,
        "checks": [
            {
                "module": "crates/franken-node/src/cli.rs",
                "substrate": "frankentui",
                "rule": "adjacent-substrate.mandatory.frankentui.raw-output",
                "status": "fail",
                "remediation_hint": "",
                "waiver_id": "",
            }
        ],
        "summary": {"total_checks": 1, "passed": 0, "failed": 1, "waived": 0},
        "gate_verdict": "fail",
        "events": [],
        "changed_modules": ["crates/franken-node/src/cli.rs"],
    }
    broken_validation = validate_gate_report(broken)
    assert any(
        check["check"] == "failure_remediation_hints_present" and not check["pass"]
        for check in broken_validation["checks"]
    )
    return True


def main() -> None:
    logger = configure_test_logging("check_substrate_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON validation report")
    parser.add_argument("--self-test", action="store_true", help="Run internal self test")
    parser.add_argument(
        "--build-report",
        action="store_true",
        help="Build artifacts/10.16/adjacent_substrate_gate_report.json before validation",
    )
    parser.add_argument(
        "--changed-module",
        action="append",
        default=[],
        help="Optional explicit changed module path (repeatable).",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    changed_modules = args.changed_module or None
    result = run_all(build_report=args.build_report, changed_modules=changed_modules)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        print(f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
