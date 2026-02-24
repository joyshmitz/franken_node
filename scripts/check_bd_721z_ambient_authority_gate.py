#!/usr/bin/env python3
"""Verification checker for bd-721z ambient-authority gate closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-721z"
SECTION = "10.15"
TITLE = "Add ambient-authority audit gate for control-plane modules"

GATE_RS = ROOT / "tools" / "lints" / "ambient_authority_gate.rs"
POLICY_MD = ROOT / "docs" / "specs" / "ambient_authority_policy.md"
ALLOWLIST_TOML = ROOT / "docs" / "specs" / "ambient_authority_allowlist.toml"
FINDINGS_JSON = ROOT / "artifacts" / "10.15" / "ambient_authority_findings.json"
EVIDENCE_JSON = ROOT / "artifacts" / "section_10_15" / BEAD_ID / "verification_evidence.json"
SUMMARY_MD = ROOT / "artifacts" / "section_10_15" / BEAD_ID / "verification_summary.md"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "ambient_authority_gate.rs"

EXPECTED_EVENT_CODES = ["AMB-001", "AMB-002", "AMB-003", "AMB-004"]
EXPECTED_RESTRICTED_APIS = [
    "std::net",
    "std::process::Command",
    "std::time::Instant",
    "std::time::SystemTime",
    "std::fs",
    "tokio::net",
    "tokio::process",
    "tokio::time::sleep",
    "tokio::time::timeout",
    "tokio::spawn",
]


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "pass": bool(passed), "detail": detail}


def _run_br_show(issue_id: str) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            ["br", "show", issue_id, "--json"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None

    if proc.returncode != 0:
        return None

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        return None
    return payload[0]


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _load_allowlist(path: Path) -> dict[str, Any] | None:
    if tomllib is None or not path.is_file():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _compute_allowlist_signature(entry: dict[str, Any]) -> str:
    payload = "\n".join(
        [
            str(entry.get("module_path", "")),
            str(entry.get("ambient_api", "")),
            str(entry.get("justification", "")),
            str(entry.get("signer", "")),
            str(entry.get("expires_on", "")),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _evidence_pass(data: dict[str, Any]) -> bool:
    status = str(data.get("status", "")).lower()
    verdict = str(data.get("verdict", "")).upper()
    return status in {"pass", "passed", "ok"} or verdict == "PASS"


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    issue = _run_br_show(BEAD_ID)
    checks.append(
        _check(
            "bead_record_accessible",
            issue is not None,
            "br show bd-721z readable" if issue is not None else "unable to load br show bd-721z --json",
        )
    )

    if issue is None:
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "title": TITLE,
            "checks": checks,
            "total": len(checks),
            "passed": 0,
            "failed": len(checks),
            "overall_pass": False,
            "verdict": "FAIL",
            "status": "fail",
        }

    checks.append(
        _check(
            "bead_identity",
            issue.get("id") == BEAD_ID and issue.get("issue_type") == "task",
            f"id={issue.get('id')} issue_type={issue.get('issue_type')}",
        )
    )
    checks.append(
        _check(
            "section_label_present",
            "section-10-15" in (issue.get("labels") or []),
            f"labels={issue.get('labels')}",
        )
    )
    checks.append(
        _check(
            "not_blocked",
            str(issue.get("status", "")).lower() != "blocked",
            f"status={issue.get('status')}",
        )
    )

    dependent_ids = [
        str(dep.get("id", ""))
        for dep in (issue.get("dependents") or [])
        if isinstance(dep, dict)
    ]
    checks.append(
        _check(
            "downstream_gate_linked",
            "bd-20eg" in dependent_ids,
            f"dependents={dependent_ids}",
        )
    )

    required_paths = [
        GATE_RS,
        POLICY_MD,
        ALLOWLIST_TOML,
        FINDINGS_JSON,
        EVIDENCE_JSON,
        SUMMARY_MD,
        CONFORMANCE_TEST,
    ]
    missing_paths = [str(path.relative_to(ROOT)) for path in required_paths if not path.is_file()]
    checks.append(
        _check(
            "required_artifacts_exist",
            len(missing_paths) == 0,
            f"missing={missing_paths}",
        )
    )

    gate_src = GATE_RS.read_text(encoding="utf-8") if GATE_RS.is_file() else ""
    policy_src = POLICY_MD.read_text(encoding="utf-8") if POLICY_MD.is_file() else ""
    summary_src = SUMMARY_MD.read_text(encoding="utf-8") if SUMMARY_MD.is_file() else ""
    conformance_src = CONFORMANCE_TEST.read_text(encoding="utf-8") if CONFORMANCE_TEST.is_file() else ""

    missing_codes = [code for code in EXPECTED_EVENT_CODES if code not in gate_src]
    checks.append(
        _check(
            "gate_event_codes_present",
            len(missing_codes) == 0,
            f"missing={missing_codes}",
        )
    )

    missing_apis = [api for api in EXPECTED_RESTRICTED_APIS if api not in gate_src]
    checks.append(
        _check(
            "gate_restricted_apis_present",
            len(missing_apis) == 0,
            f"missing={missing_apis}",
        )
    )

    missing_policy_codes = [code for code in EXPECTED_EVENT_CODES if code not in policy_src]
    checks.append(
        _check(
            "policy_event_codes_documented",
            len(missing_policy_codes) == 0,
            f"missing={missing_policy_codes}",
        )
    )

    checks.append(
        _check(
            "conformance_test_writes_artifacts",
            "write_findings_json" in conformance_src and "write_verification_artifacts" in conformance_src,
            "ambient_authority_gate conformance test emits findings + verification artifacts",
        )
    )

    allowlist = _load_allowlist(ALLOWLIST_TOML)
    checks.append(
        _check(
            "allowlist_parseable",
            allowlist is not None,
            "toml parse ok" if allowlist is not None else "invalid allowlist toml",
        )
    )

    entries: list[dict[str, Any]] = []
    bad_signatures: list[str] = []
    expired_entries: list[str] = []
    if allowlist is not None:
        raw_entries = allowlist.get("exceptions")
        if isinstance(raw_entries, list):
            for raw in raw_entries:
                if isinstance(raw, dict):
                    entries.append(raw)

        today = date.today()
        for entry in entries:
            entry_id = str(entry.get("id", ""))
            signature = str(entry.get("signature", ""))
            expected = _compute_allowlist_signature(entry)
            if signature != expected:
                bad_signatures.append(entry_id)
            try:
                expiry = date.fromisoformat(str(entry.get("expires_on", "")))
                if expiry < today:
                    expired_entries.append(entry_id)
            except ValueError:
                expired_entries.append(entry_id)

    checks.append(_check("allowlist_entries_present", len(entries) > 0, f"count={len(entries)}"))
    checks.append(
        _check(
            "allowlist_signatures_valid",
            len(bad_signatures) == 0,
            f"bad_signatures={bad_signatures}",
        )
    )
    checks.append(
        _check(
            "allowlist_entries_not_expired",
            len(expired_entries) == 0,
            f"expired_or_invalid_dates={expired_entries}",
        )
    )

    findings = _load_json(FINDINGS_JSON)
    evidence = _load_json(EVIDENCE_JSON)

    checks.append(_check("findings_parseable", findings is not None, "json parse ok" if findings else "invalid findings json"))
    checks.append(_check("evidence_parseable", evidence is not None, "json parse ok" if evidence else "invalid evidence json"))

    findings_summary = findings.get("summary") if isinstance(findings, dict) else None
    if isinstance(findings_summary, dict):
        checks.append(
            _check(
                "findings_no_violations",
                int(findings_summary.get("violations", -1)) == 0,
                f"violations={findings_summary.get('violations')}",
            )
        )
        checks.append(
            _check(
                "findings_allowlist_integrity",
                int(findings_summary.get("expired_allowlist", -1)) == 0
                and int(findings_summary.get("invalid_allowlist", -1)) == 0,
                "expired_allowlist and invalid_allowlist are zero",
            )
        )

    if isinstance(evidence, dict):
        checks.append(_check("evidence_status_pass", _evidence_pass(evidence), f"status={evidence.get('status')} verdict={evidence.get('verdict')}"))

    if isinstance(findings_summary, dict) and isinstance(evidence, dict):
        metric_fields = [
            "modules_scanned",
            "findings_total",
            "violations",
            "allowlisted",
            "expired_allowlist",
            "invalid_allowlist",
        ]
        mismatches = []
        for field in metric_fields:
            left = findings_summary.get(field)
            right = evidence.get(field)
            if left != right:
                mismatches.append(f"{field}:{left}!={right}")
        checks.append(_check("findings_evidence_metrics_match", len(mismatches) == 0, f"mismatches={mismatches}"))

    checks.append(
        _check(
            "summary_reports_pass",
            "Status: **PASS**" in summary_src,
            "verification summary contains PASS status",
        )
    )

    passed = sum(1 for c in checks if c["pass"])
    failed = len(checks) - passed

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "overall_pass": failed == 0,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "metrics": {
            "allowlist_entries": len(entries),
            "dependent_count": len(dependent_ids),
            "event_codes_required": len(EXPECTED_EVENT_CODES),
            "restricted_api_markers_required": len(EXPECTED_RESTRICTED_APIS),
        },
    }


def self_test() -> bool:
    result = run_all()
    assert result["bead_id"] == BEAD_ID
    assert result["section"] == SECTION
    assert result["total"] >= 12
    for check in result["checks"]:
        assert "check" in check and "pass" in check and "detail" in check
    return True


def main() -> None:
    logger = configure_test_logging("check_bd_721z_ambient_authority_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run built-in self test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")
        print(f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
