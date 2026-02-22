#!/usr/bin/env python3
"""Verification gate for bd-1naf BPET governance policy deliverables."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_10_21" / "bd-1naf_contract.md"
POLICY = ROOT / "docs" / "policy" / "bpet_governance_policy.md"
RUST_TEST = ROOT / "tests" / "policy" / "bpet_override_audit.rs"
AUDIT_LOG = ROOT / "artifacts" / "10.21" / "bpet_governance_audit_log.jsonl"

RESULTS: list[dict[str, Any]] = []

POLICY_HEADINGS = [
    "## Thresholding Policy",
    "## False Positive Handling",
    "## Appeal Lifecycle",
    "## Override Workflow",
    "## Signed Rationale Requirements",
    "## Safety Constraints",
    "## Auditability and Logging",
]

REQUIRED_EVENT_CODES = {
    "BPET-GOV-001",
    "BPET-GOV-002",
    "BPET-GOV-003",
    "BPET-GOV-004",
    "BPET-GOV-005",
    "BPET-GOV-007",
}

BASE_AUDIT_FIELDS = {
    "event_code",
    "event_type",
    "decision_id",
    "trace_id",
    "timestamp",
    "actor_id",
    "threshold_band",
    "rationale",
    "signature",
    "status",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    entries: list[dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            _check("audit_jsonl_parse", False, f"invalid JSON at line {line_no}")
            return []
        if not isinstance(obj, dict):
            _check("audit_jsonl_parse", False, f"non-object JSON at line {line_no}")
            return []
        entries.append(obj)

    return entries


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_files_exist() -> None:
    _check("file_spec_contract", SPEC.is_file(), _safe_relative(SPEC))
    _check("file_policy_doc", POLICY.is_file(), _safe_relative(POLICY))
    _check("file_policy_rust_test", RUST_TEST.is_file(), _safe_relative(RUST_TEST))
    _check("file_governance_audit_log", AUDIT_LOG.is_file(), _safe_relative(AUDIT_LOG))


def check_policy_content() -> None:
    if not POLICY.is_file():
        _check("policy_sections", False, "policy file missing")
        _check("policy_event_codes", False, "policy file missing")
        _check("policy_hard_stop_clause", False, "policy file missing")
        return

    text = POLICY.read_text()

    present_sections = sum(1 for section in POLICY_HEADINGS if section in text)
    _check(
        "policy_sections",
        present_sections == len(POLICY_HEADINGS),
        f"{present_sections}/{len(POLICY_HEADINGS)} required policy sections",
    )

    codes_found = sum(1 for code in REQUIRED_EVENT_CODES if code in text)
    _check(
        "policy_event_codes",
        codes_found == len(REQUIRED_EVENT_CODES),
        f"{codes_found}/{len(REQUIRED_EVENT_CODES)} required event codes",
    )

    hard_stop_ok = "Non-overridable hard-stop conditions" in text and "cannot be overridden" in text
    _check(
        "policy_hard_stop_clause",
        hard_stop_ok,
        "hard-stop non-override clause present" if hard_stop_ok else "missing hard-stop non-override clause",
    )


def check_rust_test_fixture() -> None:
    if not RUST_TEST.is_file():
        _check("rust_test_fixture", False, "rust test file missing")
        return

    src = RUST_TEST.read_text()
    test_count = src.count("#[test]")
    _check("rust_test_fixture", test_count >= 10, f"{test_count} tests")



def check_audit_log() -> None:
    entries = _read_jsonl(AUDIT_LOG)
    if not entries:
        _check("audit_entries_present", False, "no parseable audit entries")
        _check("audit_schema", False, "audit entries missing")
        _check("audit_event_code_coverage", False, "audit entries missing")
        _check("audit_appeal_lifecycle", False, "audit entries missing")
        _check("audit_override_signature", False, "audit entries missing")
        _check("audit_override_bounds", False, "audit entries missing")
        return

    _check("audit_entries_present", len(entries) >= 6, f"{len(entries)} entries")

    schema_ok = True
    for idx, entry in enumerate(entries):
        missing = BASE_AUDIT_FIELDS.difference(entry.keys())
        if missing:
            schema_ok = False
            _check("audit_schema", False, f"entry {idx} missing {sorted(missing)}")
            break
    if schema_ok:
        _check("audit_schema", True, "all entries include required base fields")

    codes = {str(e.get("event_code", "")) for e in entries}
    matched = len(REQUIRED_EVENT_CODES.intersection(codes))
    _check(
        "audit_event_code_coverage",
        REQUIRED_EVENT_CODES.issubset(codes),
        f"{matched}/{len(REQUIRED_EVENT_CODES)} required event codes present",
    )

    event_types = {str(e.get("event_type", "")) for e in entries}
    appeal_ok = "appeal_filed" in event_types and "appeal_resolved" in event_types
    _check(
        "audit_appeal_lifecycle",
        appeal_ok,
        "appeal_filed + appeal_resolved present" if appeal_ok else "appeal lifecycle incomplete",
    )

    override_events = [
        e
        for e in entries
        if str(e.get("event_type", "")).startswith("override_")
    ]
    signed_ok = bool(override_events)
    for event in override_events:
        signature = str(event.get("signature", ""))
        rationale = str(event.get("rationale", ""))
        if not signature.startswith("ed25519:") or not rationale:
            signed_ok = False
            break
    _check(
        "audit_override_signature",
        signed_ok,
        "override events contain signed rationale" if signed_ok else "override signature/rationale missing",
    )

    bounds_ok = True
    for event in entries:
        if str(event.get("event_type", "")) != "override_requested":
            continue
        ttl = int(event.get("override_ttl_minutes", 0))
        threshold = str(event.get("threshold_band", ""))
        actor = str(event.get("actor_id", ""))
        approver = str(event.get("approver_id", ""))
        if ttl <= 0 or ttl > 180:
            bounds_ok = False
            break
        if threshold == "T3" and actor == approver:
            bounds_ok = False
            break
    _check(
        "audit_override_bounds",
        bounds_ok,
        "override TTL and dual-control bounds satisfied" if bounds_ok else "override bounds violated",
    )



def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    check_files_exist()
    check_policy_content()
    check_rust_test_fixture()
    check_audit_log()

    return RESULTS



def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed
    overall = failed == 0

    return {
        "bead_id": "bd-1naf",
        "title": "BPET governance policy for thresholding/appeals/override workflows",
        "section": "10.21",
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "artifacts": {
            "spec": _safe_relative(SPEC),
            "policy": _safe_relative(POLICY),
            "rust_test": _safe_relative(RUST_TEST),
            "audit_log": _safe_relative(AUDIT_LOG),
        },
    }



def self_test() -> bool:
    checks = run_all_checks()
    if not checks:
        print("SELF-TEST FAIL: no checks", file=sys.stderr)
        return False

    for check in checks:
        if not isinstance(check, dict) or not {"check", "pass", "detail"}.issubset(check.keys()):
            print(f"SELF-TEST FAIL: malformed check entry {check}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True



def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-1naf BPET governance deliverables")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    output = run_all()
    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(f"\n  bd-1naf gate: {output['verdict']} ({output['passed']}/{output['total']})\n")
        for check in output["checks"]:
            mark = "+" if check["pass"] else "x"
            print(f"  [{mark}] {check['check']}: {check['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
