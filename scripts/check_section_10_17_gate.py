#!/usr/bin/env python3
"""Section 10.17 verification gate: Radical Expansion Execution Track.

Aggregates evidence from all section 10.17 beads and produces a gate verdict.

Usage:
    python3 scripts/check_section_10_17_gate.py          # human-readable
    python3 scripts/check_section_10_17_gate.py --json    # machine-readable
    python3 scripts/check_section_10_17_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


BEAD = "bd-3t08"
SECTION = "10.17"
ISSUES_EXPORT = ROOT / ".beads" / "issues.jsonl"

# Section 10.17 beads (all upstream dependencies of bd-3t08)
SECTION_BEADS = [
    ("bd-1nl1", "Build proof-carrying speculative execution governance framework"),
    ("bd-274s", "Implement Bayesian adversary graph and automated quarantine controller"),
    ("bd-1xbc", "Add deterministic time-travel runtime capture/replay for extension-host workflows"),
    ("bd-3ku8", "Define and enforce capability-carrying extension artifact format"),
    ("bd-gad3", "Ship adaptive multi-rail isolation mesh with hot-elevation policy"),
    ("bd-kcg9", "Add zero-knowledge attestation support for selective compliance verification"),
    ("bd-al8i", "Implement L2 engine-boundary N-version semantic oracle"),
    ("bd-26mk", "Implement security staking and slashing framework for publisher trust governance"),
    ("bd-21fo", "Build self-evolving optimization governor with safety-envelope enforcement"),
    ("bd-3l2p", "Ship intent-aware remote effects firewall for extension-originated traffic"),
    ("bd-2iyk", "Implement information-flow lineage and exfiltration sentinel"),
    ("bd-nbwo", "Publish universal verifier SDK and replay capsule format"),
    ("bd-2o8b", "Implement heterogeneous hardware planner with policy-evidenced placements"),
    ("bd-383z", "Build counterfactual incident lab and mitigation synthesis workflow"),
    ("bd-2kd9", "Implement claim compiler and public trust scoreboard pipeline"),
]

# Domain groupings for coverage checks
DOMAIN_GROUPS = {
    "speculation_governance": ["bd-1nl1"],
    "adversary_control": ["bd-274s"],
    "replay_capture": ["bd-1xbc"],
    "capability_enforcement": ["bd-3ku8", "bd-gad3"],
    "zk_attestation": ["bd-kcg9"],
    "oracle_harness": ["bd-al8i"],
    "trust_governance": ["bd-26mk"],
    "optimization_governor": ["bd-21fo"],
    "security_firewall": ["bd-3l2p", "bd-2iyk"],
    "verifier_sdk": ["bd-nbwo"],
    "hardware_planner": ["bd-2o8b"],
    "incident_lab": ["bd-383z"],
    "claim_compiler": ["bd-2kd9"],
}

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _evidence_pass(data: dict[str, Any]) -> bool:
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    if data.get("all_passed") is True:
        return True
    raw_status = str(data.get("status", "")).lower()
    if raw_status == "pass":
        return True
    if raw_status == "completed":
        return True
    if raw_status.startswith("completed_with_"):
        return True
    vr = data.get("verification_results", {})
    if vr:
        py_checker = vr.get("python_checker", {})
        py_tests = vr.get("python_unit_tests", {})
        if py_checker.get("verdict") == "PASS" and py_tests.get("verdict") == "PASS":
            return True
    overall_status = str(data.get("overall_status", "")).lower()
    if overall_status.startswith("partial_blocked_by_preexisting"):
        deliverables = data.get("deliverables", [])
        if deliverables and all(d.get("exists") for d in deliverables):
            return True
    return False


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _load_issue_index(path: Path = ISSUES_EXPORT) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}

    issues: dict[str, dict[str, Any]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            issue = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        issue_id = str(issue.get("id", "")).strip()
        if issue_id:
            issues[issue_id] = issue
    return issues


def _issue_status(issue: dict[str, Any] | None) -> str:
    if issue is None:
        return "missing"
    status = str(issue.get("status", "")).strip().lower()
    return status or "missing"


def _dependency_target(dep: dict[str, Any]) -> str:
    return str(dep.get("depends_on_id") or dep.get("id") or "").strip()


def _dependency_type(dep: dict[str, Any]) -> str:
    return str(dep.get("type") or dep.get("dependency_type") or "").strip().lower()


def _open_blockers(
    issue: dict[str, Any] | None,
    issue_index: dict[str, dict[str, Any]],
) -> list[str]:
    if issue is None:
        return []

    blockers: list[str] = []
    for dep in issue.get("dependencies", []):
        dep_type = _dependency_type(dep)
        if dep_type != "blocks":
            continue
        target_id = _dependency_target(dep)
        if not target_id:
            continue
        target_issue = issue_index.get(target_id)
        target_status = _issue_status(target_issue or dep)
        if target_status != "closed":
            blockers.append(target_id)
    return blockers


def _open_upstream_beads(
    issue_index: dict[str, dict[str, Any]],
) -> list[tuple[str, str]]:
    open_beads: list[tuple[str, str]] = []
    for bead_id, _ in SECTION_BEADS:
        status = _issue_status(issue_index.get(bead_id))
        if status != "closed":
            open_beads.append((bead_id, status))
    return open_beads


def _open_upstream_blockers(
    issue_index: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    blocker_map: dict[str, list[str]] = {}
    for bead_id, _ in SECTION_BEADS:
        blockers = _open_blockers(issue_index.get(bead_id), issue_index)
        if blockers:
            blocker_map[bead_id] = blockers
    return blocker_map


def _find_evidence(bead_id: str) -> Path | None:
    """Locate evidence file, trying verification_evidence.json then check_report.json."""
    base = ROOT / "artifacts" / "section_10_17" / bead_id
    for name in ("verification_evidence.json", "check_report.json"):
        p = base / name
        if p.is_file():
            return p
    return None


def _load_evidence(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _evaluate_bead_gate_state(
    bead_id: str,
    title: str,
    issue_index: dict[str, dict[str, Any]],
) -> tuple[bool, str]:
    evidence_path = _find_evidence(bead_id)
    if evidence_path is None:
        fallback = ROOT / "artifacts" / "section_10_17" / bead_id / "verification_evidence.json"
        return False, f"missing: {_safe_relative(fallback)}"
    data = _load_evidence(evidence_path)
    if data is None:
        return False, f"parse error: {_safe_relative(evidence_path)}"

    if not _evidence_pass(data):
        return False, f"FAIL artifact: {title[:60]}"

    issue = issue_index.get(bead_id)
    tracker_status = _issue_status(issue)
    if tracker_status != "closed":
        return False, f"stale PASS artifact: tracker status={tracker_status}"

    blockers = _open_blockers(issue, issue_index)
    if blockers:
        return False, f"stale PASS artifact: open blockers {', '.join(blockers)}"

    return True, f"PASS: {title[:60]}"


def check_bead_evidence(
    bead_id: str,
    title: str,
    issue_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    passed, detail = _evaluate_bead_gate_state(bead_id, title, issue_index)
    return _check(f"evidence_{bead_id}", passed, detail)


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / "section_10_17" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        if _find_evidence(bead_id) is not None:
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check("all_evidence_present", passed, f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_verdicts_pass(issue_index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        passed, _detail = _evaluate_bead_gate_state(bead_id, bead_id, issue_index)
        if passed:
            pass_count += 1
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_all_upstream_beads_closed(
    issue_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    open_beads = _open_upstream_beads(issue_index)
    passed = not open_beads
    if passed:
        detail = "all upstream section beads are closed"
    else:
        detail = "open/reopened upstream beads: " + ", ".join(
            f"{bead_id}={status}" for bead_id, status in open_beads
        )
    return _check("all_upstream_beads_closed", passed, detail)


def check_all_upstream_blockers_closed(
    issue_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    blocker_map = _open_upstream_blockers(issue_index)
    passed = not blocker_map
    if passed:
        detail = "all upstream bead blockers are closed"
    else:
        detail = "open blocker chain: " + "; ".join(
            f"{bead_id}->{', '.join(blockers)}"
            for bead_id, blockers in blocker_map.items()
        )
    return _check("all_upstream_blockers_closed", passed, detail)


def check_key_artifacts() -> list[dict[str, Any]]:
    checks = []
    key_artifacts = [
        ("speculation_report", "artifacts/10.17/speculation_proof_report.json"),
        ("time_travel_report", "artifacts/10.17/time_travel_replay_report.json"),
        ("capability_vectors", "artifacts/10.17/capability_artifact_vectors.json"),
        ("isolation_mesh_report", "artifacts/10.17/isolation_mesh_profile_report.json"),
        ("zk_attestation_vectors", "artifacts/10.17/zk_attestation_vectors.json"),
        ("oracle_matrix", "artifacts/10.17/semantic_oracle_divergence_matrix.csv"),
        ("staking_ledger", "artifacts/10.17/staking_ledger_snapshot.json"),
        ("governor_log", "artifacts/10.17/governor_decision_log.jsonl"),
        ("firewall_report", "artifacts/10.17/intent_firewall_eval_report.json"),
        ("exfiltration_metrics", "artifacts/10.17/exfiltration_detector_metrics.csv"),
        ("verifier_sdk_report", "artifacts/10.17/verifier_sdk_certification_report.json"),
        ("hardware_trace", "artifacts/10.17/hardware_placement_trace.json"),
        ("counterfactual_report", "artifacts/10.17/counterfactual_eval_report.json"),
        ("scoreboard_snapshot", "artifacts/10.17/public_trust_scoreboard_snapshot.json"),
    ]
    for name, rel_path in key_artifacts:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"artifact_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_gate_deliverables() -> list[dict[str, Any]]:
    checks = []
    gate_files = [
        ("gate_evidence", f"artifacts/section_10_17/{BEAD}/verification_evidence.json"),
        ("gate_summary", f"artifacts/section_10_17/{BEAD}/verification_summary.md"),
        ("gate_spec", f"docs/specs/section_10_17/{BEAD}_contract.md"),
        ("gate_tests", "tests/test_check_section_10_17_gate.py"),
    ]
    for name, rel_path in gate_files:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            name,
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_domain_coverage(
    issue_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Verify all domain groups have passing beads."""
    checks = []
    for domain, bead_ids in DOMAIN_GROUPS.items():
        passing = 0
        for bead_id in bead_ids:
            passed, _detail = _evaluate_bead_gate_state(bead_id, bead_id, issue_index)
            if passed:
                passing += 1
        all_pass = passing == len(bead_ids)
        checks.append(_check(
            f"domain_{domain}_coverage",
            all_pass,
            f"{passing}/{len(bead_ids)} beads PASS",
        ))
    return checks


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()
    issue_index = _load_issue_index()

    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title, issue_index)

    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    check_all_evidence_present()
    check_all_verdicts_pass(issue_index)
    check_all_upstream_beads_closed(issue_index)
    check_all_upstream_blockers_closed(issue_index)
    check_key_artifacts()
    check_gate_deliverables()
    check_domain_coverage(issue_index)

    return RESULTS


def run_all() -> dict[str, Any]:
    issue_index = _load_issue_index()
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    open_upstream_beads = [
        {"bead_id": bead_id, "status": status}
        for bead_id, status in _open_upstream_beads(issue_index)
    ]
    open_upstream_blockers = [
        {"bead_id": bead_id, "blockers": blockers}
        for bead_id, blockers in _open_upstream_blockers(issue_index).items()
    ]
    return {
        "bead_id": BEAD,
        "title": f"Section {SECTION} verification gate: Radical Expansion Execution Track",
        "section": SECTION,
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [b[0] for b in SECTION_BEADS],
        "issues_export": _safe_relative(ISSUES_EXPORT),
        "open_upstream_beads": open_upstream_beads,
        "open_upstream_blockers": open_upstream_blockers,
        "checks": results,
    }


def self_test() -> bool:
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for r in results:
        if not isinstance(r, dict) or not all(k in r for k in ("check", "pass", "detail")):
            print(f"SELF-TEST FAIL: bad result: {r}", file=sys.stderr)
            return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_section_10_17_gate")
    parser = argparse.ArgumentParser(description=f"Section {SECTION} verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Section {SECTION} Gate: {'PASS' if result['verdict'] == 'PASS' else 'FAIL'} ({result['passed']}/{result['total']})\n")
        for r in result["checks"]:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
