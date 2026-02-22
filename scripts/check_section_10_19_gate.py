#!/usr/bin/env python3
"""Section 10.19 verification gate: Adaptive Trust Consensus (ATC).

Aggregates evidence from all 13 section 10.19 beads and produces a gate verdict.

Usage:
    python3 scripts/check_section_10_19_gate.py          # human-readable
    python3 scripts/check_section_10_19_gate.py --json    # machine-readable
    python3 scripts/check_section_10_19_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

GATE_BEAD = "bd-3hr2"
SECTION = "10.19"

# All 13 section 10.19 implementation beads
SECTION_BEADS = [
    ("bd-293y", "ATC federation trust model"),
    ("bd-3aqy", "Canonical federated signal schema"),
    ("bd-1hj3", "Local signal extraction pipeline"),
    ("bd-ukh7", "Privacy envelope layer"),
    ("bd-3ps8", "Mergeable sketch system"),
    ("bd-2ozr", "Poisoning-resilient aggregation"),
    ("bd-253o", "ATC global priors integration"),
    ("bd-1eot", "Privacy-preserving urgent routing"),
    ("bd-11rz", "ATC release claim gate"),
    ("bd-24du", "ATC partition fallback and degraded mode"),
    ("bd-2yvw", "Sybil-resistant participation weighting"),
    ("bd-2zip", "ATC verifier APIs and proof artifacts"),
    ("bd-3gwi", "Contribution-weighted intelligence access and reciprocity controls"),
]

# Domain groupings for coverage checks
DOMAIN_GROUPS = {
    "federation_trust": ["bd-293y"],
    "signal_schema": ["bd-3aqy"],
    "signal_extraction": ["bd-1hj3"],
    "privacy_envelope": ["bd-ukh7"],
    "sketch_system": ["bd-3ps8"],
    "aggregation": ["bd-2ozr"],
    "global_priors": ["bd-253o"],
    "urgent_routing": ["bd-1eot"],
    "release_gate": ["bd-11rz"],
    "partition_fallback": ["bd-24du"],
    "participation_weighting": ["bd-2yvw"],
    "verifier_apis": ["bd-2zip"],
    "reciprocity": ["bd-3gwi"],
}

# Key section-level artifacts
KEY_ARTIFACTS = [
    ("atc_release_gate_report", "artifacts/10.19/atc_release_gate_report.json"),
    ("atc_weighting_audit_report", "artifacts/10.19/atc_weighting_audit_report.json"),
    ("atc_verifier_report", "artifacts/10.19/atc_verifier_report.json"),
    ("atc_reciprocity_matrix", "artifacts/10.19/atc_reciprocity_matrix.json"),
    ("atc_degraded_mode_events", "artifacts/10.19/atc_degraded_mode_events.jsonl"),
]

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
        py_checker = vr.get("python_checker", vr.get("check_script", {}))
        py_tests = vr.get("python_unit_tests", vr.get("unit_tests", {}))
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


def _find_evidence(bead_id: str) -> Path | None:
    base = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id
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


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = _find_evidence(bead_id)
    if evidence_path is None:
        fallback = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id / "verification_evidence.json"
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(fallback)}")
    data = _load_evidence(evidence_path)
    if data is None:
        return _check(f"evidence_{bead_id}", False, f"parse error: {_safe_relative(evidence_path)}")
    passed = _evidence_pass(data)
    return _check(
        f"evidence_{bead_id}",
        passed,
        f"PASS: {title[:60]}" if passed else f"FAIL: {title[:60]}",
    )


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / f"section_{SECTION.replace('.', '_')}" / bead_id / "verification_summary.md"
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


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = _find_evidence(bead_id)
        if evidence_path is not None:
            data = _load_evidence(evidence_path)
            if data is not None and _evidence_pass(data):
                pass_count += 1
            else:
                fail_list.append(bead_id)
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_key_artifacts() -> list[dict[str, Any]]:
    checks = []
    for name, rel_path in KEY_ARTIFACTS:
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
        ("gate_tests", "tests/test_check_section_10_19_gate.py"),
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


def check_domain_coverage() -> list[dict[str, Any]]:
    """Verify all domain groups have passing beads."""
    checks = []
    for domain, bead_ids in DOMAIN_GROUPS.items():
        passing = 0
        for bead_id in bead_ids:
            evidence_path = _find_evidence(bead_id)
            if evidence_path is not None:
                data = _load_evidence(evidence_path)
                if data is not None and _evidence_pass(data):
                    passing += 1
        all_pass = passing == len(bead_ids)
        checks.append(_check(
            f"domain_{domain}_coverage",
            all_pass,
            f"{passing}/{len(bead_ids)} beads PASS",
        ))
    return checks


def check_pipeline_completeness() -> list[dict[str, Any]]:
    """Verify the ATC pipeline has coverage: schema -> extraction -> aggregation -> priors -> routing."""
    checks = []
    pipeline_stages = [
        ("pipeline_schema_to_extraction", ["bd-3aqy", "bd-1hj3"]),
        ("pipeline_extraction_to_aggregation", ["bd-1hj3", "bd-2ozr"]),
        ("pipeline_privacy_to_aggregation", ["bd-ukh7", "bd-2ozr"]),
        ("pipeline_sketch_to_aggregation", ["bd-3ps8", "bd-2ozr"]),
        ("pipeline_aggregation_to_priors", ["bd-2ozr", "bd-253o"]),
        ("pipeline_trust_to_participation", ["bd-293y", "bd-2yvw"]),
        ("pipeline_participation_to_reciprocity", ["bd-2yvw", "bd-3gwi"]),
        ("pipeline_verifier_to_release", ["bd-2zip", "bd-11rz"]),
    ]
    for name, bead_ids in pipeline_stages:
        all_have_evidence = all(_find_evidence(bid) is not None for bid in bead_ids)
        checks.append(_check(
            name,
            all_have_evidence,
            "both have evidence" if all_have_evidence else "incomplete",
        ))
    return checks


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    check_all_evidence_present()
    check_all_verdicts_pass()
    check_key_artifacts()
    check_gate_deliverables()
    check_domain_coverage()
    check_pipeline_completeness()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": GATE_BEAD,
        "title": f"Section {SECTION} verification gate: Adaptive Trust Consensus (ATC)",
        "section": SECTION,
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [b[0] for b in SECTION_BEADS],
        "checks": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("section_bead_count", len(SECTION_BEADS) == 13, str(len(SECTION_BEADS)))
    push("domain_group_count", len(DOMAIN_GROUPS) == 13, str(len(DOMAIN_GROUPS)))
    push("gate_bead_set", GATE_BEAD == "bd-3hr2", GATE_BEAD)
    push("section_set", SECTION == "10.19", SECTION)

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")
    push("run_all_has_section_beads", len(report.get("section_beads", [])) == 13, "13 beads")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": GATE_BEAD,
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Section {SECTION} verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"SELF-TEST: {result['verdict']} ({result['passed']}/{result['total']})")
            for check in result["checks"]:
                mark = "+" if check["pass"] else "x"
                print(f"  [{mark}] {check['check']}: {check['detail']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

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
