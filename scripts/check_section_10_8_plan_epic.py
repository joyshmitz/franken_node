#!/usr/bin/env python3
"""Verification script for bd-c4f (Section 10.8 plan epic).

Ensures the plan-epic closure conditions are satisfied:
- All child dependencies are closed.
- Section verification gate evidence (bd-1fi2) is PASS.
- Section 10.8 implementation evidence/spec artifacts are present.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-c4f"
SECTION = "10.8"
TITLE = "Operational Readiness"

SECTION_GATE_ID = "bd-1fi2"
MASTER_DEPENDENT_ID = "bd-33v"

# Cross-epic deps expected by section plan semantics.
SECTION_CROSS_EPIC_DEPS = ["bd-1ta", "bd-20a", "bd-cda"]

SECTION_IMPL_BEADS = [
    "bd-tg2",
    "bd-3o6",
    "bd-k6o",
    "bd-f2y",
    "bd-nr4",
    "bd-3m6",
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

    if not isinstance(payload, list) or not payload:
        return None
    first = payload[0]
    if not isinstance(first, dict):
        return None
    return first


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _evidence_pass(data: dict[str, Any]) -> bool:
    verdict = str(data.get("verdict", "")).strip().upper()
    if verdict == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    status = str(data.get("status", "")).strip().lower()
    return status in {
        "pass",
        "passed",
        "ok",
        "completed",
        "completed_with_baseline_workspace_failures",
    }


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    epic = _run_br_show(BEAD_ID)
    checks.append(
        _check(
            "epic_record_accessible",
            epic is not None,
            "br show bd-c4f readable" if epic is not None else "unable to load br show bd-c4f --json",
        )
    )
    if epic is None:
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "title": TITLE,
            "checks": checks,
            "total": len(checks),
            "passed": sum(1 for c in checks if c["pass"]),
            "failed": sum(1 for c in checks if not c["pass"]),
            "overall_pass": False,
            "verdict": "FAIL",
            "status": "fail",
        }

    checks.append(
        _check(
            "epic_identity",
            epic.get("id") == BEAD_ID and epic.get("issue_type") == "epic",
            f"id={epic.get('id')} issue_type={epic.get('issue_type')}",
        )
    )
    checks.append(
        _check(
            "epic_section_label",
            "section-10-8" in (epic.get("labels") or []),
            f"labels={epic.get('labels')}",
        )
    )
    checks.append(
        _check(
            "success_criteria_documented",
            "## Success Criteria" in str(epic.get("description", "")),
            "Success Criteria present in description",
        )
    )
    checks.append(
        _check(
            "optimization_notes_documented",
            "## Optimization Notes" in str(epic.get("description", "")),
            "Optimization Notes present in description",
        )
    )

    dependencies = epic.get("dependencies") or []
    checks.append(
        _check(
            "has_dependencies",
            isinstance(dependencies, list) and len(dependencies) >= 10,
            f"dependency_count={len(dependencies) if isinstance(dependencies, list) else 'invalid'}",
        )
    )

    closed_dependencies = 0
    open_dependencies: list[str] = []
    dependency_ids: list[str] = []
    if isinstance(dependencies, list):
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            dep_id = str(dep.get("id", ""))
            dep_status = str(dep.get("status", "")).lower()
            if dep_id:
                dependency_ids.append(dep_id)
            if dep_status == "closed":
                closed_dependencies += 1
            else:
                open_dependencies.append(f"{dep_id}:{dep_status}")

    checks.append(
        _check(
            "all_dependencies_closed",
            len(open_dependencies) == 0,
            f"closed={closed_dependencies}/{len(dependency_ids)} open={open_dependencies}",
        )
    )

    checks.append(
        _check(
            "section_gate_dependency_present",
            SECTION_GATE_ID in dependency_ids,
            f"{SECTION_GATE_ID} in dependencies",
        )
    )

    missing_cross_epic = sorted(set(SECTION_CROSS_EPIC_DEPS).difference(dependency_ids))
    checks.append(
        _check(
            "cross_epic_dependencies_present",
            len(missing_cross_epic) == 0,
            f"missing={missing_cross_epic}",
        )
    )

    dependents = epic.get("dependents") or []
    dependent_ids = []
    if isinstance(dependents, list):
        dependent_ids = [str(d.get("id", "")) for d in dependents if isinstance(d, dict)]

    checks.append(
        _check(
            "master_graph_dependent_present",
            MASTER_DEPENDENT_ID in dependent_ids,
            f"dependents={dependent_ids}",
        )
    )

    section_gate_evidence = ROOT / "artifacts" / "section_10_8" / SECTION_GATE_ID / "verification_evidence.json"
    section_gate_summary = ROOT / "artifacts" / "section_10_8" / SECTION_GATE_ID / "verification_summary.md"
    checks.append(
        _check(
            "section_gate_evidence_exists",
            section_gate_evidence.is_file(),
            str(section_gate_evidence.relative_to(ROOT)),
        )
    )
    checks.append(
        _check(
            "section_gate_summary_exists",
            section_gate_summary.is_file(),
            str(section_gate_summary.relative_to(ROOT)),
        )
    )

    gate_payload = _load_json(section_gate_evidence)
    checks.append(
        _check(
            "section_gate_evidence_parseable",
            gate_payload is not None,
            "json parse ok" if gate_payload is not None else "invalid or missing json",
        )
    )
    if gate_payload is not None:
        checks.append(
            _check(
                "section_gate_verdict_pass",
                _evidence_pass(gate_payload),
                f"verdict={gate_payload.get('verdict')} status={gate_payload.get('status')}",
            )
        )

    spec_dir = ROOT / "docs" / "specs" / "section_10_8"
    spec_files = sorted(spec_dir.glob("bd-*_contract.md")) if spec_dir.is_dir() else []
    checks.append(
        _check(
            "section_contract_specs_present",
            len(spec_files) >= 6,
            f"spec_count={len(spec_files)}",
        )
    )

    missing_impl_evidence = []
    missing_impl_summary = []
    for bead_id in SECTION_IMPL_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_evidence.json"
        summary_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_summary.md"
        if not evidence_path.is_file():
            missing_impl_evidence.append(bead_id)
        if not summary_path.is_file():
            missing_impl_summary.append(bead_id)

    checks.append(
        _check(
            "all_impl_evidence_present",
            len(missing_impl_evidence) == 0,
            f"missing={missing_impl_evidence}",
        )
    )
    checks.append(
        _check(
            "all_impl_summaries_present",
            len(missing_impl_summary) == 0,
            f"missing={missing_impl_summary}",
        )
    )

    missing_from_epic = sorted(set(SECTION_IMPL_BEADS).difference(dependency_ids))
    checks.append(
        _check(
            "impl_beads_linked_to_epic_dependencies",
            len(missing_from_epic) == 0,
            f"missing_links={missing_from_epic}",
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
            "dependency_count": len(dependency_ids),
            "dependency_closed_count": closed_dependencies,
            "cross_epic_dependency_count": len(SECTION_CROSS_EPIC_DEPS),
            "dependent_count": len(dependent_ids),
            "section_contract_spec_count": len(spec_files),
            "section_impl_bead_count": len(SECTION_IMPL_BEADS),
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
    logger = configure_test_logging("check_section_10_8_plan_epic")
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
