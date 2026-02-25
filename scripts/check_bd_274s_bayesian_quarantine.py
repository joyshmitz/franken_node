#!/usr/bin/env python3
"""Support checker for bd-274s (Bayesian adversary graph + quarantine controller)."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


BEAD = "bd-274s"
SECTION = "10.17"
TITLE = "Implement Bayesian adversary graph and automated quarantine controller"

ADVERSARY_GRAPH_FILE = ROOT / "crates" / "franken-node" / "src" / "security" / "adversary_graph.rs"
QUARANTINE_CONTROLLER_FILE = ROOT / "crates" / "franken-node" / "src" / "security" / "quarantine_controller.rs"
INTEGRATION_TEST_FILE = ROOT / "tests" / "integration" / "bayesian_risk_quarantine.rs"
ADVERSARY_GRAPH_STATE_FILE = ROOT / "artifacts" / "10.17" / "adversary_graph_state.json"
VERIFICATION_EVIDENCE_FILE = ROOT / "artifacts" / "section_10_17" / BEAD / "verification_evidence.json"
VERIFICATION_SUMMARY_FILE = ROOT / "artifacts" / "section_10_17" / BEAD / "verification_summary.md"

FALLBACK_SIGNAL_FILE = ROOT / "crates" / "franken-node" / "src" / "security" / "bpet" / "economic_integration.rs"
SUPPORT_REPORT_FILE = ROOT / "artifacts" / "section_10_17" / BEAD / "support_check_report_purpleharbor.json"

REQUIRED_DEPENDENCY = "bd-1nl1"
REQUIRED_DEPENDENTS = ["bd-1xbc", "bd-3t08"]

REQUIRED_ACTION_TOKENS = ["throttle", "isolate", "revoke", "quarantine"]
REQUIRED_GRAPH_EXPORTS = [
    "AdversaryLogEntry",
    "EvidenceEvent",
    "EntityId",
    "EntityType",
    "PolicyThreshold",
    "QuarantineAction",
    "SignedEvidenceEntry",
    "ADV_005_ACTION_TRIGGERED",
    "ADV_006_NODE_REMOVED",
    "ADV_008_SIGNED_EVIDENCE",
]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {"check": name, "passed": bool(passed), "detail": detail or ("ok" if passed else "FAIL")}


def _read(path: Path) -> str:
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


def _load_json(path: Path) -> dict[str, Any] | list[Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data


def _evidence_pass(data: dict[str, Any]) -> bool:
    verdict = str(data.get("verdict", "")).upper()
    status = str(data.get("status", "")).lower()
    if verdict == "PASS":
        return True
    return status in {"pass", "passed", "ok", "completed", "completed_with_baseline_workspace_failures"}


def _extract_graph_method_calls(controller_src: str) -> list[str]:
    calls = set(re.findall(r"\b(?:self\.graph|graph)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", controller_src))
    calls.discard("clone")
    return sorted(calls)


def _has_pub_fn(source: str, fn_name: str) -> bool:
    return re.search(rf"\bpub\s+fn\s+{re.escape(fn_name)}\s*\(", source) is not None


def _extract_graph_new_call_args(controller_src: str) -> str | None:
    match = re.search(r"\bAdversaryGraph::new\s*\((.*?)\)", controller_src, re.DOTALL)
    if match is None:
        return None
    return " ".join(match.group(1).split())


def _extract_graph_new_signature(adversary_src: str) -> str | None:
    match = re.search(
        r"impl\s+AdversaryGraph\s*{[\s\S]*?\bpub\s+fn\s+new\s*\(([^)]*)\)",
        adversary_src,
        re.DOTALL,
    )
    if match is None:
        return None
    return " ".join(match.group(1).split())


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
    return first if isinstance(first, dict) else None


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    issue = _run_br_show(BEAD)
    checks.append(
        _check(
            "bead_record_accessible",
            issue is not None,
            "br show bd-274s readable" if issue is not None else "unable to load br show bd-274s --json",
        )
    )

    if issue is None:
        return {
            "schema_version": "bd-274s-support-v1",
            "bead_id": BEAD,
            "section": SECTION,
            "title": TITLE,
            "verdict": "FAIL",
            "status": "fail",
            "total": len(checks),
            "passed": 0,
            "failed": len(checks),
            "checks": checks,
            "metrics": {},
        }

    checks.append(_check("bead_identity", issue.get("id") == BEAD and issue.get("issue_type") == "task", f"id={issue.get('id')} issue_type={issue.get('issue_type')}"))
    checks.append(_check("section_label_present", "section-10-17" in (issue.get("labels") or []), f"labels={issue.get('labels')}"))

    status = str(issue.get("status", "")).lower()
    checks.append(
        _check(
            "bead_status_actionable_or_done",
            status in {"in_progress", "closed"},
            f"status={status}",
        )
    )

    dependencies = issue.get("dependencies") or []
    dep_map: dict[str, str] = {}
    if isinstance(dependencies, list):
        for dep in dependencies:
            if isinstance(dep, dict):
                dep_id = str(dep.get("id", ""))
                dep_status = str(dep.get("status", "")).lower()
                if dep_id:
                    dep_map[dep_id] = dep_status

    checks.append(
        _check(
            "required_dependency_closed",
            dep_map.get(REQUIRED_DEPENDENCY) == "closed",
            f"{REQUIRED_DEPENDENCY}={dep_map.get(REQUIRED_DEPENDENCY)}",
        )
    )

    dependent_ids: list[str] = []
    for dep in (issue.get("dependents") or []):
        if isinstance(dep, dict):
            dep_id = str(dep.get("id", ""))
            if dep_id:
                dependent_ids.append(dep_id)

    missing_dependents = [d for d in REQUIRED_DEPENDENTS if d not in dependent_ids]
    checks.append(
        _check(
            "required_dependents_linked",
            len(missing_dependents) == 0,
            f"missing={missing_dependents}",
        )
    )

    required_files = [
        ADVERSARY_GRAPH_FILE,
        QUARANTINE_CONTROLLER_FILE,
        INTEGRATION_TEST_FILE,
        ADVERSARY_GRAPH_STATE_FILE,
        VERIFICATION_EVIDENCE_FILE,
        VERIFICATION_SUMMARY_FILE,
    ]
    missing_required = [str(path.relative_to(ROOT)) for path in required_files if not path.is_file()]
    checks.append(_check("required_files_present", len(missing_required) == 0, f"missing={missing_required}"))

    adversary_src = _read(ADVERSARY_GRAPH_FILE)
    quarantine_src = _read(QUARANTINE_CONTROLLER_FILE)
    integration_src = _read(INTEGRATION_TEST_FILE)
    fallback_src = _read(FALLBACK_SIGNAL_FILE)
    summary_src = _read(VERIFICATION_SUMMARY_FILE)

    checks.append(
        _check(
            "adversary_graph_tokens",
            all(token in adversary_src for token in ["posterior", "determin", "evidence"]),
            "expects posterior/deterministic/evidence markers",
        )
    )

    missing_graph_exports = [name for name in REQUIRED_GRAPH_EXPORTS if re.search(rf"\b{re.escape(name)}\b", adversary_src) is None]
    checks.append(
        _check(
            "adversary_graph_exports_for_controller",
            len(missing_graph_exports) == 0,
            f"missing={missing_graph_exports}",
        )
    )

    graph_methods_called = _extract_graph_method_calls(quarantine_src)
    missing_graph_methods = [name for name in graph_methods_called if not _has_pub_fn(adversary_src, name)]
    checks.append(
        _check(
            "graph_method_contract_compat",
            len(missing_graph_methods) == 0,
            f"called={graph_methods_called} missing={missing_graph_methods}",
        )
    )

    graph_new_call_args = _extract_graph_new_call_args(quarantine_src)
    graph_new_signature = _extract_graph_new_signature(adversary_src)
    if graph_new_call_args is None or graph_new_signature is None:
        checks.append(
            _check(
                "graph_new_constructor_compat",
                False,
                f"call={graph_new_call_args} signature={graph_new_signature}",
            )
        )
    else:
        call_has_args = graph_new_call_args != ""
        signature_has_args = graph_new_signature != ""
        constructor_compat = (call_has_args and signature_has_args) or (not call_has_args)
        checks.append(
            _check(
                "graph_new_constructor_compat",
                constructor_compat,
                f"call_args='{graph_new_call_args}' signature='{graph_new_signature}'",
            )
        )

    action_token_hits = [token for token in REQUIRED_ACTION_TOKENS if token in quarantine_src]
    checks.append(
        _check(
            "quarantine_action_tokens",
            len(action_token_hits) == len(REQUIRED_ACTION_TOKENS),
            f"found={action_token_hits}",
        )
    )

    checks.append(
        _check(
            "quarantine_signed_evidence_tokens",
            "sign" in quarantine_src and "evidence" in quarantine_src,
            "expects signed evidence markers in quarantine controller",
        )
    )

    checks.append(
        _check(
            "integration_test_determinism_markers",
            "determin" in integration_src and "quarantine" in integration_src,
            "expects deterministic quarantine integration assertions",
        )
    )

    fallback_signals = ["Bayesian", "threshold", "quarantine", "propensity"]
    fallback_hits = [token for token in fallback_signals if token.lower() in fallback_src.lower()]
    checks.append(
        _check(
            "fallback_signal_surface_present",
            len(fallback_hits) >= 3,
            f"hits={fallback_hits}",
        )
    )

    state_payload = _load_json(ADVERSARY_GRAPH_STATE_FILE)
    checks.append(_check("adversary_graph_state_parseable", state_payload is not None, "json parse ok" if state_payload is not None else "missing or invalid json"))

    if isinstance(state_payload, dict):
        keys = set(state_payload.keys())
        expected_state_keys = {"schema_version", "generated_at", "posteriors", "actions"}
        missing_state_keys = sorted(expected_state_keys.difference(keys))
        checks.append(_check("adversary_graph_state_schema", len(missing_state_keys) == 0, f"missing={missing_state_keys}"))

    evidence_payload = _load_json(VERIFICATION_EVIDENCE_FILE)
    checks.append(_check("verification_evidence_parseable", isinstance(evidence_payload, dict), "json parse ok" if isinstance(evidence_payload, dict) else "missing or invalid json"))

    if isinstance(evidence_payload, dict):
        checks.append(_check("verification_evidence_status", _evidence_pass(evidence_payload), f"status={evidence_payload.get('status')} verdict={evidence_payload.get('verdict')}"))

    checks.append(
        _check(
            "verification_summary_present",
            VERIFICATION_SUMMARY_FILE.is_file() and len(summary_src.strip()) > 0,
            str(VERIFICATION_SUMMARY_FILE.relative_to(ROOT)),
        )
    )

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "schema_version": "bd-274s-support-v1",
        "bead_id": BEAD,
        "section": SECTION,
        "title": TITLE,
        "verdict": verdict,
        "status": verdict.lower(),
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "metrics": {
            "dependency_count": len(dep_map),
            "dependent_count": len(dependent_ids),
            "required_file_count": len(required_files),
            "required_files_missing": len(missing_required),
            "fallback_signal_hits": len(fallback_hits),
            "graph_export_missing_count": len(missing_graph_exports),
            "graph_method_missing_count": len(missing_graph_methods),
        },
    }


def write_report(result: dict[str, Any]) -> None:
    SUPPORT_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUPPORT_REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(_check("constants_bead", BEAD == "bd-274s"))
    checks.append(_check("constants_section", SECTION == "10.17"))
    checks.append(_check("action_token_count", len(REQUIRED_ACTION_TOKENS) == 4))

    sample = {
        "module_path": "x",
        "status": "pass",
    }
    checks.append(_check("evidence_pass_helper", _evidence_pass(sample)))

    run = run_all()
    checks.append(_check("run_all_has_checks", isinstance(run.get("checks"), list)))
    checks.append(_check("run_all_has_verdict", run.get("verdict") in {"PASS", "FAIL"}))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed

    return {
        "name": "check_bd_274s_bayesian_quarantine",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": "PASS" if failed == 0 else "FAIL",
    }


def main() -> None:
    logger = configure_test_logging("check_bd_274s_bayesian_quarantine")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{BEAD}: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
