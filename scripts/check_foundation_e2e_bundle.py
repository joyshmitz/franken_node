#!/usr/bin/env python3
"""bd-3k9t verifier: foundation E2E suite bundle + structured logs."""

from __future__ import annotations

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


HARNESS = ROOT / "tests" / "e2e" / "foundation_bootstrap_suite.sh"
SUMMARY_JSON = ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "foundation_e2e_summary.json"
BUNDLE_JSON = ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "foundation_e2e_bundle.json"
LOG_JSONL = ROOT / "artifacts" / "section_bootstrap" / "bd-3k9t" / "foundation_e2e_log.jsonl"

REQUIRED_STAGE_IDS = [
    "run_surface_contract",
    "config_profile_resolution",
    "init_profile_bootstrap",
    "doctor_command_diagnostics",
    "transplant_verify_missing_snapshot",
    "transplant_drift_probe_missing_snapshot",
]

REQUIRED_EVENT_CODES = {
    "FB-E2E-001",
    "FB-E2E-010",
    "FB-E2E-020",
    "FB-E2E-099",
}


def check_file(path: Path, check_id: str, label: str) -> dict[str, Any]:
    ok = path.is_file()
    rel = path.relative_to(ROOT) if ok else path
    return {
        "id": check_id,
        "check": label,
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"missing: {rel}",
    }


def _load_json(path: Path) -> tuple[bool, Any]:
    if not path.is_file():
        return False, None
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, None


def _load_jsonl(path: Path) -> tuple[bool, list[dict[str, Any]]]:
    if not path.is_file():
        return False, []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            return False, []
    return True, rows


def _evaluate(summary: dict[str, Any], bundle: dict[str, Any], logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    stage_results = bundle.get("stage_results")
    if not isinstance(stage_results, list):
        stage_results = []

    stage_ids = [row.get("stage_id") for row in stage_results if isinstance(row, dict)]
    missing_stage_ids = [sid for sid in REQUIRED_STAGE_IDS if sid not in stage_ids]

    checks.append(
        {
            "id": "FBE2E-BEAD-ID",
            "check": "summary bead_id is bd-3k9t",
            "pass": summary.get("bead_id") == "bd-3k9t",
            "detail": str(summary.get("bead_id")),
        }
    )
    checks.append(
        {
            "id": "FBE2E-VERDICT",
            "check": "summary verdict is PASS",
            "pass": summary.get("verdict") == "PASS",
            "detail": str(summary.get("verdict")),
        }
    )
    checks.append(
        {
            "id": "FBE2E-STAGE-COUNT",
            "check": "bundle has >= 6 stage results",
            "pass": len(stage_results) >= 6,
            "detail": f"count={len(stage_results)}",
        }
    )
    checks.append(
        {
            "id": "FBE2E-REQUIRED-STAGES",
            "check": "required stage ids present",
            "pass": len(missing_stage_ids) == 0,
            "detail": "ok" if not missing_stage_ids else ",".join(missing_stage_ids),
        }
    )

    coverage = summary.get("coverage", {})
    clean = int(coverage.get("clean", 0)) if isinstance(coverage, dict) else 0
    degraded = int(coverage.get("degraded", 0)) if isinstance(coverage, dict) else 0
    drifted = int(coverage.get("drifted", 0)) if isinstance(coverage, dict) else 0
    checks.append(
        {
            "id": "FBE2E-COVERAGE",
            "check": "clean/degraded/drifted coverage each >= 1",
            "pass": clean >= 1 and degraded >= 1 and drifted >= 1,
            "detail": f"clean={clean},degraded={degraded},drifted={drifted}",
        }
    )

    event_codes = {row.get("event_code") for row in logs if isinstance(row, dict)}
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - event_codes)
    checks.append(
        {
            "id": "FBE2E-EVENT-CODES",
            "check": "required stable event codes present",
            "pass": not missing_event_codes,
            "detail": "ok" if not missing_event_codes else ",".join(missing_event_codes),
        }
    )

    trace_ids = {row.get("trace_id") for row in logs if isinstance(row, dict)}
    checks.append(
        {
            "id": "FBE2E-TRACE-ID",
            "check": "structured logs use a single trace correlation id",
            "pass": len(trace_ids) == 1,
            "detail": f"trace_ids={sorted([str(t) for t in trace_ids])}",
        }
    )

    stage_paths_ok = True
    missing_paths = []
    for row in stage_results:
        if not isinstance(row, dict):
            stage_paths_ok = False
            missing_paths.append("<non-object-stage-row>")
            continue
        stdout_rel = row.get("stdout_path")
        stderr_rel = row.get("stderr_path")
        if not isinstance(stdout_rel, str) or not isinstance(stderr_rel, str):
            stage_paths_ok = False
            missing_paths.append(f"{row.get('stage_id')}:missing-path-fields")
            continue
        stdout_path = ROOT / stdout_rel
        stderr_path = ROOT / stderr_rel
        if not stdout_path.is_file():
            stage_paths_ok = False
            missing_paths.append(str(stdout_rel))
        if not stderr_path.is_file():
            stage_paths_ok = False
            missing_paths.append(str(stderr_rel))
    checks.append(
        {
            "id": "FBE2E-STAGE-ARTIFACTS",
            "check": "all stage stdout/stderr artifacts exist",
            "pass": stage_paths_ok,
            "detail": "ok" if stage_paths_ok else ";".join(missing_paths[:8]),
        }
    )

    replay_inputs = bundle.get("replay_inputs")
    replay_ok = isinstance(replay_inputs, list) and len(replay_inputs) >= 5
    missing_replay = []
    if replay_ok:
        for rel in replay_inputs:
            if not isinstance(rel, str):
                replay_ok = False
                missing_replay.append("<non-string-replay-input>")
                continue
            if not (ROOT / rel).exists():
                replay_ok = False
                missing_replay.append(rel)
    checks.append(
        {
            "id": "FBE2E-REPLAY-INPUTS",
            "check": "bundle replay inputs exist",
            "pass": replay_ok,
            "detail": "ok" if replay_ok else ";".join(missing_replay[:8]),
        }
    )

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(HARNESS, "FBE2E-FILE-HARNESS", "foundation harness script exists"))
    checks.append(check_file(SUMMARY_JSON, "FBE2E-FILE-SUMMARY", "summary json exists"))
    checks.append(check_file(BUNDLE_JSON, "FBE2E-FILE-BUNDLE", "bundle json exists"))
    checks.append(check_file(LOG_JSONL, "FBE2E-FILE-LOG", "jsonl log exists"))

    summary_ok, summary = _load_json(SUMMARY_JSON)
    bundle_ok, bundle = _load_json(BUNDLE_JSON)
    log_ok, logs = _load_jsonl(LOG_JSONL)

    checks.append(
        {
            "id": "FBE2E-SUMMARY-JSON",
            "check": "summary json parses",
            "pass": summary_ok,
            "detail": "valid" if summary_ok else "invalid/missing",
        }
    )
    checks.append(
        {
            "id": "FBE2E-BUNDLE-JSON",
            "check": "bundle json parses",
            "pass": bundle_ok,
            "detail": "valid" if bundle_ok else "invalid/missing",
        }
    )
    checks.append(
        {
            "id": "FBE2E-LOG-JSONL",
            "check": "jsonl log parses",
            "pass": log_ok,
            "detail": f"rows={len(logs)}" if log_ok else "invalid/missing",
        }
    )

    if summary_ok and bundle_ok and log_ok:
        checks.extend(_evaluate(summary, bundle, logs))

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead": "bd-3k9t",
        "title": "Foundation e2e scripts with structured log bundles",
        "section": "bootstrap",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test() -> None:
    summary = {
        "bead_id": "bd-3k9t",
        "verdict": "PASS",
        "coverage": {"clean": 4, "degraded": 1, "drifted": 1},
    }
    bundle = {
        "stage_results": [
            {"stage_id": sid, "stdout_path": "tests/e2e/foundation_bootstrap_suite.sh", "stderr_path": "tests/e2e/foundation_bootstrap_suite.sh"}
            for sid in REQUIRED_STAGE_IDS
        ],
        "replay_inputs": [
            "artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json",
            "artifacts/section_bootstrap/bd-32e/init_snapshots.json",
            "artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json",
            "transplant/TRANSPLANT_LOCKFILE.sha256",
            "transplant/transplant_manifest.txt",
        ],
    }
    logs = [
        {"event_code": "FB-E2E-001", "trace_id": "trace-self-test"},
        {"event_code": "FB-E2E-010", "trace_id": "trace-self-test"},
        {"event_code": "FB-E2E-020", "trace_id": "trace-self-test"},
        {"event_code": "FB-E2E-099", "trace_id": "trace-self-test"},
    ]
    checks = _evaluate(summary, bundle, logs)
    assert all(c["pass"] for c in checks), "self-test evaluate should pass"
    print(f"self_test passed: {len(checks)} checks")


def main() -> int:
    logger = configure_test_logging("check_foundation_e2e_bundle")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    report = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-3k9t verdict: {report['verdict']}")
        print(
            f"checks: {report['summary']['passing_checks']}/"
            f"{report['summary']['total_checks']} passed"
        )
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
