#!/usr/bin/env python3
"""Checker for bd-1z5a.3 operator E2E replay/quarantine/scoreboard bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


BEAD = "bd-1z5a.3"
PARENT_BEAD = "bd-1z5a"
HARNESS = ROOT / "tests" / "e2e" / "verifier_replay_operator_suite.sh"
SUMMARY_JSON = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD / "operator_e2e_summary.json"
BUNDLE_JSON = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD / "operator_e2e_bundle.json"
LOG_JSONL = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD / "operator_e2e_log.jsonl"
SUMMARY_MD = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD / "operator_e2e_summary.md"

REQUIRED_STAGE_IDS = [
    "capsule_verify_success",
    "capsule_verify_reject_tampered",
    "capsule_verify_fraud_proof",
    "capsule_verify_quarantine_replay",
    "verifier_score_update",
]

REQUIRED_EVENT_CODES = {
    "CAPSULE_VERIFY_PASSED",
    "CAPSULE_VERIFY_REJECTED",
    "CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED",
    "CAPSULE_VERIFY_QUARANTINE_REPLAYED",
    "VERIFIER_SCORE_UPDATED",
}

REQUIRED_OPERATOR_FIELDS = [
    "trace_id",
    "capsule_id",
    "verifier_id",
    "claim_id",
    "commitment_digest",
    "decision",
    "reason_code",
    "fraud_proof_id",
]


def check_file(path: Path, check_id: str, label: str) -> dict[str, Any]:
    exists = path.is_file()
    rel = path.relative_to(ROOT) if exists else path
    return {
        "check": label,
        "id": check_id,
        "pass": exists,
        "detail": f"exists: {rel}" if exists else f"missing: {rel}",
    }


def load_json(path: Path) -> tuple[bool, Any]:
    if not path.is_file():
        return False, None
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, None


def load_jsonl(path: Path) -> tuple[bool, list[dict[str, Any]]]:
    if not path.is_file():
        return False, []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            return False, []
    return True, rows


def evaluate(summary: dict[str, Any], bundle: dict[str, Any], logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    stage_results = bundle.get("stage_results")
    if not isinstance(stage_results, list):
        stage_results = []

    stage_ids = [row.get("stage_id") for row in stage_results if isinstance(row, dict)]
    missing_stage_ids = [sid for sid in REQUIRED_STAGE_IDS if sid not in stage_ids]
    checks.append(
        {
            "check": "required operator stage ids present",
            "id": "OP-E2E-STAGES",
            "pass": not missing_stage_ids,
            "detail": "ok" if not missing_stage_ids else ",".join(missing_stage_ids),
        }
    )

    stage_pass = all(isinstance(row, dict) and row.get("status") == "pass" for row in stage_results)
    checks.append(
        {
            "check": "all operator stages passed",
            "id": "OP-E2E-STAGE-STATUS",
            "pass": stage_pass and len(stage_results) >= len(REQUIRED_STAGE_IDS),
            "detail": f"count={len(stage_results)}",
        }
    )

    operator_logs = [
        row for row in logs
        if isinstance(row, dict)
        and (str(row.get("event_code", "")).startswith("CAPSULE_VERIFY_")
             or str(row.get("event_code", "")).startswith("VERIFIER_SCORE_"))
    ]
    event_codes = {str(row.get("event_code", "")) for row in operator_logs}
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - event_codes)
    checks.append(
        {
            "check": "required CAPSULE_VERIFY_* and VERIFIER_SCORE_* events present",
            "id": "OP-E2E-EVENTS",
            "pass": not missing_event_codes,
            "detail": "ok" if not missing_event_codes else ",".join(missing_event_codes),
        }
    )

    missing_field_refs: list[str] = []
    for row in operator_logs:
        for field in REQUIRED_OPERATOR_FIELDS:
            if field not in row:
                missing_field_refs.append(f"{row.get('event_code','?')}:{field}")
    checks.append(
        {
            "check": "operator events expose required fields",
            "id": "OP-E2E-FIELDS",
            "pass": not missing_field_refs,
            "detail": "ok" if not missing_field_refs else ";".join(missing_field_refs[:8]),
        }
    )

    trace_ids = {str(row.get("trace_id", "")) for row in operator_logs}
    checks.append(
        {
            "check": "operator events share one trace_id",
            "id": "OP-E2E-TRACE",
            "pass": len(trace_ids) == 1,
            "detail": f"trace_ids={sorted(trace_ids)}",
        }
    )

    summary_ok = (
        summary.get("bead_id") == BEAD
        and summary.get("parent_bead") == PARENT_BEAD
        and summary.get("verdict") == "PASS"
    )
    checks.append(
        {
            "check": "summary metadata and verdict are correct",
            "id": "OP-E2E-SUMMARY",
            "pass": summary_ok,
            "detail": json.dumps(
                {
                    "bead_id": summary.get("bead_id"),
                    "parent_bead": summary.get("parent_bead"),
                    "verdict": summary.get("verdict"),
                },
                sort_keys=True,
            ),
        }
    )

    stage_artifacts_missing: list[str] = []
    for row in stage_results:
        if not isinstance(row, dict):
            stage_artifacts_missing.append("<non-object-stage-result>")
            continue
        for key in ("stdout_path", "stderr_path"):
            rel = row.get(key)
            if not isinstance(rel, str) or not (ROOT / rel).is_file():
                stage_artifacts_missing.append(f"{row.get('stage_id','?')}:{key}")
    checks.append(
        {
            "check": "stage stdout/stderr artifacts exist",
            "id": "OP-E2E-ARTIFACTS",
            "pass": not stage_artifacts_missing,
            "detail": "ok" if not stage_artifacts_missing else ";".join(stage_artifacts_missing[:8]),
        }
    )

    replay_inputs = bundle.get("replay_inputs")
    replay_inputs_ok = isinstance(replay_inputs, list) and len(replay_inputs) >= 6
    missing_inputs: list[str] = []
    if replay_inputs_ok:
        for rel in replay_inputs:
            if not isinstance(rel, str) or not (ROOT / rel).exists():
                replay_inputs_ok = False
                missing_inputs.append(str(rel))
    checks.append(
        {
            "check": "bundle replay inputs exist",
            "id": "OP-E2E-INPUTS",
            "pass": replay_inputs_ok,
            "detail": "ok" if replay_inputs_ok else ";".join(missing_inputs[:8]),
        }
    )

    build_ids = summary.get("build_ids")
    checks.append(
        {
            "check": "summary exposes build_ids list",
            "id": "OP-E2E-BUILD-IDS",
            "pass": isinstance(build_ids, list),
            "detail": json.dumps(build_ids),
        }
    )

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(HARNESS, "OP-E2E-HARNESS", "operator harness exists"))
    checks.append(check_file(SUMMARY_JSON, "OP-E2E-SUMMARY-FILE", "summary json exists"))
    checks.append(check_file(BUNDLE_JSON, "OP-E2E-BUNDLE-FILE", "bundle json exists"))
    checks.append(check_file(LOG_JSONL, "OP-E2E-LOG-FILE", "structured log exists"))
    checks.append(check_file(SUMMARY_MD, "OP-E2E-SUMMARY-MD", "summary markdown exists"))

    summary_ok, summary = load_json(SUMMARY_JSON)
    bundle_ok, bundle = load_json(BUNDLE_JSON)
    logs_ok, logs = load_jsonl(LOG_JSONL)

    checks.append(
        {
            "check": "summary json parses",
            "id": "OP-E2E-SUMMARY-PARSE",
            "pass": summary_ok,
            "detail": "valid" if summary_ok else "invalid/missing",
        }
    )
    checks.append(
        {
            "check": "bundle json parses",
            "id": "OP-E2E-BUNDLE-PARSE",
            "pass": bundle_ok,
            "detail": "valid" if bundle_ok else "invalid/missing",
        }
    )
    checks.append(
        {
            "check": "log jsonl parses",
            "id": "OP-E2E-LOG-PARSE",
            "pass": logs_ok,
            "detail": f"rows={len(logs)}" if logs_ok else "invalid/missing",
        }
    )

    if summary_ok and bundle_ok and logs_ok:
        checks.extend(evaluate(summary, bundle, logs))

    passed = sum(1 for check in checks if check["pass"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": BEAD,
        "parent_bead": PARENT_BEAD,
        "title": "Operator E2E replay/quarantine/scoreboard bundle",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def self_test() -> dict[str, Any]:
    result = run_checks()
    checks = [
        {
            "check": "required stage count is 5",
            "passed": len(REQUIRED_STAGE_IDS) == 5,
            "detail": str(len(REQUIRED_STAGE_IDS)),
        },
        {
            "check": "required event coverage count is 5",
            "passed": len(REQUIRED_EVENT_CODES) == 5,
            "detail": str(len(REQUIRED_EVENT_CODES)),
        },
        {
            "check": "run_checks returns bead_id",
            "passed": result.get("bead_id") == BEAD,
            "detail": str(result.get("bead_id")),
        },
        {
            "check": "run_checks returns checks list",
            "passed": isinstance(result.get("checks"), list),
            "detail": type(result.get("checks")).__name__,
        },
        {
            "check": "run_checks verdict is PASS or FAIL",
            "passed": result.get("verdict") in {"PASS", "FAIL"},
            "detail": str(result.get("verdict")),
        },
    ]
    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "name": "check_verifier_replay_operator_e2e",
        "bead_id": BEAD,
        "verdict": verdict,
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def main() -> None:
    configure_test_logging("check_verifier_replay_operator_e2e")
    parser = argparse.ArgumentParser(description="bd-1z5a.3 operator E2E checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    payload = self_test() if args.self_test else run_checks()
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{payload['bead_id']}: {payload['verdict']} "
            f"({payload['passed']}/{payload['total'] if 'total' in payload else payload['passed'] + payload['failed']})"
        )
        for check in payload["checks"]:
            mark = "+" if check.get("pass", check.get("passed")) else "x"
            print(f"[{mark}] {check['check']}: {check['detail']}")
    if args.self_test:
        raise SystemExit(0 if payload["verdict"] == "PASS" else 1)
    raise SystemExit(0 if payload["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
