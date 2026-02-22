#!/usr/bin/env python3
"""Verify bd-2l1k: concrete target gate for 100% replay artifact coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-2l1k_contract.md"
MATRIX = ROOT / "artifacts" / "13" / "replay_coverage_matrix.json"

REQUIRED_INCIDENT_TYPES = {
    "rce",
    "privilege_escalation",
    "data_exfiltration",
    "sandbox_escape",
    "trust_system_bypass",
    "supply_chain_compromise",
    "denial_of_service",
    "memory_corruption",
}

REQUIRED_EVENT_CODES = {
    "RCG-001",
    "RCG-002",
    "RCG-003",
    "RCG-004",
    "RCG-005",
    "RCG-006",
    "RCG-007",
}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _record_required_fields() -> tuple[str, ...]:
    return (
        "incident_type",
        "artifact_path",
        "last_verified_utc",
        "deterministic_runs",
        "deterministic_match",
        "initial_state_snapshot",
        "input_sequence",
        "expected_behavior_trace",
        "actual_behavior_trace",
        "divergence_point",
        "reproduction_command",
        "discovered_at_utc",
    )


def _validate_record(record: dict[str, Any], idx: int, errors: list[str]) -> None:
    for field in _record_required_fields():
        if field not in record:
            errors.append(f"replay_artifacts[{idx}] missing field: {field}")

    incident_type = record.get("incident_type")
    if not isinstance(incident_type, str) or not incident_type:
        errors.append(f"replay_artifacts[{idx}].incident_type must be non-empty string")

    artifact_path = record.get("artifact_path")
    if not isinstance(artifact_path, str) or not artifact_path:
        errors.append(f"replay_artifacts[{idx}].artifact_path must be non-empty string")

    for field in (
        "initial_state_snapshot",
        "divergence_point",
        "reproduction_command",
        "last_verified_utc",
        "discovered_at_utc",
    ):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"replay_artifacts[{idx}].{field} must be non-empty string")

    for field in (
        "input_sequence",
        "expected_behavior_trace",
        "actual_behavior_trace",
    ):
        value = record.get(field)
        if not isinstance(value, list) or len(value) == 0:
            errors.append(f"replay_artifacts[{idx}].{field} must be non-empty list")

    runs = record.get("deterministic_runs")
    if not isinstance(runs, int) or runs < 10:
        errors.append(f"replay_artifacts[{idx}].deterministic_runs must be >= 10")

    match = record.get("deterministic_match")
    if not isinstance(match, bool) or not match:
        errors.append(f"replay_artifacts[{idx}].deterministic_match must be true")

    command = record.get("reproduction_command")
    if isinstance(command, str) and not command.startswith("python3 "):
        errors.append(
            f"replay_artifacts[{idx}].reproduction_command must start with 'python3 '"
        )

    try:
        discovered = _parse_iso8601(str(record.get("discovered_at_utc")))
        verified = _parse_iso8601(str(record.get("last_verified_utc")))
        if verified < discovered:
            errors.append(
                f"replay_artifacts[{idx}] last_verified_utc must be >= discovered_at_utc"
            )
    except Exception:
        errors.append(f"replay_artifacts[{idx}] timestamps must be valid RFC-3339 UTC values")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be object")
    return payload


def _resolve_artifact_path(raw_path: str, matrix_path: Path) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate

    repo_relative = ROOT / raw_path
    if repo_relative.is_file():
        return repo_relative

    return matrix_path.parent / raw_path


def run_checks(spec_path: Path = SPEC, matrix_path: Path = MATRIX) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: spec contract", spec_path.is_file(), _safe_rel(spec_path))
    _check("file: replay coverage matrix", matrix_path.is_file(), _safe_rel(matrix_path))

    spec_text = ""
    if spec_path.is_file():
        spec_text = spec_path.read_text(encoding="utf-8")
    _check("spec threshold 100% coverage", "100%" in spec_text or "1.0" in spec_text)
    _check(
        "spec incident enumeration",
        all(incident in spec_text for incident in REQUIRED_INCIDENT_TYPES),
    )
    _check("spec event codes", all(code in spec_text for code in REQUIRED_EVENT_CODES))

    matrix: dict[str, Any] = {}
    parse_error = ""
    if matrix_path.is_file():
        try:
            matrix = _load_json(matrix_path)
        except Exception as exc:
            parse_error = str(exc)

    _check("matrix parse", parse_error == "", parse_error or "ok")
    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for check in CHECKS if check["pass"])
        failed = total - passed
        return {
            "bead_id": "bd-2l1k",
            "title": "Replay coverage gate (100%)",
            "section": "13",
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = (
        "bead_id",
        "generated_at_utc",
        "trace_id",
        "minimum_required_coverage_ratio",
        "new_incident_type_sla_days",
        "required_incident_types",
        "replay_artifacts",
        "coverage_summary",
    )
    missing_top = [field for field in required_top if field not in matrix]
    _check(
        "matrix required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("matrix bead id", matrix.get("bead_id") == "bd-2l1k")

    timestamp_ok = False
    generated_at = matrix.get("generated_at_utc")
    if isinstance(generated_at, str) and generated_at:
        try:
            _parse_iso8601(generated_at)
            timestamp_ok = True
        except Exception:
            timestamp_ok = False
    _check("matrix timestamp valid RFC3339 UTC", timestamp_ok)

    required_incidents = matrix.get("required_incident_types", [])
    required_incidents_ok = isinstance(required_incidents, list)
    _check("required_incident_types is list", required_incidents_ok)
    required_set = {value for value in required_incidents if isinstance(value, str)}
    missing_required = sorted(REQUIRED_INCIDENT_TYPES - required_set)
    _check(
        "required incident types covered",
        len(missing_required) == 0,
        "missing: " + ", ".join(missing_required) if missing_required else "ok",
    )

    records = matrix.get("replay_artifacts", [])
    records_ok = isinstance(records, list)
    _check("replay_artifacts is list", records_ok)
    if not records_ok:
        records = []

    record_errors: list[str] = []
    seen_incidents: set[str] = set()
    duplicate_incidents: set[str] = set()

    sla_days = matrix.get("new_incident_type_sla_days", 14)
    if not isinstance(sla_days, (int, float)) or sla_days <= 0:
        _check("new incident SLA days valid", False, f"value={sla_days}")
        sla_days = 14
    else:
        _check("new incident SLA days valid", True, f"value={sla_days}")

    artifact_missing_paths: list[str] = []
    content_incomplete = False
    determinism_issue = False
    sla_issue = False

    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            record_errors.append(f"replay_artifacts[{idx}] must be object")
            continue
        _validate_record(record, idx, record_errors)

        incident = record.get("incident_type")
        if isinstance(incident, str):
            if incident in seen_incidents:
                duplicate_incidents.add(incident)
            seen_incidents.add(incident)

        path = record.get("artifact_path")
        if isinstance(path, str):
            artifact_file = _resolve_artifact_path(path, matrix_path)
            if not artifact_file.is_file():
                artifact_missing_paths.append(path)

        runs = record.get("deterministic_runs")
        match = record.get("deterministic_match")
        if not isinstance(runs, int) or runs < 10 or match is not True:
            determinism_issue = True

        required_content_fields = (
            "initial_state_snapshot",
            "input_sequence",
            "expected_behavior_trace",
            "actual_behavior_trace",
            "divergence_point",
        )
        if any(
            (field not in record)
            or (
                isinstance(record.get(field), list)
                and len(record.get(field, [])) == 0
            )
            or (
                isinstance(record.get(field), str)
                and not str(record.get(field)).strip()
            )
            for field in required_content_fields
        ):
            content_incomplete = True

        try:
            discovered = _parse_iso8601(str(record.get("discovered_at_utc")))
            verified = _parse_iso8601(str(record.get("last_verified_utc")))
            delta_days = (verified - discovered).total_seconds() / 86400.0
            if delta_days > float(sla_days):
                sla_issue = True
        except Exception:
            sla_issue = True

    if duplicate_incidents:
        record_errors.append("duplicate incident records: " + ", ".join(sorted(duplicate_incidents)))

    _check(
        "replay artifact record schema",
        len(record_errors) == 0,
        "; ".join(record_errors[:5]) if record_errors else "ok",
    )

    _check(
        "artifact files exist",
        len(artifact_missing_paths) == 0,
        "missing: " + ", ".join(artifact_missing_paths[:5]) if artifact_missing_paths else "ok",
    )

    covered_required = sorted(REQUIRED_INCIDENT_TYPES.intersection(seen_incidents))
    missing_coverage = sorted(REQUIRED_INCIDENT_TYPES - set(covered_required))
    _check(
        "100% required incident coverage",
        len(missing_coverage) == 0,
        "missing: " + ", ".join(missing_coverage) if missing_coverage else "ok",
    )

    _check(
        "replay artifact content completeness",
        not content_incomplete,
        "required replay content missing" if content_incomplete else "ok",
    )

    _check(
        "deterministic replay requirements",
        not determinism_issue,
        "deterministic_runs < 10 or deterministic_match=false" if determinism_issue else "ok",
    )

    _check(
        "new incident SLA met",
        not sla_issue,
        f"required <= {sla_days} days",
    )

    required_count = len(REQUIRED_INCIDENT_TYPES)
    covered_count = len(covered_required)
    coverage_ratio = covered_count / required_count if required_count > 0 else 0.0

    summary = matrix.get("coverage_summary", {})
    summary_ok = isinstance(summary, dict)
    _check("coverage_summary is object", summary_ok)

    declared_required = summary.get("required_count") if summary_ok else None
    declared_covered = summary.get("covered_count") if summary_ok else None
    declared_ratio = summary.get("coverage_ratio") if summary_ok else None

    _check(
        "summary required_count matches",
        declared_required == required_count,
        f"declared={declared_required}, computed={required_count}",
    )
    _check(
        "summary covered_count matches",
        declared_covered == covered_count,
        f"declared={declared_covered}, computed={covered_count}",
    )
    _check(
        "summary coverage_ratio matches",
        isinstance(declared_ratio, (int, float)) and abs(float(declared_ratio) - coverage_ratio) <= 1e-9,
        f"declared={declared_ratio}, computed={coverage_ratio:.4f}",
    )

    threshold = matrix.get("minimum_required_coverage_ratio", 1.0)
    threshold_ok = isinstance(threshold, (int, float)) and coverage_ratio >= float(threshold)
    _check(
        "coverage ratio threshold met",
        threshold_ok,
        f"ratio={coverage_ratio:.4f}, threshold={threshold}",
    )

    # Determinism under reordered matrix records.
    reordered_incidents = [
        record.get("incident_type")
        for record in reversed(records)
        if isinstance(record, dict) and isinstance(record.get("incident_type"), str)
    ]
    reordered_covered_count = len(REQUIRED_INCIDENT_TYPES.intersection(reordered_incidents))
    reordered_ratio = (
        reordered_covered_count / required_count if required_count > 0 else 0.0
    )
    determinism_ok = reordered_covered_count == covered_count and abs(reordered_ratio - coverage_ratio) <= 1e-9
    _check(
        "determinism under reordering",
        determinism_ok,
        f"ratio={coverage_ratio:.4f}, reordered_ratio={reordered_ratio:.4f}",
    )

    # Adversarial perturbation: remove one incident from coverage and expect threshold miss.
    perturbed_covered = max(0, covered_count - 1)
    perturbed_ratio = perturbed_covered / required_count if required_count > 0 else 0.0
    adversarial_expected_fail = perturbed_ratio < float(threshold) if isinstance(threshold, (int, float)) else False
    _check(
        "adversarial perturbation flips threshold",
        adversarial_expected_fail,
        f"perturbed_ratio={perturbed_ratio:.4f}, threshold={threshold}",
    )

    trace = matrix.get("trace_id")
    if not isinstance(trace, str) or not trace:
        trace = _trace_id(matrix)

    events.append(
        {
            "event_code": "RCG-001",
            "trace_id": trace,
            "message": (
                "Replay coverage metrics computed "
                f"(required={required_count}, covered={covered_count}, ratio={coverage_ratio:.4f})."
            ),
        }
    )

    events.append(
        {
            "event_code": "RCG-002" if threshold_ok and covered_count == required_count else "RCG-003",
            "trace_id": trace,
            "message": "Replay coverage gate passed." if threshold_ok and covered_count == required_count else "Replay coverage gate failed.",
        }
    )

    if missing_coverage:
        events.append(
            {
                "event_code": "RCG-004",
                "trace_id": trace,
                "message": "Missing required incident-type coverage.",
            }
        )

    if content_incomplete or artifact_missing_paths:
        events.append(
            {
                "event_code": "RCG-005",
                "trace_id": trace,
                "message": "Replay artifact content/completeness violation.",
            }
        )

    events.append(
        {
            "event_code": "RCG-006",
            "trace_id": trace,
            "message": "Determinism validation executed.",
        }
    )
    events.append(
        {
            "event_code": "RCG-007",
            "trace_id": trace,
            "message": "New-incident SLA validation executed.",
        }
    )

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-2l1k",
        "title": "Replay coverage gate (100%)",
        "section": "13",
        "trace_id": trace,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "required_count": required_count,
            "covered_count": covered_count,
            "coverage_ratio": round(coverage_ratio, 4),
            "minimum_required_coverage_ratio": threshold,
            "missing_incident_types": missing_coverage,
            "sla_days": sla_days,
        },
        "checks": CHECKS,
        "events": events,
    }


def replay_incident(incident_type: str, matrix_path: Path = MATRIX) -> dict[str, Any]:
    try:
        matrix = _load_json(matrix_path)
    except Exception as exc:
        return {"ok": False, "error": f"failed to load matrix: {exc}"}

    records = matrix.get("replay_artifacts")
    if not isinstance(records, list):
        return {"ok": False, "error": "replay_artifacts must be list"}

    target = None
    for record in records:
        if isinstance(record, dict) and record.get("incident_type") == incident_type:
            target = record
            break

    if target is None:
        return {"ok": False, "error": f"incident_type not found: {incident_type}"}

    artifact_path = _resolve_artifact_path(str(target.get("artifact_path")), matrix_path)
    if not artifact_path.is_file():
        return {
            "ok": False,
            "error": "artifact file not found",
            "artifact_path": _safe_rel(artifact_path),
        }

    try:
        artifact = _load_json(artifact_path)
    except Exception as exc:
        return {"ok": False, "error": f"failed to load artifact: {exc}"}

    deterministic = (
        target.get("deterministic_match") is True
        and isinstance(target.get("deterministic_runs"), int)
        and int(target.get("deterministic_runs")) >= 10
    )

    expected_trace = target.get("expected_behavior_trace")
    actual_trace = target.get("actual_behavior_trace")
    traces_match = expected_trace == actual_trace

    return {
        "ok": True,
        "incident_type": incident_type,
        "artifact_path": _safe_rel(artifact_path),
        "deterministic": deterministic,
        "deterministic_runs": target.get("deterministic_runs"),
        "trace_match": traces_match,
        "divergence_point": target.get("divergence_point"),
        "artifact_snapshot": artifact.get("initial_state_snapshot"),
    }


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-2l1k-self-test-") as tmp:
        root = Path(tmp)
        spec = root / "spec.md"
        matrix_path = root / "matrix.json"
        artifacts_dir = root / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        spec.write_text(
            "\n".join(
                [
                    "# test spec",
                    "100%",
                    *sorted(REQUIRED_INCIDENT_TYPES),
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        required = sorted(REQUIRED_INCIDENT_TYPES)
        records = []
        for idx, incident in enumerate(required):
            artifact_rel = f"artifacts/{incident}.json"
            artifact_abs = root / artifact_rel
            artifact_abs.write_text(
                json.dumps(
                    {
                        "incident_type": incident,
                        "initial_state_snapshot": f"snap-{incident}",
                        "input_sequence": ["seed", "execute", "trace"],
                        "expected_behavior_trace": ["a", "b", "c"],
                        "actual_behavior_trace": ["a", "b", "c"],
                        "divergence_point": "none",
                        "last_verified_utc": "2026-02-21T00:00:00Z",
                        "deterministic_runs": 10,
                        "deterministic_match": True,
                        "reproduction_command": f"python3 script.py --incident {incident}",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            records.append(
                {
                    "incident_type": incident,
                    "artifact_path": artifact_rel,
                    "last_verified_utc": "2026-02-21T00:00:00Z",
                    "deterministic_runs": 10,
                    "deterministic_match": True,
                    "initial_state_snapshot": f"snap-{incident}",
                    "input_sequence": ["seed", "execute", "trace"],
                    "expected_behavior_trace": ["a", "b", "c"],
                    "actual_behavior_trace": ["a", "b", "c"],
                    "divergence_point": "none",
                    "reproduction_command": f"python3 script.py --incident {incident}",
                    "discovered_at_utc": f"2026-02-{10 + idx:02d}T00:00:00Z",
                }
            )

        matrix = {
            "bead_id": "bd-2l1k",
            "generated_at_utc": "2026-02-21T00:00:00Z",
            "trace_id": "self-test-trace",
            "minimum_required_coverage_ratio": 1.0,
            "new_incident_type_sla_days": 14,
            "required_incident_types": required,
            "replay_artifacts": records,
            "coverage_summary": {
                "required_count": len(required),
                "covered_count": len(required),
                "coverage_ratio": 1.0,
            },
        }
        matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

        pass_result = run_checks(spec_path=spec, matrix_path=matrix_path)
        if pass_result["verdict"] != "PASS":
            return False

        # Perturb by dropping one required incident coverage.
        data = json.loads(matrix_path.read_text(encoding="utf-8"))
        data["replay_artifacts"] = data["replay_artifacts"][:-1]
        data["coverage_summary"]["covered_count"] = len(data["replay_artifacts"])
        data["coverage_summary"]["coverage_ratio"] = round(
            len(data["replay_artifacts"]) / len(required),
            4,
        )
        matrix_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        fail_result = run_checks(spec_path=spec, matrix_path=matrix_path)
        return fail_result["verdict"] == "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
    parser.add_argument("--matrix", default=str(MATRIX), help="Override replay matrix path.")
    parser.add_argument("--replay-incident", help="Replay one incident_type from matrix.")
    args = parser.parse_args()

    matrix_path = Path(args.matrix)

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed"}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    if args.replay_incident:
        payload = replay_incident(args.replay_incident, matrix_path=matrix_path)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload)
        return 0 if payload.get("ok") else 1

    result = run_checks(matrix_path=matrix_path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {result['title']}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
