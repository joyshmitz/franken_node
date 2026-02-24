#!/usr/bin/env python3
"""Validate Section 11 benchmark/correctness contract field (bd-3l8d)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

TEMPLATE_PATH = ROOT / "docs" / "templates" / "change_summary_template.md"
EXAMPLE_PATH = ROOT / "docs" / "change_summaries" / "example_change_summary.json"
DEFAULT_SUMMARY_DIR = ROOT / "docs" / "change_summaries"

REQUIRED_EVENT_CODES = {
    "CONTRACT_BENCH_CORRECT_VALIDATED",
    "CONTRACT_BENCH_CORRECT_MISSING",
    "CONTRACT_BENCH_CORRECT_INCOMPLETE",
}

SUBSYSTEM_PATH_PREFIXES = (
    "crates/franken-node/src/",
    "crates/franken-engine/src/",
    "crates/asupersync/src/",
    "services/",
)

ARTIFACT_PATH_PREFIX = "artifacts/section_"
DELTA_EPSILON = 1e-9


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_changed_files(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"changed-files list not found: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _discover_changed_files_from_git(project_root: Path) -> list[str]:
    commands = [
        ["git", "-C", str(project_root), "diff", "--name-only", "origin/main...HEAD"],
        ["git", "-C", str(project_root), "diff", "--name-only", "HEAD~1...HEAD"],
    ]
    last_error: Exception | None = None
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception as exc:  # pragma: no cover - defensive fallback
            last_error = exc
    raise RuntimeError(f"unable to discover changed files via git diff: {last_error}")


def _is_subsystem_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SUBSYSTEM_PATH_PREFIXES)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_non_empty_str(value: Any, field: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} must be a non-empty string")
        return ""
    return value.strip()


def _require_list(value: Any, field: str, errors: list[str], *, min_items: int = 0) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    if len(value) < min_items:
        errors.append(f"{field} must contain at least {min_items} item(s)")
    return value


def _validate_artifact_path(
    *,
    artifact_path: str,
    field: str,
    project_root: Path,
    errors: list[str],
) -> bool:
    if not artifact_path.startswith(ARTIFACT_PATH_PREFIX):
        errors.append(f"{field} must start with {ARTIFACT_PATH_PREFIX}")
        return False

    artifact_abs = project_root / artifact_path
    if not artifact_abs.is_file():
        errors.append(f"{field} does not exist: {artifact_path}")
        return False

    return True


def _validate_summary_file(summary_path: Path, project_root: Path) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    summary_rel = _rel(summary_path, project_root)
    if not summary_path.is_file():
        message = f"summary file listed in diff but missing on disk: {summary_rel}"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_BENCH_CORRECT_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in {summary_rel}: {exc}"
        trace = _trace_id({"summary_file": summary_rel, "error": str(exc)})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_BENCH_CORRECT_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    if not isinstance(payload, dict):
        message = f"{summary_rel} must contain a JSON object"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_BENCH_CORRECT_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    trace = _trace_id(payload)

    change_summary = payload.get("change_summary")
    if not isinstance(change_summary, dict):
        errors.append("change_summary must be an object")
        change_summary = {}

    bench_correct = change_summary.get("benchmark_and_correctness_artifacts")
    if not isinstance(bench_correct, dict):
        errors.append("change_summary.benchmark_and_correctness_artifacts must be an object")
        bench_correct = {}

    benchmark_metrics = _require_list(
        bench_correct.get("benchmark_metrics"),
        "change_summary.benchmark_and_correctness_artifacts.benchmark_metrics",
        errors,
        min_items=1,
    )
    validated_metric_count = 0
    for idx, metric in enumerate(benchmark_metrics):
        prefix = f"change_summary.benchmark_and_correctness_artifacts.benchmark_metrics[{idx}]"
        if not isinstance(metric, dict):
            errors.append(f"{prefix} must be an object")
            continue

        _require_non_empty_str(metric.get("metric_name"), f"{prefix}.metric_name", errors)
        _require_non_empty_str(metric.get("unit"), f"{prefix}.unit", errors)

        measured_value = metric.get("measured_value")
        baseline_value = metric.get("baseline_value")
        delta = metric.get("delta")

        if not _is_number(measured_value):
            errors.append(f"{prefix}.measured_value must be numeric")
        if not _is_number(baseline_value):
            errors.append(f"{prefix}.baseline_value must be numeric")
        if not _is_number(delta):
            errors.append(f"{prefix}.delta must be numeric")

        if _is_number(measured_value) and _is_number(baseline_value) and _is_number(delta):
            expected_delta = float(measured_value) - float(baseline_value)
            if abs(float(delta) - expected_delta) > DELTA_EPSILON:
                errors.append(
                    f"{prefix}.delta must equal measured_value - baseline_value "
                    f"(expected {expected_delta}, got {delta})"
                )

        within_bounds = metric.get("within_acceptable_bounds")
        if not isinstance(within_bounds, bool):
            errors.append(f"{prefix}.within_acceptable_bounds must be boolean")

        artifact_path = _require_non_empty_str(metric.get("artifact_path"), f"{prefix}.artifact_path", errors)
        if artifact_path:
            if _validate_artifact_path(
                artifact_path=artifact_path,
                field=f"{prefix}.artifact_path",
                project_root=project_root,
                errors=errors,
            ):
                validated_metric_count += 1

    correctness_suites = _require_list(
        bench_correct.get("correctness_suites"),
        "change_summary.benchmark_and_correctness_artifacts.correctness_suites",
        errors,
        min_items=1,
    )
    validated_suite_count = 0
    for idx, suite in enumerate(correctness_suites):
        prefix = f"change_summary.benchmark_and_correctness_artifacts.correctness_suites[{idx}]"
        if not isinstance(suite, dict):
            errors.append(f"{prefix} must be an object")
            continue

        _require_non_empty_str(suite.get("suite_name"), f"{prefix}.suite_name", errors)

        pass_count = suite.get("pass_count")
        fail_count = suite.get("fail_count")
        if not isinstance(pass_count, int) or isinstance(pass_count, bool) or pass_count < 0:
            errors.append(f"{prefix}.pass_count must be an integer >= 0")
        if not isinstance(fail_count, int) or isinstance(fail_count, bool) or fail_count < 0:
            errors.append(f"{prefix}.fail_count must be an integer >= 0")
        if (
            isinstance(pass_count, int)
            and not isinstance(pass_count, bool)
            and isinstance(fail_count, int)
            and not isinstance(fail_count, bool)
            and pass_count + fail_count == 0
        ):
            errors.append(f"{prefix} must report at least one test result")

        coverage_percent = suite.get("coverage_percent")
        if not _is_number(coverage_percent):
            errors.append(f"{prefix}.coverage_percent must be numeric")
        elif not (0.0 <= float(coverage_percent) <= 100.0):
            errors.append(f"{prefix}.coverage_percent must be in range 0..100")

        raw_output_artifact = _require_non_empty_str(
            suite.get("raw_output_artifact"),
            f"{prefix}.raw_output_artifact",
            errors,
        )
        if raw_output_artifact:
            if _validate_artifact_path(
                artifact_path=raw_output_artifact,
                field=f"{prefix}.raw_output_artifact",
                project_root=project_root,
                errors=errors,
            ):
                validated_suite_count += 1

    ok = len(errors) == 0
    event_code = (
        "CONTRACT_BENCH_CORRECT_VALIDATED"
        if ok
        else "CONTRACT_BENCH_CORRECT_INCOMPLETE"
    )
    message = (
        f"benchmark/correctness artifacts validated: {summary_rel}"
        if ok
        else f"benchmark/correctness artifacts incomplete: {summary_rel}"
    )
    events.append(
        {
            "event_code": event_code,
            "severity": "info" if ok else "error",
            "trace_correlation": trace,
            "summary_file": summary_rel,
            "message": message,
        }
    )

    return ok, {
        "summary_file": summary_rel,
        "ok": ok,
        "trace_correlation": trace,
        "errors": errors,
        "warnings": warnings,
        "events": events,
        "validated_metric_count": validated_metric_count,
        "validated_suite_count": validated_suite_count,
    }


def run_checks(
    *,
    changed_files: list[str] | None = None,
    changed_files_path: Path | None = None,
    project_root: Path = ROOT,
    summary_dir: Path | None = None,
) -> tuple[bool, dict[str, Any]]:
    summary_dir = summary_dir or (project_root / "docs" / "change_summaries")
    template_path = project_root / "docs" / "templates" / "change_summary_template.md"
    example_path = project_root / "docs" / "change_summaries" / "example_change_summary.json"

    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    if not template_path.is_file():
        errors.append(f"missing template file: {_rel(template_path, project_root)}")
    if not example_path.is_file():
        errors.append(f"missing example change summary: {_rel(example_path, project_root)}")
    if not summary_dir.exists():
        errors.append(f"missing summary directory: {_rel(summary_dir, project_root)}")

    if changed_files is None:
        if changed_files_path is not None:
            changed_files = _load_changed_files(changed_files_path)
            changed_source = _rel(changed_files_path, project_root)
        else:
            changed_files = _discover_changed_files_from_git(project_root)
            changed_source = "git-diff"
    else:
        changed_source = "inline"

    normalized_changed = sorted({_norm(path) for path in changed_files if path})
    changed_subsystem_files = [path for path in normalized_changed if _is_subsystem_path(path)]
    requires_contract = len(changed_subsystem_files) > 0

    summary_dir_rel = _rel(summary_dir, project_root)
    changed_summary_files = [
        path
        for path in normalized_changed
        if path.startswith(f"{summary_dir_rel}/") and path.endswith(".json")
    ]

    validated_summaries: list[dict[str, Any]] = []

    if requires_contract and not changed_summary_files:
        message = (
            "missing required change summary file under "
            f"{summary_dir_rel}/ for subsystem code changes"
        )
        trace = _trace_id({"changed_subsystem_files": changed_subsystem_files, "rule": "missing"})
        errors.append(message)
        events.append(
            {
                "event_code": "CONTRACT_BENCH_CORRECT_MISSING",
                "severity": "error",
                "trace_correlation": trace,
                "message": message,
                "changed_subsystem_files": changed_subsystem_files,
            }
        )

    for summary_rel in changed_summary_files:
        ok, detail = _validate_summary_file(project_root / summary_rel, project_root)
        validated_summaries.append(detail)
        events.extend(detail["events"])
        warnings.extend(detail["warnings"])
        if not ok:
            errors.extend(detail["errors"])

    ok = len(errors) == 0
    report = {
        "bead_id": "bd-3l8d",
        "ok": ok,
        "changed_files_source": changed_source,
        "changed_file_count": len(normalized_changed),
        "subsystem_change_count": len(changed_subsystem_files),
        "requires_contract": requires_contract,
        "summary_files_checked": [item["summary_file"] for item in validated_summaries],
        "template": _rel(template_path, project_root),
        "example": _rel(example_path, project_root),
        "summary_directory": _rel(summary_dir, project_root),
        "required_event_codes": sorted(REQUIRED_EVENT_CODES),
        "errors": sorted(dict.fromkeys(errors)),
        "warnings": sorted(dict.fromkeys(warnings)),
        "events": events,
        "validated_summaries": validated_summaries,
    }
    return ok, report


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="bench-correct-selftest-") as tmp:
        root = Path(tmp)
        (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)

        (root / "docs" / "templates" / "change_summary_template.md").write_text(
            "# benchmark and correctness template\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "section_11" / "bd-3l8d" / "benchmark_metrics.json").write_text(
            "{\"ok\": true}\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "section_11" / "bd-3l8d" / "correctness_suite_output.txt").write_text(
            "suite output\n",
            encoding="utf-8",
        )

        valid_summary = {
            "summary_id": "chg-self-test",
            "contract_version": "1.0",
            "change_summary": {
                "benchmark_and_correctness_artifacts": {
                    "benchmark_metrics": [
                        {
                            "metric_name": "p95_latency_ms",
                            "unit": "ms",
                            "measured_value": 31.4,
                            "baseline_value": 29.8,
                            "delta": 1.6,
                            "within_acceptable_bounds": True,
                            "artifact_path": "artifacts/section_11/bd-3l8d/benchmark_metrics.json",
                        }
                    ],
                    "correctness_suites": [
                        {
                            "suite_name": "tests/security/control_epoch_validity.rs",
                            "pass_count": 6,
                            "fail_count": 0,
                            "coverage_percent": 92.1,
                            "raw_output_artifact": "artifacts/section_11/bd-3l8d/correctness_suite_output.txt",
                        }
                    ],
                }
            },
        }

        example_path = root / "docs" / "change_summaries" / "example_change_summary.json"
        example_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")
        pass_path = root / "docs" / "change_summaries" / "self_test_summary.json"
        pass_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")

        pass_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/self_test_summary.json",
        ]
        ok_pass, report_pass = run_checks(changed_files=pass_changed, project_root=root)
        assert ok_pass, f"self_test expected pass but failed: {report_pass['errors']}"

        bad_summary = json.loads(json.dumps(valid_summary))
        bad_summary["change_summary"]["benchmark_and_correctness_artifacts"]["benchmark_metrics"] = []
        bad_path = root / "docs" / "change_summaries" / "broken_summary.json"
        bad_path.write_text(json.dumps(bad_summary, indent=2), encoding="utf-8")
        fail_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/broken_summary.json",
        ]
        ok_fail, report_fail = run_checks(changed_files=fail_changed, project_root=root)
        assert not ok_fail, "self_test expected failure for empty benchmark metric list"
        assert any("benchmark_metrics must contain at least 1 item" in err for err in report_fail["errors"])

        delta_summary = json.loads(json.dumps(valid_summary))
        delta_summary["change_summary"]["benchmark_and_correctness_artifacts"]["benchmark_metrics"][0]["delta"] = 2.0
        delta_path = root / "docs" / "change_summaries" / "delta_mismatch_summary.json"
        delta_path.write_text(json.dumps(delta_summary, indent=2), encoding="utf-8")
        delta_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/delta_mismatch_summary.json",
        ]
        ok_delta, report_delta = run_checks(changed_files=delta_changed, project_root=root)
        assert not ok_delta, "self_test expected failure for delta mismatch"
        assert any("must equal measured_value - baseline_value" in err for err in report_delta["errors"])

        ok_missing, report_missing = run_checks(
            changed_files=["crates/franken-node/src/connector/mock.rs"],
            project_root=root,
        )
        assert not ok_missing, "self_test expected failure when summary file is missing"
        assert any("missing required change summary file" in err for err in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_benchmark_correctness_artifacts")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        default=None,
        help="Path to newline-delimited changed-file list (recommended in CI).",
    )
    parser.add_argument(
        "--project-root",
        default=str(ROOT),
        help="Project root path.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test.")
    args = parser.parse_args()

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            changed_files_path = Path(args.changed_files) if args.changed_files else None
            ok, payload = run_checks(
                changed_files_path=changed_files_path,
                project_root=Path(args.project_root),
            )
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        payload = {"ok": False, "error": str(exc)}
        ok = False

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if ok:
            print("PASS")
        else:
            print("FAIL")
            for err in payload.get("errors", [payload.get("error", "unknown error")]):
                print(f"- {err}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
