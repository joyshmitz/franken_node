#!/usr/bin/env python3
"""Validate Section 11 compatibility/threat evidence contract field (bd-36wa)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

TEMPLATE_PATH = ROOT / "docs" / "templates" / "change_summary_template.md"
EXAMPLE_PATH = ROOT / "docs" / "change_summaries" / "example_change_summary.json"
DEFAULT_SUMMARY_DIR = ROOT / "docs" / "change_summaries"

REQUIRED_EVENT_CODES = {
    "CONTRACT_COMPAT_THREAT_VALIDATED",
    "CONTRACT_COMPAT_THREAT_MISSING",
    "CONTRACT_COMPAT_THREAT_INCOMPLETE",
}

SUBSYSTEM_PATH_PREFIXES = (
    "crates/franken-node/src/",
    "crates/franken-engine/src/",
    "crates/asupersync/src/",
    "services/",
)

REQUIRED_THREAT_VECTORS = {
    "privilege_escalation",
    "data_exfiltration",
    "denial_of_service",
}

RISK_LEVELS = {"low", "medium", "high", "critical"}


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
                    "event_code": "CONTRACT_COMPAT_THREAT_INCOMPLETE",
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
                    "event_code": "CONTRACT_COMPAT_THREAT_INCOMPLETE",
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
                    "event_code": "CONTRACT_COMPAT_THREAT_INCOMPLETE",
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

    compat_threat = change_summary.get("compatibility_and_threat_evidence")
    if not isinstance(compat_threat, dict):
        errors.append("change_summary.compatibility_and_threat_evidence must be an object")
        compat_threat = {}

    suites = _require_list(
        compat_threat.get("compatibility_test_suites"),
        "change_summary.compatibility_and_threat_evidence.compatibility_test_suites",
        errors,
        min_items=1,
    )
    validated_suite_count = 0
    for idx, suite in enumerate(suites):
        prefix = (
            "change_summary.compatibility_and_threat_evidence"
            f".compatibility_test_suites[{idx}]"
        )
        if not isinstance(suite, dict):
            errors.append(f"{prefix} must be an object")
            continue

        _require_non_empty_str(suite.get("suite_name"), f"{prefix}.suite_name", errors)

        pass_count = suite.get("pass_count")
        fail_count = suite.get("fail_count")
        if not isinstance(pass_count, int) or pass_count < 0:
            errors.append(f"{prefix}.pass_count must be an integer >= 0")
        if not isinstance(fail_count, int) or fail_count < 0:
            errors.append(f"{prefix}.fail_count must be an integer >= 0")
        if isinstance(pass_count, int) and isinstance(fail_count, int):
            if pass_count + fail_count == 0:
                errors.append(f"{prefix} must report at least one test result")

        artifact_path = _require_non_empty_str(
            suite.get("artifact_path"),
            f"{prefix}.artifact_path",
            errors,
        )
        if artifact_path:
            artifact_abs = project_root / artifact_path
            if not artifact_abs.is_file():
                errors.append(f"{prefix}.artifact_path does not exist: {artifact_path}")
            else:
                validated_suite_count += 1

    risk = compat_threat.get("regression_risk_assessment")
    if not isinstance(risk, dict):
        errors.append(
            "change_summary.compatibility_and_threat_evidence.regression_risk_assessment must be an object"
        )
        risk = {}

    risk_level = _require_non_empty_str(
        risk.get("risk_level"),
        "change_summary.compatibility_and_threat_evidence.regression_risk_assessment.risk_level",
        errors,
    )
    if risk_level and risk_level not in RISK_LEVELS:
        errors.append(
            "change_summary.compatibility_and_threat_evidence.regression_risk_assessment.risk_level "
            f"must be one of: {', '.join(sorted(RISK_LEVELS))}"
        )

    api_families_raw = _require_list(
        risk.get("api_families"),
        "change_summary.compatibility_and_threat_evidence.regression_risk_assessment.api_families",
        errors,
        min_items=1,
    )
    api_families: list[str] = []
    for idx, family in enumerate(api_families_raw):
        if not isinstance(family, str) or not family.strip():
            errors.append(
                "change_summary.compatibility_and_threat_evidence.regression_risk_assessment"
                f".api_families[{idx}] must be a non-empty string"
            )
            continue
        api_families.append(family.strip())

    _require_non_empty_str(
        risk.get("notes"),
        "change_summary.compatibility_and_threat_evidence.regression_risk_assessment.notes",
        errors,
    )

    vectors = _require_list(
        compat_threat.get("threat_vectors"),
        "change_summary.compatibility_and_threat_evidence.threat_vectors",
        errors,
        min_items=1,
    )
    seen_required_vectors: set[str] = set()
    seen_vector_names: list[str] = []
    for idx, entry in enumerate(vectors):
        prefix = f"change_summary.compatibility_and_threat_evidence.threat_vectors[{idx}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue

        vector = _require_non_empty_str(entry.get("vector"), f"{prefix}.vector", errors)
        mitigation = _require_non_empty_str(entry.get("mitigation"), f"{prefix}.mitigation", errors)
        if vector:
            seen_vector_names.append(vector)
            if vector in REQUIRED_THREAT_VECTORS and mitigation:
                seen_required_vectors.add(vector)

    missing_required_vectors = sorted(REQUIRED_THREAT_VECTORS - seen_required_vectors)
    if missing_required_vectors:
        errors.append(
            "change_summary.compatibility_and_threat_evidence.threat_vectors missing required "
            f"vector(s): {', '.join(missing_required_vectors)}"
        )

    ok = len(errors) == 0
    event_code = (
        "CONTRACT_COMPAT_THREAT_VALIDATED" if ok else "CONTRACT_COMPAT_THREAT_INCOMPLETE"
    )
    message = (
        f"compatibility/threat evidence validated: {summary_rel}"
        if ok
        else f"compatibility/threat evidence incomplete: {summary_rel}"
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
        "validated_suite_count": validated_suite_count,
        "api_families": api_families,
        "threat_vectors": sorted(dict.fromkeys(seen_vector_names)),
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
                "event_code": "CONTRACT_COMPAT_THREAT_MISSING",
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
        "bead_id": "bd-36wa",
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
    with tempfile.TemporaryDirectory(prefix="compat-threat-selftest-") as tmp:
        root = Path(tmp)
        (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "11").mkdir(parents=True, exist_ok=True)

        (root / "docs" / "templates" / "change_summary_template.md").write_text(
            "# compatibility and threat template\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "11" / "mock_report.json").write_text(
            "{\"ok\": true}\n",
            encoding="utf-8",
        )

        valid_summary = {
            "summary_id": "chg-self-test",
            "contract_version": "1.0",
            "change_summary": {
                "compatibility_and_threat_evidence": {
                    "compatibility_test_suites": [
                        {
                            "suite_name": "tests/conformance/mock.rs",
                            "pass_count": 5,
                            "fail_count": 0,
                            "artifact_path": "artifacts/11/mock_report.json",
                        }
                    ],
                    "regression_risk_assessment": {
                        "risk_level": "medium",
                        "api_families": ["POST /v1/mock"],
                        "notes": "Adds validation without changing API shape.",
                    },
                    "threat_vectors": [
                        {
                            "vector": "privilege_escalation",
                            "mitigation": "Boundary capability checks applied.",
                        },
                        {
                            "vector": "data_exfiltration",
                            "mitigation": "Sensitive fields are redacted in error outputs.",
                        },
                        {
                            "vector": "denial_of_service",
                            "mitigation": "Rate limits and timeout caps are enforced.",
                        },
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
        bad_summary["change_summary"]["compatibility_and_threat_evidence"]["threat_vectors"] = [
            {
                "vector": "privilege_escalation",
                "mitigation": "Boundary capability checks applied.",
            }
        ]
        bad_path = root / "docs" / "change_summaries" / "broken_summary.json"
        bad_path.write_text(json.dumps(bad_summary, indent=2), encoding="utf-8")
        fail_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/broken_summary.json",
        ]
        ok_fail, report_fail = run_checks(changed_files=fail_changed, project_root=root)
        assert not ok_fail, "self_test expected failure for missing required threat vectors"
        assert any("missing required vector" in err for err in report_fail["errors"])

        ok_missing, report_missing = run_checks(
            changed_files=["crates/franken-node/src/connector/mock.rs"],
            project_root=root,
        )
        assert not ok_missing, "self_test expected failure when summary file is missing"
        assert any("missing required change summary file" in err for err in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
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
