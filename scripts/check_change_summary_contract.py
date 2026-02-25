#!/usr/bin/env python3
"""Validate Section 11 change-summary contract field completeness (bd-3se1)."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

TEMPLATE_PATH = ROOT / "docs" / "templates" / "change_summary_template.md"
EXAMPLE_PATH = ROOT / "docs" / "change_summaries" / "example_change_summary.json"
DEFAULT_SUMMARY_DIR = ROOT / "docs" / "change_summaries"

REQUIRED_EVENT_CODES = {
    "CONTRACT_CHANGE_SUMMARY_VALIDATED",
    "CONTRACT_MISSING",
    "CONTRACT_INCOMPLETE",
}

SUBSYSTEM_PATH_PREFIXES = (
    "crates/franken-node/src/",
    "crates/franken-engine/src/",
    "crates/asupersync/src/",
    "services/",
)

RISK_TIERS = {"low", "medium", "high", "critical"}
BACKWARD_COMPAT_VALUES = {"compatible", "breaking", "n/a"}
FORWARD_COMPAT_VALUES = {"enables", "neutral", "blocks"}


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


def _require_str_list(
    value: Any,
    field: str,
    errors: list[str],
    *,
    min_items: int = 0,
) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []

    cleaned: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field}[{idx}] must be a non-empty string")
            continue
        cleaned.append(item.strip())

    if len(cleaned) < min_items:
        errors.append(f"{field} must contain at least {min_items} item(s)")
    return cleaned


def _validate_summary_file(
    summary_path: Path,
    changed_subsystem_files: list[str],
    project_root: Path,
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []

    if not summary_path.is_file():
        message = f"summary file listed in diff but missing on disk: {_rel(summary_path, project_root)}"
        event = {
            "event_code": "CONTRACT_INCOMPLETE",
            "severity": "error",
            "trace_correlation": _trace_id({"summary_path": _norm(summary_path), "error": message}),
            "summary_file": _rel(summary_path, project_root),
            "message": message,
        }
        return False, {
            "summary_file": _rel(summary_path, project_root),
            "ok": False,
            "errors": [message],
            "warnings": warnings,
            "events": [event],
        }

    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in {_rel(summary_path, project_root)}: {exc}"
        event = {
            "event_code": "CONTRACT_INCOMPLETE",
            "severity": "error",
            "trace_correlation": _trace_id({"summary_path": _norm(summary_path), "error": str(exc)}),
            "summary_file": _rel(summary_path, project_root),
            "message": message,
        }
        return False, {
            "summary_file": _rel(summary_path, project_root),
            "ok": False,
            "errors": [message],
            "warnings": warnings,
            "events": [event],
        }

    if not isinstance(payload, dict):
        message = f"{_rel(summary_path, project_root)} must contain a JSON object"
        event = {
            "event_code": "CONTRACT_INCOMPLETE",
            "severity": "error",
            "trace_correlation": _trace_id({"summary_path": _norm(summary_path), "error": message}),
            "summary_file": _rel(summary_path, project_root),
            "message": message,
        }
        return False, {
            "summary_file": _rel(summary_path, project_root),
            "ok": False,
            "errors": [message],
            "warnings": warnings,
            "events": [event],
        }

    trace = _trace_id(payload)
    events: list[dict[str, Any]] = []

    _require_non_empty_str(payload.get("summary_id"), "summary_id", errors)
    _require_non_empty_str(payload.get("contract_version"), "contract_version", errors)

    change_summary = payload.get("change_summary")
    if not isinstance(change_summary, dict):
        errors.append("change_summary must be an object")
        change_summary = {}

    intent = _require_non_empty_str(change_summary.get("intent"), "change_summary.intent", errors)
    if intent and "\n" in intent:
        errors.append("change_summary.intent must be a one-line statement")

    scope = change_summary.get("scope")
    if not isinstance(scope, dict):
        errors.append("change_summary.scope must be an object")
        scope = {}
    subsystems = _require_str_list(
        scope.get("subsystems"),
        "change_summary.scope.subsystems",
        errors,
        min_items=1,
    )
    modules = _require_str_list(
        scope.get("modules"),
        "change_summary.scope.modules",
        errors,
        min_items=1,
    )
    if changed_subsystem_files and modules:
        overlap = sorted(set(modules).intersection(changed_subsystem_files))
        if not overlap:
            errors.append(
                "change_summary.scope.modules must reference at least one changed subsystem file"
            )

    surface_area_delta = change_summary.get("surface_area_delta")
    if not isinstance(surface_area_delta, dict):
        errors.append("change_summary.surface_area_delta must be an object")
        surface_area_delta = {}
    _require_str_list(surface_area_delta.get("new_apis"), "change_summary.surface_area_delta.new_apis", errors)
    _require_str_list(
        surface_area_delta.get("removed_apis"),
        "change_summary.surface_area_delta.removed_apis",
        errors,
    )
    _require_str_list(
        surface_area_delta.get("changed_signatures"),
        "change_summary.surface_area_delta.changed_signatures",
        errors,
    )

    affected_contracts = change_summary.get("affected_contracts")
    if not isinstance(affected_contracts, dict):
        errors.append("change_summary.affected_contracts must be an object")
        affected_contracts = {}
    beads = _require_str_list(
        affected_contracts.get("beads"),
        "change_summary.affected_contracts.beads",
        errors,
        min_items=1,
    )
    documents = _require_str_list(
        affected_contracts.get("documents"),
        "change_summary.affected_contracts.documents",
        errors,
        min_items=1,
    )
    for bead in beads:
        if not bead.startswith("bd-"):
            errors.append(f"change_summary.affected_contracts.beads contains invalid id: {bead}")
    for doc in documents:
        if not (project_root / doc).is_file():
            errors.append(
                f"change_summary.affected_contracts.documents path does not exist: {doc}"
            )

    operational_impact = change_summary.get("operational_impact")
    if not isinstance(operational_impact, dict):
        errors.append("change_summary.operational_impact must be an object")
        operational_impact = {}
    _require_non_empty_str(
        operational_impact.get("operator_notes"),
        "change_summary.operational_impact.operator_notes",
        errors,
    )
    _require_str_list(
        operational_impact.get("required_actions"),
        "change_summary.operational_impact.required_actions",
        errors,
        min_items=1,
    )
    _require_non_empty_str(
        operational_impact.get("rollout_notes"),
        "change_summary.operational_impact.rollout_notes",
        errors,
    )

    risk_delta = change_summary.get("risk_delta")
    if not isinstance(risk_delta, dict):
        errors.append("change_summary.risk_delta must be an object")
        risk_delta = {}
    previous_tier = _require_non_empty_str(
        risk_delta.get("previous_tier"),
        "change_summary.risk_delta.previous_tier",
        errors,
    )
    new_tier = _require_non_empty_str(risk_delta.get("new_tier"), "change_summary.risk_delta.new_tier", errors)
    if previous_tier and previous_tier not in RISK_TIERS:
        errors.append(
            f"change_summary.risk_delta.previous_tier must be one of: {', '.join(sorted(RISK_TIERS))}"
        )
    if new_tier and new_tier not in RISK_TIERS:
        errors.append(
            f"change_summary.risk_delta.new_tier must be one of: {', '.join(sorted(RISK_TIERS))}"
        )
    _require_non_empty_str(risk_delta.get("rationale"), "change_summary.risk_delta.rationale", errors)

    compatibility = change_summary.get("compatibility")
    if not isinstance(compatibility, dict):
        errors.append("change_summary.compatibility must be an object")
        compatibility = {}
    backward = _require_non_empty_str(
        compatibility.get("backward_compatibility"),
        "change_summary.compatibility.backward_compatibility",
        errors,
    )
    forward = _require_non_empty_str(
        compatibility.get("forward_compatibility"),
        "change_summary.compatibility.forward_compatibility",
        errors,
    )
    if backward and backward not in BACKWARD_COMPAT_VALUES:
        errors.append(
            "change_summary.compatibility.backward_compatibility must be one of: "
            + ", ".join(sorted(BACKWARD_COMPAT_VALUES))
        )
    if forward and forward not in FORWARD_COMPAT_VALUES:
        errors.append(
            "change_summary.compatibility.forward_compatibility must be one of: "
            + ", ".join(sorted(FORWARD_COMPAT_VALUES))
        )
    _require_non_empty_str(compatibility.get("details"), "change_summary.compatibility.details", errors)

    dependency_changes = change_summary.get("dependency_changes")
    if not isinstance(dependency_changes, dict):
        errors.append("change_summary.dependency_changes must be an object")
        dependency_changes = {}
    _require_str_list(dependency_changes.get("added"), "change_summary.dependency_changes.added", errors)
    _require_str_list(dependency_changes.get("removed"), "change_summary.dependency_changes.removed", errors)
    _require_str_list(dependency_changes.get("updated"), "change_summary.dependency_changes.updated", errors)

    ok = len(errors) == 0
    event_code = "CONTRACT_CHANGE_SUMMARY_VALIDATED" if ok else "CONTRACT_INCOMPLETE"
    severity = "info" if ok else "error"
    summary_rel = _rel(summary_path, project_root)
    message = (
        f"change summary validated: {summary_rel}"
        if ok
        else f"change summary incomplete: {summary_rel}"
    )
    events.append(
        {
            "event_code": event_code,
            "severity": severity,
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
        "subsystems": subsystems,
        "modules": modules,
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
    requires_change_summary = len(changed_subsystem_files) > 0

    summary_dir_rel = _rel(summary_dir, project_root)
    changed_summary_files = [
        path
        for path in normalized_changed
        if path.startswith(f"{summary_dir_rel}/") and path.endswith(".json")
    ]

    validated_summaries: list[dict[str, Any]] = []

    if requires_change_summary and not changed_summary_files:
        trace = _trace_id({"changed_subsystem_files": changed_subsystem_files})
        message = (
            "missing required change summary file under "
            f"{summary_dir_rel}/ for subsystem code changes"
        )
        errors.append(message)
        events.append(
            {
                "event_code": "CONTRACT_MISSING",
                "severity": "error",
                "trace_correlation": trace,
                "message": message,
                "changed_subsystem_files": changed_subsystem_files,
            }
        )

    for summary_rel in changed_summary_files:
        ok, detail = _validate_summary_file(
            project_root / summary_rel,
            changed_subsystem_files,
            project_root,
        )
        validated_summaries.append(detail)
        events.extend(detail["events"])
        warnings.extend(detail["warnings"])
        if not ok:
            errors.extend(detail["errors"])

    ok = len(errors) == 0
    report = {
        "bead_id": "bd-3se1",
        "ok": ok,
        "changed_files_source": changed_source,
        "changed_file_count": len(normalized_changed),
        "subsystem_change_count": len(changed_subsystem_files),
        "requires_change_summary": requires_change_summary,
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
    with tempfile.TemporaryDirectory(prefix="change-summary-contract-selftest-") as tmp:
        root = Path(tmp)
        (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "specs").mkdir(parents=True, exist_ok=True)

        (root / "docs" / "templates" / "change_summary_template.md").write_text(
            "# change summary template\n",
            encoding="utf-8",
        )
        (root / "docs" / "specs" / "mock_contract.md").write_text(
            "# mock contract\n",
            encoding="utf-8",
        )

        valid_summary = {
            "summary_id": "chg-20260220-self-test",
            "contract_version": "1.0",
            "change_summary": {
                "intent": "Add deterministic validation step.",
                "scope": {
                    "subsystems": ["franken_node.connector"],
                    "modules": ["crates/franken-node/src/connector/lease_service.rs"],
                },
                "surface_area_delta": {
                    "new_apis": ["POST /v1/lease/validate"],
                    "removed_apis": [],
                    "changed_signatures": [],
                },
                "affected_contracts": {
                    "beads": ["bd-3se1"],
                    "documents": ["docs/specs/mock_contract.md"],
                },
                "operational_impact": {
                    "operator_notes": "Operators must monitor validation failures.",
                    "required_actions": ["Run verifier before rollout."],
                    "rollout_notes": "Ship behind canary for one release window.",
                },
                "risk_delta": {
                    "previous_tier": "high",
                    "new_tier": "medium",
                    "rationale": "Validation narrows unsafe finalize paths.",
                },
                "compatibility": {
                    "backward_compatibility": "compatible",
                    "forward_compatibility": "enables",
                    "details": "Adds guards without changing API semantics.",
                },
                "dependency_changes": {
                    "added": [],
                    "removed": [],
                    "updated": ["tokio: 1.44.0 -> 1.45.0"],
                },
            },
        }

        example_path = root / "docs" / "change_summaries" / "example_change_summary.json"
        example_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")
        test_summary_path = root / "docs" / "change_summaries" / "self_test_summary.json"
        test_summary_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")

        pass_changed = [
            "crates/franken-node/src/connector/lease_service.rs",
            "docs/change_summaries/self_test_summary.json",
        ]
        ok_pass, report_pass = run_checks(changed_files=pass_changed, project_root=root)
        assert ok_pass, f"self_test expected pass but failed: {report_pass['errors']}"

        bad_summary = dict(valid_summary)
        bad_change_summary = dict(valid_summary["change_summary"])
        bad_change_summary["intent"] = ""
        bad_summary["change_summary"] = bad_change_summary
        (root / "docs" / "change_summaries" / "broken_summary.json").write_text(
            json.dumps(bad_summary, indent=2),
            encoding="utf-8",
        )
        fail_changed = [
            "crates/franken-node/src/connector/lease_service.rs",
            "docs/change_summaries/broken_summary.json",
        ]
        ok_fail, report_fail = run_checks(changed_files=fail_changed, project_root=root)
        assert not ok_fail, "self_test expected failure for incomplete summary"
        assert any("change_summary.intent" in err for err in report_fail["errors"])

        ok_missing, report_missing = run_checks(
            changed_files=["crates/franken-node/src/connector/lease_service.rs"],
            project_root=root,
        )
        assert not ok_missing, "self_test expected failure when summary is missing"
        assert any("missing required change summary file" in err for err in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_change_summary_contract")
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
