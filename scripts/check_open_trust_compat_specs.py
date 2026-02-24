#!/usr/bin/env python3
"""Verifier for bd-f955 open trust/compatibility specification artifacts."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
SPEC_PATH = ROOT / "docs" / "specs" / "section_16" / "bd-f955_open_trust_compatibility_specs.md"
ARTIFACT_PATH = ROOT / "artifacts" / "16" / "open_trust_compatibility_specs.json"

REQUIRED_HEADINGS = [
    "## Scope",
    "## Publication Surface",
    "## Compatibility Contract Matrix",
    "## Trust Evidence Contract",
    "## Determinism and Reproducibility Requirements",
    "## Release Gate Contract",
    "## Event Codes",
    "## Invariants",
    "## Governance",
]

REQUIRED_EVENT_CODES = {
    "OTCS-001",
    "OTCS-002",
    "OTCS-003",
    "OTCS-004",
}

REQUIRED_INVARIANTS = {
    "INV-OTCS-OPEN",
    "INV-OTCS-COMPAT",
    "INV-OTCS-TRUST",
    "INV-OTCS-DETERMINISTIC",
}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> None:
    CHECKS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("found" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("artifact root must be a JSON object")
    return payload


def run_checks(spec_path: Path = SPEC_PATH, artifact_path: Path = ARTIFACT_PATH) -> dict[str, Any]:
    CHECKS.clear()

    _check("spec_exists", spec_path.is_file(), str(spec_path))
    _check("artifact_exists", artifact_path.is_file(), str(artifact_path))

    spec_text = spec_path.read_text(encoding="utf-8") if spec_path.is_file() else ""

    heading_failures = [heading for heading in REQUIRED_HEADINGS if heading not in spec_text]
    _check(
        "spec_required_headings",
        len(heading_failures) == 0,
        "missing: " + ", ".join(heading_failures) if heading_failures else "all present",
    )

    missing_codes = sorted(code for code in REQUIRED_EVENT_CODES if code not in spec_text)
    _check(
        "spec_event_codes",
        len(missing_codes) == 0,
        "missing: " + ", ".join(missing_codes) if missing_codes else "all present",
    )

    missing_invariants = sorted(inv for inv in REQUIRED_INVARIANTS if inv not in spec_text)
    _check(
        "spec_invariants",
        len(missing_invariants) == 0,
        "missing: " + ", ".join(missing_invariants) if missing_invariants else "all present",
    )

    artifact: dict[str, Any] = {}
    parse_error = ""
    if artifact_path.is_file():
        try:
            artifact = _load_json(artifact_path)
        except Exception as exc:  # pragma: no cover - defensive
            parse_error = str(exc)
    _check("artifact_parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for item in CHECKS if item["pass"])
        return {
            "bead_id": "bd-f955",
            "title": "open trust and compatibility specs",
            "section": "16",
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "checks": CHECKS,
        }

    required_top = {
        "bead_id",
        "section",
        "spec_version",
        "spec_path",
        "published_documents",
        "event_codes",
        "compatibility_matrix",
        "trust_requirements",
        "invariants",
        "release_gate",
    }
    missing_top = sorted(required_top - set(artifact.keys()))
    _check(
        "artifact_required_top_fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "all present",
    )

    _check("artifact_bead_id", artifact.get("bead_id") == "bd-f955", str(artifact.get("bead_id")))
    _check("artifact_section", str(artifact.get("section")) == "16", str(artifact.get("section")))

    spec_version = str(artifact.get("spec_version", ""))
    _check("artifact_spec_version", spec_version.startswith("1."), spec_version)

    published = artifact.get("published_documents")
    published_ok = isinstance(published, list) and (
        "docs/specs/section_16/bd-f955_open_trust_compatibility_specs.md" in published
    )
    _check("artifact_published_documents", published_ok)

    event_codes = artifact.get("event_codes")
    event_codes_ok = isinstance(event_codes, list) and REQUIRED_EVENT_CODES.issubset(set(event_codes))
    _check("artifact_event_codes", event_codes_ok)

    matrix = artifact.get("compatibility_matrix")
    matrix_ok = isinstance(matrix, list) and len(matrix) >= 6
    _check("artifact_compatibility_matrix", matrix_ok, f"count={len(matrix) if isinstance(matrix, list) else 0}")

    trust = artifact.get("trust_requirements")
    trust_ok = (
        isinstance(trust, dict)
        and trust.get("signed_provenance") is True
        and trust.get("deterministic_replay") is True
        and trust.get("open_schema") is True
    )
    _check("artifact_trust_requirements", trust_ok)

    invariants = artifact.get("invariants")
    invariant_ids = set()
    invariants_ok = isinstance(invariants, list)
    if isinstance(invariants, list):
        for entry in invariants:
            if not isinstance(entry, dict):
                invariants_ok = False
                continue
            inv_id = str(entry.get("id", "")).strip()
            pass_condition = str(entry.get("pass_condition", "")).strip()
            if inv_id:
                invariant_ids.add(inv_id)
            if not pass_condition:
                invariants_ok = False
    invariants_ok = invariants_ok and REQUIRED_INVARIANTS.issubset(invariant_ids)
    _check("artifact_invariants", invariants_ok)

    release_gate = artifact.get("release_gate")
    release_gate_ok = (
        isinstance(release_gate, dict)
        and release_gate.get("checker_command")
        == "python3 scripts/check_open_trust_compat_specs.py --json"
        and release_gate.get("unit_test_command")
        == "python3 -m unittest tests/test_check_open_trust_compat_specs.py"
    )
    _check("artifact_release_gate", release_gate_ok)

    total = len(CHECKS)
    passed = sum(1 for item in CHECKS if item["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-f955",
        "title": "open trust and compatibility specs",
        "section": "16",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": CHECKS,
        "artifacts": {
            "spec": "docs/specs/section_16/bd-f955_open_trust_compatibility_specs.md",
            "machine_artifact": "artifacts/16/open_trust_compatibility_specs.json",
        },
    }


def _fixture(base: Path, *, missing_heading: bool = False, missing_code: bool = False) -> tuple[Path, Path]:
    spec_dir = base / "docs" / "specs" / "section_16"
    artifact_dir = base / "artifacts" / "16"
    spec_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    spec_text = SPEC_PATH.read_text(encoding="utf-8")
    if missing_heading:
        spec_text = spec_text.replace("## Governance", "## Policy Governance", 1)
    if missing_code:
        spec_text = spec_text.replace("`OTCS-004`", "`OTCS-099`", 1)

    spec_path = spec_dir / "bd-f955_open_trust_compatibility_specs.md"
    spec_path.write_text(spec_text, encoding="utf-8")

    artifact = _load_json(ARTIFACT_PATH)
    artifact_path = artifact_dir / "open_trust_compatibility_specs.json"
    artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    return spec_path, artifact_path


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-f955-") as tmp:
        base = Path(tmp)
        spec_ok, artifact_ok = _fixture(base)
        report_ok = run_checks(spec_ok, artifact_ok)
        if report_ok["verdict"] != "PASS":
            return False

        spec_fail, artifact_fail = _fixture(base, missing_heading=True)
        report_fail = run_checks(spec_fail, artifact_fail)
        if report_fail["verdict"] != "FAIL":
            return False

    return True


def main() -> int:
    logger = configure_test_logging("check_open_trust_compat_specs")
    parser = argparse.ArgumentParser(description="Check bd-f955 open trust/compatibility specs")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"self_test": "PASS" if ok else "FAIL"}, indent=2))
        else:
            print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    report = run_checks()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['verdict']} ({report['passed']}/{report['total']})")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
