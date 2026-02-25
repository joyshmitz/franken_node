#!/usr/bin/env python3
"""
Compatibility CI Gate.

Verifies that compatibility implementation files cite spec sections and
fixture IDs. Missing references fail the review gate.

Usage:
    python3 scripts/check_compat_ci_gate.py [--json]
"""

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path

COMPAT_SRC_DIRS = [
    ROOT / "src" / "compat",
    ROOT / "crates" / "compat",
]
FIXTURE_DIRS = [
    ROOT / "docs" / "fixtures",
    ROOT / "docs" / "fixtures" / "core",
    ROOT / "docs" / "fixtures" / "high_value",
    ROOT / "docs" / "fixtures" / "edge",
]
REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"
GOVERNANCE_PATH = ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md"
GATE_SPEC_PATH = ROOT / "docs" / "specs" / "section_10_2" / "bd-7mt_contract.md"

SPEC_REF_PATTERN = re.compile(
    r"(?:Spec:\s*Section\s+\d+\.\d+|ADR-\d{3}|docs/specs/|spec_section|COMPATIBILITY_BANDS)",
    re.IGNORECASE,
)
FIXTURE_REF_PATTERN = re.compile(r"fixture:[a-z_]+:[a-zA-Z_]+:[a-z0-9_-]+")
BAND_PATTERN = re.compile(r"\b(?:core|high-value|edge|unsafe)\b")


def collect_fixture_ids() -> set[str]:
    """Collect all fixture IDs from the corpus."""
    ids = set()
    for d in FIXTURE_DIRS:
        if d.is_dir():
            for f in d.rglob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    if "id" in data and data["id"].startswith("fixture:"):
                        ids.add(data["id"])
                except (json.JSONDecodeError, KeyError):
                    pass
    return ids


def collect_compat_files() -> list[Path]:
    """Find compatibility implementation files."""
    files = []
    for d in COMPAT_SRC_DIRS:
        if d.is_dir():
            files.extend(d.rglob("*.rs"))
            files.extend(d.rglob("*.ts"))
            files.extend(d.rglob("*.js"))
    return sorted(files)


def check_gate_spec_exists() -> dict:
    """Verify the gate spec document exists."""
    check = {"id": "CI-GATE-SPEC", "status": "PASS", "details": {}}
    check["details"]["spec_exists"] = GATE_SPEC_PATH.exists()
    check["details"]["governance_exists"] = GOVERNANCE_PATH.exists()
    if not GATE_SPEC_PATH.exists() or not GOVERNANCE_PATH.exists():
        check["status"] = "FAIL"
    return check


def check_governance_references() -> dict:
    """Verify governance doc mentions CI gate enforcement."""
    check = {"id": "CI-GATE-GOVERNANCE", "status": "PASS", "details": {}}
    if not GOVERNANCE_PATH.exists():
        check["status"] = "FAIL"
        return check
    text = GOVERNANCE_PATH.read_text().lower()
    has_spec_ref = "spec" in text and ("reference" in text or "section" in text)
    has_fixture_ref = "fixture" in text
    check["details"]["governance_mentions_spec_refs"] = has_spec_ref
    check["details"]["governance_mentions_fixtures"] = has_fixture_ref
    if not has_spec_ref or not has_fixture_ref:
        check["status"] = "FAIL"
    return check


def check_fixture_corpus_exists() -> dict:
    """Verify fixture corpus has entries."""
    check = {"id": "CI-GATE-CORPUS", "status": "PASS", "details": {}}
    ids = collect_fixture_ids()
    check["details"]["fixture_count"] = len(ids)
    if len(ids) < 5:
        check["status"] = "FAIL"
    return check


def check_registry_has_entries() -> dict:
    """Verify compatibility registry is populated."""
    check = {"id": "CI-GATE-REGISTRY", "status": "PASS", "details": {}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["registry_exists"] = False
        return check
    registry = json.loads(REGISTRY_PATH.read_text())
    entries = registry.get("behaviors", [])
    check["details"]["entry_count"] = len(entries)
    if len(entries) < 1:
        check["status"] = "FAIL"
    return check


def check_implementation_compliance() -> dict:
    """Check that any existing compat implementation files cite spec+fixtures.

    If no implementation files exist yet (pre-implementation phase),
    this check passes — the gate is ready to enforce when code lands.
    """
    check = {"id": "CI-GATE-COMPLIANCE", "status": "PASS", "details": {}}
    files = collect_compat_files()
    check["details"]["compat_files_found"] = len(files)

    if not files:
        check["details"]["note"] = "No compatibility implementation files yet; gate ready for enforcement"
        return check

    fixture_ids = collect_fixture_ids()
    violations = []

    for f in files:
        text = f.read_text()
        has_spec = bool(SPEC_REF_PATTERN.search(text))
        has_fixture = bool(FIXTURE_REF_PATTERN.search(text))
        has_band = bool(BAND_PATTERN.search(text))

        cited_fixtures = FIXTURE_REF_PATTERN.findall(text)
        unresolved = [fid for fid in cited_fixtures if fid not in fixture_ids]

        if not has_spec or not has_fixture or not has_band or unresolved:
            violations.append({
                "file": str(f.relative_to(ROOT)) if str(f).startswith(str(ROOT)) else str(f),
                "missing_spec_ref": not has_spec,
                "missing_fixture_ref": not has_fixture,
                "missing_band_decl": not has_band,
                "unresolved_fixtures": unresolved,
            })

    check["details"]["violations"] = violations
    if violations:
        check["status"] = "FAIL"
    return check


def main():
    logger = configure_test_logging("check_compat_ci_gate")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_gate_spec_exists(),
        check_governance_references(),
        check_fixture_corpus_exists(),
        check_registry_has_entries(),
        check_implementation_compliance(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "compat_ci_gate_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Compatibility CI Gate Verifier ===")
        print(f"Timestamp: {timestamp}\n")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nChecks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
