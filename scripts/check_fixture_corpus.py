#!/usr/bin/env python3
"""
Fixture Corpus Verifier.

Validates that the fixture corpus is complete, well-organized, and
correctly prioritized per compatibility band.

Usage:
    python3 scripts/check_fixture_corpus.py [--json]
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
FIXTURE_DIRS = {
    "core": ROOT / "docs" / "fixtures" / "core",
    "high-value": ROOT / "docs" / "fixtures" / "high_value",
    "edge": ROOT / "docs" / "fixtures" / "edge",
}
LEGACY_FIXTURE_DIR = ROOT / "docs" / "fixtures"
CAPTURE_DIR = ROOT / "scripts" / "captures"
SCHEMA_PATH = ROOT / "schemas" / "compatibility_fixture.schema.json"
REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"

ID_PATTERN = re.compile(r"^fixture:[a-z_]+:[a-zA-Z_]+:[a-z0-9_-]+$")
VALID_BANDS = {"core", "high-value", "edge", "unsafe"}


def load_fixtures() -> list[dict]:
    """Load all fixture JSON files from organized and legacy dirs."""
    fixtures = []
    # Organized dirs
    for band_dir in FIXTURE_DIRS.values():
        if band_dir.is_dir():
            for family_dir in sorted(band_dir.iterdir()):
                if family_dir.is_dir():
                    for f in sorted(family_dir.glob("*.json")):
                        fixtures.append(json.loads(f.read_text()))
                elif family_dir.suffix == ".json":
                    fixtures.append(json.loads(family_dir.read_text()))
    # Edge fixtures may be flat
    edge_dir = FIXTURE_DIRS.get("edge")
    if edge_dir and edge_dir.is_dir():
        for f in sorted(edge_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if data.get("id") and data["id"] not in [fx["id"] for fx in fixtures]:
                    fixtures.append(data)
            except (json.JSONDecodeError, KeyError):
                pass
    # Legacy flat dir
    for f in sorted(LEGACY_FIXTURE_DIR.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if data.get("id") and data["id"] not in [fx["id"] for fx in fixtures]:
                fixtures.append(data)
        except (json.JSONDecodeError, KeyError):
            pass
    return fixtures


def check_corpus_structure() -> dict:
    """Verify organized directory structure exists."""
    check = {"id": "CORPUS-STRUCTURE", "status": "PASS", "details": {"dirs": {}}}
    for band, d in FIXTURE_DIRS.items():
        exists = d.is_dir()
        check["details"]["dirs"][band] = exists
        if not exists:
            check["status"] = "FAIL"
    return check


def check_capture_programs() -> dict:
    """Verify reference capture programs exist."""
    check = {"id": "CORPUS-CAPTURES", "status": "PASS", "details": {"programs": {}}}
    if not CAPTURE_DIR.is_dir():
        check["status"] = "FAIL"
        check["details"]["capture_dir_exists"] = False
        return check
    programs = sorted(CAPTURE_DIR.glob("capture_*.js"))
    check["details"]["count"] = len(programs)
    check["details"]["programs"] = {p.name: True for p in programs}
    if len(programs) < 2:
        check["status"] = "FAIL"
    return check


def check_fixture_validity(fixtures: list[dict]) -> dict:
    """Validate all fixtures have required fields and valid IDs."""
    check = {"id": "CORPUS-VALID", "status": "PASS", "details": {"total": len(fixtures), "valid": 0, "invalid": []}}
    required = {"id", "api_family", "api_name", "band", "input", "expected_output"}
    for fx in fixtures:
        missing = required - set(fx.keys())
        bad_id = not ID_PATTERN.match(fx.get("id", ""))
        bad_band = fx.get("band") not in VALID_BANDS
        if missing or bad_id or bad_band:
            check["details"]["invalid"].append(fx.get("id", "<unknown>"))
            check["status"] = "FAIL"
        else:
            check["details"]["valid"] += 1
    return check


def check_fixture_uniqueness(fixtures: list[dict]) -> dict:
    """Verify all fixture IDs are unique."""
    check = {"id": "CORPUS-UNIQUE", "status": "PASS", "details": {"duplicates": []}}
    seen = set()
    for fx in fixtures:
        fid = fx.get("id", "")
        if fid in seen:
            check["details"]["duplicates"].append(fid)
            check["status"] = "FAIL"
        seen.add(fid)
    return check


def check_band_coverage(fixtures: list[dict]) -> dict:
    """Check fixture counts per band meet minimum thresholds."""
    check = {"id": "CORPUS-COVERAGE", "status": "PASS", "details": {"by_band": {}}}
    band_counts = {}
    for fx in fixtures:
        band = fx.get("band", "unknown")
        band_counts[band] = band_counts.get(band, 0) + 1
    check["details"]["by_band"] = band_counts

    # Per-band family coverage
    family_by_band = {}
    for fx in fixtures:
        band = fx.get("band", "unknown")
        family = fx.get("api_family", "unknown")
        family_by_band.setdefault(band, set()).add(family)
    check["details"]["families_by_band"] = {b: sorted(f) for b, f in family_by_band.items()}

    # Core must have >= 3 families
    core_families = family_by_band.get("core", set())
    if len(core_families) < 3:
        check["status"] = "FAIL"
        check["details"]["core_family_deficit"] = f"Need >= 3, have {len(core_families)}"
    return check


def check_registry_alignment(fixtures: list[dict]) -> dict:
    """Verify core registry entries have corresponding fixtures."""
    check = {"id": "CORPUS-REGISTRY", "status": "PASS", "details": {"covered": [], "missing": []}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["registry_exists"] = False
        return check

    registry = json.loads(REGISTRY_PATH.read_text())
    entries = registry.get("behaviors", [])
    fixture_apis = {(fx["api_family"], fx["api_name"]) for fx in fixtures}

    for entry in entries:
        family = entry.get("api_family", "")
        api = entry.get("api_name", "")
        if (family, api) in fixture_apis:
            check["details"]["covered"].append(f"{family}:{api}")
        else:
            check["details"]["missing"].append(f"{family}:{api}")
            if entry.get("band") == "core":
                check["status"] = "FAIL"
    return check


def main():
    logger = configure_test_logging("check_fixture_corpus")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    fixtures = load_fixtures()
    checks = [
        check_corpus_structure(),
        check_capture_programs(),
        check_fixture_validity(fixtures),
        check_fixture_uniqueness(fixtures),
        check_band_coverage(fixtures),
        check_registry_alignment(fixtures),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "fixture_corpus_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
            "total_fixtures": len(fixtures),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Fixture Corpus Verifier ===")
        print(f"Timestamp: {timestamp}\n")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nFixtures: {len(fixtures)}")
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
