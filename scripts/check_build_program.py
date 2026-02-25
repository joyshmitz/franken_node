#!/usr/bin/env python3
"""Verification script for bd-3hig: Multi-Track Build Program (Section 9).

Checks:
  - Required files exist
  - Five build tracks (Track-A through Track-E) documented
  - Exit gates documented for each track
  - Fifteen enhancement maps (9A through 9O) documented
  - Track-to-section mappings (10.1-10.21 referenced)
  - Event codes BLD-001 through BLD-004
  - Invariants INV-BLD-TRACKS, INV-BLD-MAPS, INV-BLD-EXIT, INV-BLD-TRACE
  - Required sections exist in governance doc
  - Spec contract keywords present

Usage:
  python scripts/check_build_program.py          # human-readable output
  python scripts/check_build_program.py --json   # JSON output
"""

import json
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_CONTRACT = os.path.join(ROOT, "docs", "specs", "section_9", "bd-3hig_contract.md")
GOVERNANCE_DOC = os.path.join(ROOT, "docs", "governance", "build_program.md")

REQUIRED_FILES = [SPEC_CONTRACT, GOVERNANCE_DOC]

TRACKS = ["Track-A", "Track-B", "Track-C", "Track-D", "Track-E"]

ENHANCEMENT_MAPS = [f"9{chr(65 + i)}" for i in range(15)]  # 9A..9O

EVENT_CODES = ["BLD-001", "BLD-002", "BLD-003", "BLD-004"]

INVARIANTS = ["INV-BLD-TRACKS", "INV-BLD-MAPS", "INV-BLD-EXIT", "INV-BLD-TRACE"]

REQUIRED_SECTIONS = [
    "Track-A",
    "Track-B",
    "Track-C",
    "Track-D",
    "Track-E",
    "Enhancement Map",
    "Event Code",
    "Invariant",
]

SPEC_KEYWORDS = [
    "Exit Gate",
    "Enhancement Map",
    "Event Code",
    "Invariant",
    "Acceptance Criteria",
]

# Sections that should be referenced in track-to-section mappings
TRACK_SECTIONS = [
    "10.1", "10.2", "10.3", "10.4", "10.5", "10.7", "10.8", "10.9",
    "10.12", "10.13", "10.14", "10.17", "10.18", "10.19", "10.20", "10.21",
]

RESULTS = []


def _check(name, passed, detail=""):
    """Record a single check result."""
    RESULTS.append({"check": name, "passed": passed, "detail": detail})


def _read(path):
    """Read file contents or return empty string if missing."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def check_files_exist():
    """Check that required files exist."""
    for fpath in REQUIRED_FILES:
        rel = os.path.relpath(fpath, ROOT)
        exists = os.path.isfile(fpath)
        _check(f"file_exists:{rel}", exists,
               f"{'found' if exists else 'MISSING'}: {rel}")


def check_five_tracks():
    """Check that all five tracks are documented in both files."""
    spec = _read(SPEC_CONTRACT)
    gov = _read(GOVERNANCE_DOC)
    combined = spec + gov
    for track in TRACKS:
        found = track in combined
        _check(f"track_documented:{track}", found,
               f"{'found' if found else 'MISSING'} in docs")


def check_exit_gates():
    """Check that each track has an exit gate documented."""
    gov = _read(GOVERNANCE_DOC)
    for track in TRACKS:
        # Look for the track heading followed by an Exit Gate section
        track_label = track.replace("-", "-")
        idx = gov.find(f"### {track_label}")
        if idx < 0:
            _check(f"exit_gate:{track}", False, "track section not found")
            continue
        # Check for "Exit Gate" within the track section (next 2000 chars)
        section = gov[idx:idx + 2000]
        has_gate = "Exit Gate" in section
        _check(f"exit_gate:{track}", has_gate,
               f"{'found' if has_gate else 'MISSING'} exit gate for {track}")


def check_enhancement_maps():
    """Check that all 15 enhancement maps are documented."""
    spec = _read(SPEC_CONTRACT)
    gov = _read(GOVERNANCE_DOC)
    combined = spec + gov
    for map_id in ENHANCEMENT_MAPS:
        found = map_id in combined
        _check(f"enhancement_map:{map_id}", found,
               f"{'found' if found else 'MISSING'}: {map_id}")


def check_track_section_mappings():
    """Check that track-to-section mappings reference required 10.x sections."""
    spec = _read(SPEC_CONTRACT)
    gov = _read(GOVERNANCE_DOC)
    combined = spec + gov
    for section in TRACK_SECTIONS:
        found = section in combined
        _check(f"section_mapping:{section}", found,
               f"{'found' if found else 'MISSING'}: {section}")


def check_event_codes():
    """Check that all event codes are documented."""
    spec = _read(SPEC_CONTRACT)
    gov = _read(GOVERNANCE_DOC)
    combined = spec + gov
    for code in EVENT_CODES:
        found = code in combined
        _check(f"event_code:{code}", found,
               f"{'found' if found else 'MISSING'}: {code}")


def check_invariants():
    """Check that all invariants are documented."""
    spec = _read(SPEC_CONTRACT)
    gov = _read(GOVERNANCE_DOC)
    combined = spec + gov
    for inv in INVARIANTS:
        found = inv in combined
        _check(f"invariant:{inv}", found,
               f"{'found' if found else 'MISSING'}: {inv}")


def check_required_sections():
    """Check that required sections exist in the governance doc."""
    gov = _read(GOVERNANCE_DOC)
    for section in REQUIRED_SECTIONS:
        found = section in gov
        _check(f"required_section:{section}", found,
               f"{'found' if found else 'MISSING'} section: {section}")


def check_spec_keywords():
    """Check that spec contract contains expected keywords."""
    spec = _read(SPEC_CONTRACT)
    for kw in SPEC_KEYWORDS:
        found = kw in spec
        _check(f"spec_keyword:{kw}", found,
               f"{'found' if found else 'MISSING'} keyword: {kw}")


def run_all():
    """Run all checks and return summary dict."""
    RESULTS.clear()
    check_files_exist()
    check_five_tracks()
    check_exit_gates()
    check_enhancement_maps()
    check_track_section_mappings()
    check_event_codes()
    check_invariants()
    check_required_sections()
    check_spec_keywords()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["passed"])
    failed = total - passed

    return {
        "bead_id": "bd-3hig",
        "section": "9",
        "title": "Multi-Track Build Program",
        "total": total,
        "passed": passed,
        "failed": failed,
        "ok": failed == 0,
        "checks": RESULTS,
    }


def self_test():
    """Self-test: verify the verification script itself is well-formed."""
    # Check that all expected constants are defined and non-empty
    assert len(TRACKS) == 5, f"Expected 5 tracks, got {len(TRACKS)}"
    assert len(ENHANCEMENT_MAPS) == 15, f"Expected 15 maps, got {len(ENHANCEMENT_MAPS)}"
    assert len(EVENT_CODES) == 4, f"Expected 4 event codes, got {len(EVENT_CODES)}"
    assert len(INVARIANTS) == 4, f"Expected 4 invariants, got {len(INVARIANTS)}"
    assert ENHANCEMENT_MAPS[0] == "9A", f"First map should be 9A, got {ENHANCEMENT_MAPS[0]}"
    assert ENHANCEMENT_MAPS[-1] == "9O", f"Last map should be 9O, got {ENHANCEMENT_MAPS[-1]}"
    assert len(REQUIRED_FILES) == 2, f"Expected 2 required files, got {len(REQUIRED_FILES)}"
    assert len(REQUIRED_SECTIONS) == 8, "Expected 8 required sections"
    assert len(SPEC_KEYWORDS) == 5, "Expected 5 spec keywords"

    # Run checks and verify structure
    result = run_all()
    assert "bead_id" in result and result["bead_id"] == "bd-3hig"
    assert "total" in result and result["total"] > 0
    assert "passed" in result
    assert "failed" in result
    assert "ok" in result
    assert "checks" in result and isinstance(result["checks"], list)
    for check in result["checks"]:
        assert "check" in check
        assert "passed" in check
        assert "detail" in check

    print("self_test passed: all assertions hold")
    return True


def main():
    logger = configure_test_logging("check_build_program")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-3hig: Multi-Track Build Program")
        print(f"{'=' * 50}")
        print(f"Total: {result['total']}  Passed: {result['passed']}  "
              f"Failed: {result['failed']}  OK: {result['ok']}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
