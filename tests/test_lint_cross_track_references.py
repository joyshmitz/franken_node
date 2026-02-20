#!/usr/bin/env python3
"""Tests for cross-track canonical-reference linter."""

import sys
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from lint_cross_track_references import (
    extract_objective_text,
    extract_section,
    find_referenced_tracks,
    is_integration_bead,
    lint_bead,
)


def test_extract_section():
    assert extract_section("[10.15] Some bead title") == "10.15"
    assert extract_section("[10.2] Another bead") == "10.2"
    assert extract_section("No section prefix here") is None
    assert extract_section("[PLAN] Master graph") is None


def test_find_referenced_tracks():
    assert find_referenced_tracks("from 10.14 and 10.13") == ["10.14", "10.13"]
    assert find_referenced_tracks("no track refs here") == []
    assert find_referenced_tracks("10.15 10.17") == ["10.15", "10.17"]


def test_extract_objective_text_strips_boilerplate():
    desc = """Task Objective:
Build the integration bridge for control plane.

Acceptance Criteria:
- All integration points tested.

Testing & Logging Requirements:
- Unit tests for integration tests and e2e.
- Integration tests with full coverage.

Task-Specific Clarification:
- Integration/E2E scripts required."""

    result = extract_objective_text(desc)
    # Should keep Task Objective and Acceptance Criteria
    assert "Build the integration bridge" in result
    assert "All integration points tested" in result
    # Should strip Testing & Logging and Task-Specific Clarification
    assert "Unit tests for integration tests" not in result
    assert "Integration/E2E scripts required" not in result


def test_is_integration_bead_true():
    title = "[10.15] Integrate canonical fault harness (from `10.14`)"
    desc = "Task Objective:\nIntegrate the canonical fault harness from 10.14."
    assert is_integration_bead(title, desc) is True


def test_is_integration_bead_false_boilerplate_only():
    title = "[10.14] Build fault harness core"
    desc = """Task Objective:
Build the core fault harness for cancellation injection.

Acceptance Criteria:
- All cancellation points covered.

Testing & Logging Requirements:
- Unit tests for all injection points.
- Integration tests covering fault scenarios.
- E2E test scripts for full integration/e2e pipeline."""

    # "integration" only appears in boilerplate, should NOT match
    assert is_integration_bead(title, desc) is False


def test_is_integration_bead_cross_track_keywords():
    title = "[10.15] Enforce canonical DPOR exploration"
    desc = "Task Objective:\nAdopt DPOR schedule exploration from `10.14`."
    assert is_integration_bead(title, desc) is True

    title2 = "[10.20] Cross-track dependency scanning"
    desc2 = "Task Objective:\nCross-section dependency integration."
    assert is_integration_bead(title2, desc2) is True


def test_lint_bead_finds_missing_ref():
    registry = {
        "capabilities": [
            {
                "id": "CAP-001",
                "domain": "Fault harness, cancellation injection",
                "canonical_owner": "10.14",
                "integration_tracks": ["10.15", "10.20"],
            }
        ]
    }
    bead = {
        "id": "bd-test1",
        "title": "[10.15] Integrate fault harness for control plane",
        "description": (
            "Task Objective:\n"
            "Integrate the canonical fault harness into 10.15 control plane.\n"
            "References 10.13 for auth channel.\n"
            "Acceptance Criteria:\n- Cancellation injection gates active."
        ),
    }
    findings = lint_bead(bead, registry)
    assert len(findings) == 1
    assert findings[0]["capability"] == "CAP-001"
    assert findings[0]["canonical_owner"] == "10.14"
    assert findings[0]["category"] == "missing_canonical_reference"


def test_lint_bead_pass_when_owner_referenced():
    registry = {
        "capabilities": [
            {
                "id": "CAP-001",
                "domain": "Fault harness, cancellation injection",
                "canonical_owner": "10.14",
                "integration_tracks": ["10.15"],
            }
        ]
    }
    bead = {
        "id": "bd-test2",
        "title": "[10.15] Integrate fault harness from 10.14",
        "description": (
            "Task Objective:\n"
            "Integrate the canonical fault harness from 10.14.\n"
            "Cancellation injection gates enforced."
        ),
    }
    findings = lint_bead(bead, registry)
    assert len(findings) == 0


def test_lint_bead_skips_non_integration():
    registry = {
        "capabilities": [
            {
                "id": "CAP-001",
                "domain": "Fault harness",
                "canonical_owner": "10.14",
                "integration_tracks": ["10.15"],
            }
        ]
    }
    bead = {
        "id": "bd-test3",
        "title": "[10.14] Build core fault harness",
        "description": (
            "Task Objective:\nBuild the core fault harness.\n\n"
            "Testing & Logging Requirements:\n- Integration tests."
        ),
    }
    findings = lint_bead(bead, registry)
    assert len(findings) == 0


if __name__ == "__main__":
    tests = [
        test_extract_section,
        test_find_referenced_tracks,
        test_extract_objective_text_strips_boilerplate,
        test_is_integration_bead_true,
        test_is_integration_bead_false_boilerplate_only,
        test_is_integration_bead_cross_track_keywords,
        test_lint_bead_finds_missing_ref,
        test_lint_bead_pass_when_owner_referenced,
        test_lint_bead_skips_non_integration,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR {t.__name__}: {e}")
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
