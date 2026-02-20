#!/usr/bin/env python3
"""Verification script for bd-1w78: Continuous Lockstep Validation.

Checks that all contract requirements for the continuous lockstep validation
system are satisfied: spec completeness, policy coverage, lockstep architecture,
CI integration, corpus requirements, divergence classification, event codes,
and invariants.

Usage:
    python scripts/check_lockstep_validation.py          # human-readable
    python scripts/check_lockstep_validation.py --json    # machine-readable
"""

import json
import os
import sys
import unittest
from pathlib import Path

BEAD_ID = "bd-1w78"
ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_13" / "bd-1w78_contract.md"
POLICY_PATH = ROOT / "docs" / "policy" / "continuous_lockstep_validation.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_13" / "bd-1w78" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_13" / "bd-1w78" / "verification_summary.md"

EVENT_CODES = ["CLV-001", "CLV-002", "CLV-003", "CLV-004"]
INVARIANTS = [
    "INV-CLV-CONTINUOUS",
    "INV-CLV-COVERAGE",
    "INV-CLV-REGRESSION",
    "INV-CLV-CORPUS",
]

REQUIRED_FILES = [SPEC_PATH, POLICY_PATH, EVIDENCE_PATH, SUMMARY_PATH]


def _read(path: Path) -> str:
    """Read file contents or return empty string if missing."""
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


def check_files_exist() -> dict:
    """Verify all required deliverable files exist."""
    missing = [str(f.relative_to(ROOT)) for f in REQUIRED_FILES if not f.is_file()]
    return {
        "name": "files_exist",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all files present",
    }


def check_spec_completeness() -> dict:
    """Verify the spec contract covers all required sections."""
    content = _read(SPEC_PATH)
    required_sections = [
        "Purpose",
        "Targets",
        "Lockstep Architecture",
        "Event Codes",
        "Invariants",
        "Acceptance Criteria",
    ]
    missing = [s for s in required_sections if s not in content]
    return {
        "name": "spec_completeness",
        "passed": len(missing) == 0,
        "detail": f"missing sections: {missing}" if missing else "all sections present",
    }


def check_lockstep_architecture() -> dict:
    """Verify lockstep oracle architecture (L1 + L2) is documented."""
    spec = _read(SPEC_PATH)
    policy = _read(POLICY_PATH)
    combined = spec + policy
    has_l1 = "L1" in combined and ("Product Layer" in combined or "Product" in combined)
    has_l2 = "L2" in combined and ("Engine Layer" in combined or "Engine" in combined)
    passed = has_l1 and has_l2
    detail_parts = []
    if not has_l1:
        detail_parts.append("missing L1 Product Layer")
    if not has_l2:
        detail_parts.append("missing L2 Engine Layer")
    return {
        "name": "lockstep_architecture",
        "passed": passed,
        "detail": "; ".join(detail_parts) if detail_parts else "L1 + L2 architecture documented",
    }


def check_ci_integration() -> dict:
    """Verify CI integration requirements are documented."""
    policy = _read(POLICY_PATH)
    keywords = ["every", "push", "gate", "block", "merge"]
    found = [k for k in keywords if k.lower() in policy.lower()]
    missing = [k for k in keywords if k.lower() not in policy.lower()]
    passed = len(missing) == 0
    return {
        "name": "ci_integration",
        "passed": passed,
        "detail": f"missing keywords: {missing}" if missing else "CI integration documented",
    }


def check_corpus_requirements() -> dict:
    """Verify corpus management requirements (>= 1000, version-controlled, community)."""
    policy = _read(POLICY_PATH)
    spec = _read(SPEC_PATH)
    combined = policy + spec
    has_min_size = "1000" in combined
    has_version_control = "version-controlled" in combined.lower() or "version control" in combined.lower()
    has_community = "community" in combined.lower() or "pull request" in combined.lower()
    issues = []
    if not has_min_size:
        issues.append("missing 1000 minimum corpus size")
    if not has_version_control:
        issues.append("missing version-control requirement")
    if not has_community:
        issues.append("missing community contribution workflow")
    return {
        "name": "corpus_requirements",
        "passed": len(issues) == 0,
        "detail": "; ".join(issues) if issues else "corpus requirements met",
    }


def check_divergence_classification() -> dict:
    """Verify three-tier divergence classification is documented."""
    policy = _read(POLICY_PATH)
    classes = ["harmless", "acceptable", "blocking"]
    found = [c for c in classes if c.lower() in policy.lower()]
    missing = [c for c in classes if c.lower() not in policy.lower()]
    return {
        "name": "divergence_classification",
        "passed": len(missing) == 0,
        "detail": f"missing classes: {missing}" if missing else "all divergence classes documented",
    }


def check_event_codes() -> dict:
    """Verify all CLV event codes are defined in the spec."""
    spec = _read(SPEC_PATH)
    missing = [code for code in EVENT_CODES if code not in spec]
    return {
        "name": "event_codes",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all event codes defined",
    }


def check_invariants() -> dict:
    """Verify all INV-CLV invariants are defined in the spec."""
    spec = _read(SPEC_PATH)
    missing = [inv for inv in INVARIANTS if inv not in spec]
    return {
        "name": "invariants",
        "passed": len(missing) == 0,
        "detail": f"missing: {missing}" if missing else "all invariants defined",
    }


def check_targets() -> dict:
    """Verify quantitative targets are specified."""
    spec = _read(SPEC_PATH)
    targets = ["95%", "100 ms", "1000", "zero"]
    found = [t for t in targets if t.lower() in spec.lower()]
    missing = [t for t in targets if t.lower() not in spec.lower()]
    return {
        "name": "targets",
        "passed": len(missing) == 0,
        "detail": f"missing targets: {missing}" if missing else "all quantitative targets present",
    }


def check_alerting_policy() -> dict:
    """Verify alerting on score drops is documented."""
    policy = _read(POLICY_PATH)
    has_alert = "alert" in policy.lower()
    has_score_drop = "score drop" in policy.lower() or "drop" in policy.lower()
    passed = has_alert and has_score_drop
    return {
        "name": "alerting_policy",
        "passed": passed,
        "detail": "alerting policy documented" if passed else "missing alerting on score drops",
    }


ALL_CHECKS = [
    check_files_exist,
    check_spec_completeness,
    check_lockstep_architecture,
    check_ci_integration,
    check_corpus_requirements,
    check_divergence_classification,
    check_event_codes,
    check_invariants,
    check_targets,
    check_alerting_policy,
]


def run_all() -> dict:
    """Run all checks and return a consolidated result."""
    results = [fn() for fn in ALL_CHECKS]
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    return {
        "bead_id": BEAD_ID,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": results,
    }


def self_test():
    """Built-in self-test suite for the verification script."""

    class SelfTest(unittest.TestCase):
        def test_bead_id(self):
            self.assertEqual(BEAD_ID, "bd-1w78")

        def test_event_codes_count(self):
            self.assertEqual(len(EVENT_CODES), 4)

        def test_invariants_count(self):
            self.assertEqual(len(INVARIANTS), 4)

        def test_required_files_count(self):
            self.assertEqual(len(REQUIRED_FILES), 4)

        def test_all_checks_count(self):
            self.assertGreaterEqual(len(ALL_CHECKS), 8)

        def test_run_all_structure(self):
            result = run_all()
            self.assertIn("bead_id", result)
            self.assertIn("passed", result)
            self.assertIn("total", result)
            self.assertIn("all_passed", result)
            self.assertIn("checks", result)
            self.assertEqual(result["bead_id"], BEAD_ID)
            self.assertIsInstance(result["checks"], list)

        def test_each_check_returns_dict(self):
            for fn in ALL_CHECKS:
                result = fn()
                self.assertIn("name", result)
                self.assertIn("passed", result)
                self.assertIn("detail", result)

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(SelfTest)
    runner = unittest.TextTestRunner(verbosity=2)
    outcome = runner.run(suite)
    return 0 if outcome.wasSuccessful() else 1


def main():
    if "--self-test" in sys.argv:
        sys.exit(self_test())

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-1w78 Continuous Lockstep Validation: {result['passed']}/{result['total']} checks passed")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['name']}: {check['detail']}")
        print()
        if result["all_passed"]:
            print("Result: ALL CHECKS PASSED")
        else:
            print("Result: SOME CHECKS FAILED")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
