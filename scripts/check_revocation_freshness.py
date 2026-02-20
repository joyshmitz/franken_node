#!/usr/bin/env python3
"""Verification script for bd-1m8r: Revocation freshness gate per safety tier."""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(check_id, description, passed, details=None):
    entry = {"id": check_id, "description": description, "status": "PASS" if passed else "FAIL"}
    if details:
        entry["details"] = details
    CHECKS.append(entry)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {check_id}: {description}")
    if details:
        print(f"         {details}")
    return passed


def main():
    print("bd-1m8r: Revocation Freshness Gate — Verification\n")
    all_pass = True

    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/revocation_freshness.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_tier = "enum SafetyTier" in content
        has_policy = "struct FreshnessPolicy" in content
        has_decision = "struct FreshnessDecision" in content
        has_error = "enum FreshnessError" in content
        has_evaluate = "fn evaluate_freshness" in content
        has_receipt = "struct OverrideReceipt" in content
        all_types = has_tier and has_policy and has_decision and has_error and has_evaluate and has_receipt
    else:
        all_types = False
    all_pass &= check("RF-IMPL", "Implementation with all required types",
                       impl_exists and all_types)

    if impl_exists:
        content = open(impl_path).read()
        errors = ["RF_STALE_FRONTIER", "RF_OVERRIDE_REQUIRED", "RF_POLICY_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("RF-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("RF-ERRORS", "Error codes", False)

    fixture_path = os.path.join(ROOT, "fixtures/security/freshness_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.load(open(fixture_path))
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("RF-FIXTURES", "Freshness scenarios fixture", fixture_valid)

    decisions_path = os.path.join(ROOT, "artifacts/section_10_13/bd-1m8r/revocation_freshness_decisions.json")
    decisions_valid = False
    if os.path.isfile(decisions_path):
        try:
            data = json.load(open(decisions_path))
            decisions_valid = "decisions" in data and len(data["decisions"]) >= 3
        except json.JSONDecodeError:
            pass
    all_pass &= check("RF-DECISIONS", "Freshness decisions artifact", decisions_valid)

    sec_path = os.path.join(ROOT, "tests/security/revocation_freshness_gate.rs")
    sec_exists = os.path.isfile(sec_path)
    if sec_exists:
        content = open(sec_path).read()
        has_standard = "inv_rf_standard" in content
        has_tier_gate = "inv_rf_tier_gate" in content
        has_override = "inv_rf_override" in content
        has_audit = "inv_rf_audit" in content
    else:
        has_standard = has_tier_gate = has_override = has_audit = False
    all_pass &= check("RF-SEC-TESTS", "Security tests cover all 4 invariants",
                       sec_exists and has_standard and has_tier_gate and has_override and has_audit)

    try:
        result = subprocess.run(
            ["cargo", "test", "-p", "frankenengine-node", "--",
             "security::revocation_freshness"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("RF-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("RF-TESTS", "Rust unit tests pass", False, str(e))

    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1m8r_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-RF" in content
        has_types = "SafetyTier" in content and "FreshnessDecision" in content
    else:
        has_invariants = has_types = False
    all_pass &= check("RF-SPEC", "Specification with invariants and types",
                       spec_exists and has_invariants and has_types)

    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "revocation_freshness_verification",
        "bead": "bd-1m8r",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-1m8r")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
