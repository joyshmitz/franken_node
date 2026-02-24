#!/usr/bin/env python3
"""Verification script for bd-24s: Snapshot Policy and Bounded Replay Targets."""

import json
import os
import re
import subprocess
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

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
    logger = configure_test_logging("check_snapshot_policy")
    print("bd-24s: Snapshot Policy and Bounded Replay — Verification\n")
    all_pass = True

    # SNAP-IMPL: Implementation file exists with key types
    impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/snapshot_policy.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = __import__("pathlib").Path(impl_path).read_text(encoding="utf-8")
        has_policy = "struct SnapshotPolicy" in content
        has_tracker = "struct SnapshotTracker" in content
        has_record = "struct SnapshotRecord" in content
        has_replay = "struct ReplayTarget" in content
        all_types = has_policy and has_tracker and has_record and has_replay
    else:
        all_types = False
    all_pass &= check("SNAP-IMPL", "Implementation with SnapshotPolicy, Tracker, Record, ReplayTarget",
                      impl_exists and all_types)

    # SNAP-TRIGGERS: Policy has both every_updates and every_bytes
    if impl_exists:
        content = __import__("pathlib").Path(impl_path).read_text(encoding="utf-8")
        has_updates = "every_updates" in content
        has_bytes = "every_bytes" in content
        all_pass &= check("SNAP-TRIGGERS", "Both snapshot triggers (every_updates, every_bytes)",
                          has_updates and has_bytes)
    else:
        all_pass &= check("SNAP-TRIGGERS", "Both snapshot triggers", False)

    # SNAP-ERRORS: All 4 error codes present
    if impl_exists:
        content = __import__("pathlib").Path(impl_path).read_text(encoding="utf-8")
        errors = ["SNAPSHOT_HASH_MISMATCH", "SNAPSHOT_STALE", "REPLAY_BOUND_EXCEEDED", "POLICY_INVALID"]
        found = [e for e in errors if e in content]
        all_pass &= check("SNAP-ERRORS", "All 4 error codes present",
                          len(found) == 4, f"found {len(found)}/4")
    else:
        all_pass &= check("SNAP-ERRORS", "All 4 error codes present", False)

    # SNAP-AUDIT: Policy audit record type exists
    if impl_exists:
        content = __import__("pathlib").Path(impl_path).read_text(encoding="utf-8")
        has_audit = "struct PolicyAuditRecord" in content and "audit_log" in content
        all_pass &= check("SNAP-AUDIT", "Policy change audit records", has_audit)
    else:
        all_pass &= check("SNAP-AUDIT", "Policy change audit records", False)

    # SNAP-FIXTURES: Fixture files exist
    fixture_dir = os.path.join(ROOT, "fixtures/snapshot_policy")
    expected = ["trigger_scenarios.json", "replay_bound_scenarios.json", "policy_audit_scenarios.json"]
    found_fixtures = [f for f in expected if os.path.isfile(os.path.join(fixture_dir, f))]
    all_pass &= check("SNAP-FIXTURES", "Fixture files for triggers, replay, audit",
                      len(found_fixtures) == len(expected),
                      f"found {len(found_fixtures)}/{len(expected)}")

    # SNAP-FIXTURE-VALID: Fixtures are valid JSON
    fixture_valid = True
    for f in expected:
        fpath = os.path.join(fixture_dir, f)
        if os.path.isfile(fpath):
            try:
                data = json.loads(__import__("pathlib").Path(fpath).read_text(encoding="utf-8"))
                if "cases" not in data or len(data["cases"]) == 0:
                    fixture_valid = False
            except (json.JSONDecodeError, KeyError):
                fixture_valid = False
        else:
            fixture_valid = False
    all_pass &= check("SNAP-FIXTURE-VALID", "Fixtures are valid JSON with cases", fixture_valid)

    # SNAP-CONFORMANCE: Conformance test file exists
    conf_path = os.path.join(ROOT, "tests/conformance/snapshot_policy_conformance.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = __import__("pathlib").Path(conf_path).read_text(encoding="utf-8")
        has_trigger = "trigger" in content.lower()
        has_replay = "replay" in content.lower()
        has_hash = "hash" in content.lower()
        has_monotonic = "monotonic" in content.lower() or "must_increase" in content.lower()
        has_audit = "audit" in content.lower()
        all_aspects = has_trigger and has_replay and has_hash and has_monotonic and has_audit
    else:
        all_aspects = False
    all_pass &= check("SNAP-CONFORMANCE", "Conformance tests cover triggers, replay, hash, monotonicity, audit",
                      conf_exists and all_aspects)

    # SNAP-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            ["cargo", "test", "--", "connector::snapshot_policy"],
            capture_output=True, text=True, timeout=120,
            cwd=os.path.join(ROOT, "crates/franken-node")
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("SNAP-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("SNAP-TESTS", "Rust unit tests pass", False, str(e))

    # SNAP-SPEC: Spec contract exists
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-24s_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = __import__("pathlib").Path(spec_path).read_text(encoding="utf-8")
        has_triggers = "every_updates" in content and "every_bytes" in content
        has_invariants = "INV-SNAP" in content
    else:
        has_triggers = False
        has_invariants = False
    all_pass &= check("SNAP-SPEC", "Specification contract with triggers and invariants",
                      spec_exists and has_triggers and has_invariants)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "snapshot_policy_verification",
        "bead": "bd-24s",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-24s")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
