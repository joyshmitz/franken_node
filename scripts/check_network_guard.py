#!/usr/bin/env python3
"""Verification script for bd-2m2b: Network Guard Egress Layer."""

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
    print("bd-2m2b: Network Guard Egress Layer — Verification\n")
    all_pass = True

    # GUARD-IMPL: Implementation file
    impl_path = os.path.join(ROOT, "crates/franken-node/src/security/network_guard.rs")
    impl_exists = os.path.isfile(impl_path)
    if impl_exists:
        content = open(impl_path).read()
        has_guard = "struct NetworkGuard" in content
        has_policy = "struct EgressPolicy" in content
        has_rule = "struct EgressRule" in content
        has_audit = "struct AuditEvent" in content
        all_types = has_guard and has_policy and has_rule and has_audit
    else:
        all_types = False
    all_pass &= check("GUARD-IMPL", "Implementation with guard, policy, rules, audit events",
                      impl_exists and all_types)

    # GUARD-PROTOCOLS: HTTP and TCP support
    if impl_exists:
        content = open(impl_path).read()
        has_http = "Http" in content
        has_tcp = "Tcp" in content
        all_pass &= check("GUARD-PROTOCOLS", "HTTP and TCP protocol support", has_http and has_tcp)
    else:
        all_pass &= check("GUARD-PROTOCOLS", "Protocol support", False)

    # GUARD-ERRORS: All 3 error codes
    if impl_exists:
        content = open(impl_path).read()
        errors = ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]
        found = [e for e in errors if e in content]
        all_pass &= check("GUARD-ERRORS", "All 3 error codes present",
                          len(found) == 3, f"found {len(found)}/3")
    else:
        all_pass &= check("GUARD-ERRORS", "Error codes", False)

    # GUARD-FIXTURES: Fixture files
    fixture_path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
    fixture_valid = False
    if os.path.isfile(fixture_path):
        try:
            data = json.load(open(fixture_path))
            fixture_valid = "cases" in data and len(data["cases"]) >= 4
        except json.JSONDecodeError:
            pass
    all_pass &= check("GUARD-FIXTURES", "Egress policy fixture with scenarios", fixture_valid)

    # GUARD-AUDIT-SAMPLES: Audit JSONL samples
    audit_path = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl")
    audit_valid = False
    if os.path.isfile(audit_path):
        lines = open(audit_path).readlines()
        audit_valid = len(lines) >= 2
        for line in lines:
            if line.strip():
                try:
                    event = json.loads(line)
                    if "trace_id" not in event or "action" not in event:
                        audit_valid = False
                except json.JSONDecodeError:
                    audit_valid = False
    all_pass &= check("GUARD-AUDIT-SAMPLES", "Audit JSONL samples with trace IDs", audit_valid)

    # GUARD-CONFORMANCE: Conformance test file
    conf_path = os.path.join(ROOT, "tests/conformance/network_guard_policy.rs")
    conf_exists = os.path.isfile(conf_path)
    if conf_exists:
        content = open(conf_path).read()
        has_deny = "default_deny" in content or "deny" in content.lower()
        has_order = "order" in content.lower()
        has_audit = "audit" in content.lower()
    else:
        has_deny = has_order = has_audit = False
    all_pass &= check("GUARD-CONFORMANCE", "Conformance tests cover deny, ordering, audit",
                      conf_exists and has_deny and has_order and has_audit)

    # GUARD-TESTS: Rust tests pass
    try:
        result = subprocess.run(
            ["cargo", "test", "-p", "frankenengine-node", "--", "security::network_guard"],
            capture_output=True, text=True, timeout=120,
            cwd=ROOT
        )
        test_output = result.stdout + result.stderr
        match = re.search(r"test result: ok\. (\d+) passed", test_output)
        rust_tests = int(match.group(1)) if match else 0
        tests_pass = result.returncode == 0 and rust_tests > 0
        all_pass &= check("GUARD-TESTS", "Rust unit tests pass", tests_pass,
                          f"{rust_tests} tests passed")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        all_pass &= check("GUARD-TESTS", "Rust unit tests pass", False, str(e))

    # GUARD-SPEC: Spec contract
    spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2m2b_contract.md")
    spec_exists = os.path.isfile(spec_path)
    if spec_exists:
        content = open(spec_path).read()
        has_invariants = "INV-GUARD" in content
        has_audit = "Audit Event" in content
    else:
        has_invariants = has_audit = False
    all_pass &= check("GUARD-SPEC", "Specification with invariants and audit event schema",
                      spec_exists and has_invariants and has_audit)

    # Summary
    passing = sum(1 for c in CHECKS if c["status"] == "PASS")
    total = len(CHECKS)
    print(f"\nResult: {passing}/{total} checks passed")

    evidence = {
        "gate": "network_guard_verification",
        "bead": "bd-2m2b",
        "section": "10.13",
        "verdict": "PASS" if all_pass else "FAIL",
        "checks": CHECKS,
        "summary": {"total_checks": total, "passing_checks": passing, "failing_checks": total - passing}
    }

    evidence_dir = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b")
    os.makedirs(evidence_dir, exist_ok=True)
    with open(os.path.join(evidence_dir, "verification_evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
