#!/usr/bin/env python3
"""bd-cvt verifier: capability profile narrowing gate for product subsystems."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CAPABILITY_GUARD_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "connector", "capability_guard.rs"
)
MOD_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "connector", "mod.rs"
)
CAPABILITIES_DIR = os.path.join(ROOT, "capabilities")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_11", "bd-cvt_contract.md")
TESTS = os.path.join(ROOT, "tests", "test_check_capability_profiles.py")
EVIDENCE = os.path.join(
    ROOT, "artifacts", "section_10_11", "bd-cvt", "verification_evidence.json"
)

BEAD = "bd-cvt"
SECTION = "10.11"
TITLE = "Capability profiles for product subsystems with narrowing enforcement"


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    # --- File existence ---
    ok("rust_module_exists", os.path.isfile(CAPABILITY_GUARD_RS), CAPABILITY_GUARD_RS)
    ok("spec_contract_exists", os.path.isfile(SPEC), SPEC)
    ok("test_file_exists", os.path.isfile(TESTS), TESTS)

    # --- Module wired into connector/mod.rs ---
    mod_src = _read(MOD_RS)
    ok(
        "module_wired_into_mod_rs",
        "pub mod capability_guard;" in mod_src,
        "connector/mod.rs exports capability_guard",
    )

    # --- Capabilities directory ---
    cap_dir_exists = os.path.isdir(CAPABILITIES_DIR)
    ok("capabilities_dir_exists", cap_dir_exists, CAPABILITIES_DIR)

    toml_files: list[str] = []
    if cap_dir_exists:
        toml_files = [
            f for f in os.listdir(CAPABILITIES_DIR) if f.endswith(".toml")
        ]
    ok(
        "capabilities_profile_count",
        len(toml_files) >= 5,
        f"{len(toml_files)} TOML profiles (>= 5 required)",
    )

    # --- Profile content validation ---
    profiles_valid = True
    profile_detail = []
    for tf in toml_files:
        content = _read(os.path.join(CAPABILITIES_DIR, tf))
        has_meta = "[metadata]" in content and "name" in content and "version" in content and "risk_level" in content
        has_caps = "[capabilities" in content and "justification" in content
        if not (has_meta and has_caps):
            profiles_valid = False
            profile_detail.append(f"{tf}: missing required sections")
    ok(
        "profiles_parse_correctly",
        profiles_valid and len(toml_files) >= 5,
        "; ".join(profile_detail) if profile_detail else f"all {len(toml_files)} profiles valid",
    )

    # --- Rust source checks ---
    src = _read(CAPABILITY_GUARD_RS)

    # Event codes CAP-001 through CAP-008
    event_codes = [f"CAP_{i:03d}" for i in range(1, 9)]
    missing_events = [c for c in event_codes if c not in src]
    ok(
        "event_codes_defined",
        len(missing_events) == 0,
        f"{len(event_codes) - len(missing_events)}/{len(event_codes)} event codes"
        + (f" missing: {', '.join(missing_events)}" if missing_events else ""),
    )

    # Error codes
    error_codes = [
        "ERR_CAP_UNDECLARED",
        "ERR_CAP_DENIED",
        "ERR_CAP_PROFILE_MISSING",
        "ERR_CAP_INVALID_LEVEL",
        "ERR_CAP_AUDIT_FAILURE",
    ]
    missing_errors = [c for c in error_codes if c not in src]
    ok(
        "error_codes_defined",
        len(missing_errors) == 0,
        f"{len(error_codes) - len(missing_errors)}/{len(error_codes)} error codes"
        + (f" missing: {', '.join(missing_errors)}" if missing_errors else ""),
    )

    # Invariants
    invariants = [
        "INV-CAP-LEAST-PRIVILEGE",
        "INV-CAP-DENY-DEFAULT",
        "INV-CAP-AUDIT-COMPLETE",
        "INV-CAP-PROFILE-VERSIONED",
        "INV-CAP-DETERMINISTIC",
    ]
    missing_inv = [i for i in invariants if i not in src]
    ok(
        "invariants_defined",
        len(missing_inv) == 0,
        f"{len(invariants) - len(missing_inv)}/{len(invariants)} invariants"
        + (f" missing: {', '.join(missing_inv)}" if missing_inv else ""),
    )

    # Capability taxonomy completeness (12 capabilities)
    cap_names = [
        "cap:network:listen",
        "cap:network:connect",
        "cap:fs:read",
        "cap:fs:write",
        "cap:fs:temp",
        "cap:process:spawn",
        "cap:crypto:sign",
        "cap:crypto:verify",
        "cap:crypto:derive",
        "cap:trust:read",
        "cap:trust:write",
        "cap:trust:revoke",
    ]
    missing_caps = [c for c in cap_names if c not in src]
    ok(
        "capability_taxonomy_complete",
        len(missing_caps) == 0,
        f"{len(cap_names) - len(missing_caps)}/{len(cap_names)} capabilities"
        + (f" missing: {', '.join(missing_caps)}" if missing_caps else ""),
    )

    # Guard logic implements deny-default
    ok(
        "deny_default_implemented",
        "INV-CAP-DENY-DEFAULT" in src and "CapabilityDenied" in src,
        "deny-default enforcement via CapabilityDenied",
    )

    # Audit trail implemented
    ok(
        "audit_trail_implemented",
        "CapabilityAuditEntry" in src and "audit_trail" in src,
        "CapabilityAuditEntry and audit_trail present",
    )

    # Schema version
    ok(
        "schema_version",
        '"cap-v1.0"' in src,
        "schema version cap-v1.0 defined",
    )

    # BTreeMap usage for determinism
    ok(
        "btreemap_determinism",
        "BTreeMap" in src,
        "BTreeMap used for deterministic output",
    )

    # Test count
    test_count = len(re.findall(r"#\[test\]", src))
    ok(
        "test_count",
        test_count >= 20,
        f"{test_count} tests (>= 20 required)",
    )

    # Evidence file exists and has PASS verdict
    evidence_src = _read(EVIDENCE)
    evidence_pass = False
    if evidence_src:
        try:
            evidence_data = json.loads(evidence_src)
            evidence_pass = evidence_data.get("verdict") == "PASS"
        except (json.JSONDecodeError, KeyError):
            pass
    ok(
        "evidence_pass_verdict",
        evidence_pass,
        "verification_evidence.json has PASS verdict",
    )

    return checks


def self_test() -> dict[str, Any]:
    checks = _checks()
    assert len(checks) >= 11, f"expected >= 11 checks, got {len(checks)}"
    assert all("check" in c and "passed" in c and "detail" in c for c in checks)

    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"

    result = {
        "bead_id": BEAD,
        "section": SECTION,
        "title": TITLE,
        "verdict": verdict,
        "checks_passed": passed,
        "checks_total": total,
        "events": [
            {"code": "CAP-SELF-TEST", "detail": f"self_test: {total} checks validated"}
        ],
        "summary": f"{passed}/{total} checks passed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(f"self_test: {total} checks validated", file=sys.stderr)
    return result


def main() -> int:
    if "--self-test" in sys.argv:
        result = self_test()
        if "--json" in sys.argv:
            print(json.dumps(result, indent=2))
        return 0

    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"

    payload = {
        "bead_id": BEAD,
        "section": SECTION,
        "title": TITLE,
        "gate_script": os.path.basename(__file__),
        "checks_passed": passed,
        "checks_total": total,
        "verdict": verdict,
        "checks": checks,
    }

    if "--json" in sys.argv:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{BEAD}: {verdict} ({passed}/{total})")
        for c in checks:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
