#!/usr/bin/env python3
"""bd-3vm verifier: ambient-authority audit gate for security-critical modules."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTHORITY_AUDIT_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "runtime", "authority_audit.rs"
)
MOD_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "runtime", "mod.rs"
)
CONFIG_TOML = os.path.join(ROOT, "config", "security_critical_modules.toml")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_11", "bd-3vm_contract.md")
TESTS = os.path.join(ROOT, "tests", "test_check_ambient_authority.py")
EVIDENCE = os.path.join(
    ROOT, "artifacts", "section_10_11", "bd-3vm", "verification_evidence.json"
)

BEAD = "bd-3vm"
SECTION = "10.11"
TITLE = "Ambient-authority audit gate for security-critical modules"


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
    ok("rust_module_exists", os.path.isfile(AUTHORITY_AUDIT_RS), AUTHORITY_AUDIT_RS)
    ok("config_inventory_exists", os.path.isfile(CONFIG_TOML), CONFIG_TOML)
    ok("spec_contract_exists", os.path.isfile(SPEC), SPEC)
    ok("test_file_exists", os.path.isfile(TESTS), TESTS)

    # --- Module wired into runtime/mod.rs ---
    mod_src = _read(MOD_RS)
    ok(
        "module_wired_into_mod_rs",
        "pub mod authority_audit;" in mod_src,
        "runtime/mod.rs exports authority_audit",
    )

    # --- Rust source checks ---
    src = _read(AUTHORITY_AUDIT_RS)

    # Event codes FN-AA-001 through FN-AA-008
    event_codes = [f"FN_AA_{i:03d}" for i in range(1, 9)]
    missing_events = [c for c in event_codes if c not in src]
    ok(
        "event_codes_defined",
        len(missing_events) == 0,
        f"{len(event_codes) - len(missing_events)}/{len(event_codes)} event codes"
        + (f" missing: {', '.join(missing_events)}" if missing_events else ""),
    )

    # Error codes
    error_codes = [
        "ERR_AA_MISSING_CAPABILITY",
        "ERR_AA_AMBIENT_DETECTED",
        "ERR_AA_INVENTORY_STALE",
        "ERR_AA_AUDIT_INCOMPLETE",
        "ERR_AA_GUARD_BYPASSED",
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
        "INV-AA-NO-AMBIENT",
        "INV-AA-GUARD-ENFORCED",
        "INV-AA-AUDIT-COMPLETE",
        "INV-AA-INVENTORY-CURRENT",
        "INV-AA-DETERMINISTIC",
    ]
    missing_inv = [i for i in invariants if i not in src]
    ok(
        "invariants_defined",
        len(missing_inv) == 0,
        f"{len(invariants) - len(missing_inv)}/{len(invariants)} invariants"
        + (f" missing: {', '.join(missing_inv)}" if missing_inv else ""),
    )

    # Core types
    core_types = [
        "AuthorityAuditGuard",
        "CapabilityContext",
        "SecurityCriticalInventory",
        "SecurityCriticalModule",
        "AmbientAuthorityViolation",
        "AuditReport",
        "AuditEvent",
        "ModuleAuditResult",
        "AmbientAuthorityPattern",
        "RiskLevel",
        "Capability",
    ]
    missing_types = [t for t in core_types if t not in src]
    ok(
        "core_types_present",
        len(missing_types) == 0,
        f"{len(core_types) - len(missing_types)}/{len(core_types)} types"
        + (f" missing: {', '.join(missing_types)}" if missing_types else ""),
    )

    # Audit report generation
    ok(
        "audit_report_generation",
        "generate_audit_report" in src and "audit_all" in src,
        "generate_audit_report and audit_all functions present",
    )

    # Capability taxonomy completeness (>= 10 capabilities)
    cap_labels = [
        "key_access",
        "artifact_signing",
        "signature_verification",
        "epoch_store_access",
        "trust_state_mutation",
        "network_egress",
        "file_system_read",
        "file_system_write",
        "policy_evaluation",
        "revocation_access",
    ]
    missing_caps = [c for c in cap_labels if c not in src]
    ok(
        "capability_taxonomy_complete",
        len(missing_caps) == 0,
        f"{len(cap_labels) - len(missing_caps)}/{len(cap_labels)} capabilities"
        + (f" missing: {', '.join(missing_caps)}" if missing_caps else ""),
    )

    # Schema version
    ok(
        "schema_version",
        '"aa-v1.0"' in src,
        "schema version aa-v1.0 defined",
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

    # Config TOML content checks
    config_src = _read(CONFIG_TOML)
    ok(
        "config_has_modules",
        "module_path" in config_src and "required_capabilities" in config_src and "risk_level" in config_src,
        "config TOML has module_path, required_capabilities, risk_level fields",
    )

    # Spec contract content checks
    spec_src = _read(SPEC)
    ok(
        "spec_has_invariants",
        all(i in spec_src for i in invariants),
        "spec contract contains all invariants",
    )

    # Tests reference the gate script and bead
    if os.path.isfile(TESTS):
        test_src = _read(TESTS)
    else:
        test_src = ""
    ok(
        "tests_reference_script",
        "check_ambient_authority.py" in test_src and BEAD in test_src,
        "test file references script + bead",
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
            {"code": "FN-AA-SELF-TEST", "detail": f"self_test: {total} checks validated"}
        ],
        "summary": f"{passed}/{total} checks passed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(f"self_test: {total} checks validated", file=sys.stderr)
    return result


def main() -> int:
    logger = configure_test_logging("check_ambient_authority")
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
