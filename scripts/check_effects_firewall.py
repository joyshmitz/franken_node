#!/usr/bin/env python3
"""bd-3l2p verifier: intent-aware remote effects firewall for extension-originated traffic."""

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

INTENT_FIREWALL_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "security", "intent_firewall.rs"
)
MOD_RS = os.path.join(
    ROOT, "crates", "franken-node", "src", "security", "mod.rs"
)
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_17", "bd-3l2p_contract.md")
TESTS = os.path.join(ROOT, "tests", "test_check_effects_firewall.py")
EVIDENCE = os.path.join(
    ROOT, "artifacts", "section_10_17", "bd-3l2p", "verification_evidence.json"
)

BEAD = "bd-3l2p"
SECTION = "10.17"
TITLE = "Intent-aware remote effects firewall for extension-originated traffic"


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
    ok("rust_module_exists", os.path.isfile(INTENT_FIREWALL_RS), INTENT_FIREWALL_RS)
    ok("spec_contract_exists", os.path.isfile(SPEC), SPEC)
    ok("test_file_exists", os.path.isfile(TESTS), TESTS)

    # --- Module wired into security/mod.rs ---
    mod_src = _read(MOD_RS)
    ok(
        "module_wired_into_mod_rs",
        "pub mod intent_firewall;" in mod_src,
        "security/mod.rs exports intent_firewall",
    )

    # --- Rust source checks ---
    src = _read(INTENT_FIREWALL_RS)

    # Event codes FW_001 through FW_010
    event_codes = [f"FW_{i:03d}" for i in range(1, 11)]
    missing_events = [c for c in event_codes if c not in src]
    ok(
        "event_codes_defined",
        len(missing_events) == 0,
        f"{len(event_codes) - len(missing_events)}/{len(event_codes)} event codes"
        + (f" missing: {', '.join(missing_events)}" if missing_events else ""),
    )

    # Error codes
    error_codes = [
        "ERR_FW_UNCLASSIFIED",
        "ERR_FW_NO_POLICY",
        "ERR_FW_INVALID_EFFECT",
        "ERR_FW_RECEIPT_FAILED",
        "ERR_FW_POLICY_CONFLICT",
        "ERR_FW_EXTENSION_UNKNOWN",
        "ERR_FW_OVERRIDE_UNAUTHORIZED",
        "ERR_FW_QUARANTINE_FULL",
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
        "INV-FW-FAIL-CLOSED",
        "INV-FW-RECEIPT-EVERY-DECISION",
        "INV-FW-RISKY-DEFAULT-DENY",
        "INV-FW-DETERMINISTIC",
        "INV-FW-EXTENSION-SCOPED",
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
        "EffectsFirewall",
        "IntentClassification",
        "TrafficPolicy",
        "FirewallDecision",
        "RemoteEffect",
        "FirewallVerdict",
        "TrafficPolicyRule",
        "TrafficOrigin",
        "FirewallError",
        "FirewallAuditEvent",
        "IntentClassifier",
        "PolicyOverride",
    ]
    missing_types = [t for t in core_types if t not in src]
    ok(
        "core_types_present",
        len(missing_types) == 0,
        f"{len(core_types) - len(missing_types)}/{len(core_types)} types"
        + (f" missing: {', '.join(missing_types)}" if missing_types else ""),
    )

    # Verdict pathways
    verdict_pathways = ["Allow", "Challenge", "Simulate", "Deny", "Quarantine"]
    missing_verdicts = [v for v in verdict_pathways if v not in src]
    ok(
        "verdict_pathways_present",
        len(missing_verdicts) == 0,
        f"{len(verdict_pathways) - len(missing_verdicts)}/{len(verdict_pathways)} verdict pathways"
        + (f" missing: {', '.join(missing_verdicts)}" if missing_verdicts else ""),
    )

    # Schema version
    ok(
        "schema_version",
        '"fw-v1.0"' in src,
        "schema version fw-v1.0 defined",
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
        "check_effects_firewall.py" in test_src and BEAD in test_src,
        "test file references script + bead",
    )

    return checks


def self_test() -> dict[str, Any]:
    checks = _checks()
    assert len(checks) >= 12, f"expected >= 12 checks, got {len(checks)}"
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
            {"code": "FN-FW-SELF-TEST", "detail": f"self_test: {total} checks validated"}
        ],
        "summary": f"{passed}/{total} checks passed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(f"self_test: {total} checks validated", file=sys.stderr)
    return result


def main() -> int:
    logger = configure_test_logging("check_effects_firewall")
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
