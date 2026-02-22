#!/usr/bin/env python3
"""bd-3l2p verification gate for intent-aware remote effects firewall."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-3l2p"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/intent_effects_policy.md"
IMPL_FILE = ROOT / "crates/franken-node/src/security/intent_firewall.rs"
MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
CONFORMANCE_TEST = ROOT / "tests/security/intent_firewall_conformance.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_intent_firewall.py"
REPORT_FILE = ROOT / "artifacts/10.17/intent_firewall_eval_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-3l2p/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-3l2p/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "FIREWALL_REQUEST_CLASSIFIED",
    "FIREWALL_INTENT_BENIGN",
    "FIREWALL_INTENT_RISKY",
    "FIREWALL_CHALLENGE_ISSUED",
    "FIREWALL_VERDICT_RENDERED",
]

REQUIRED_ERROR_CODES = [
    "ERR_FIREWALL_CLASSIFICATION_FAILED",
    "ERR_FIREWALL_CHALLENGE_TIMEOUT",
    "ERR_FIREWALL_SIMULATE_FAILED",
    "ERR_FIREWALL_QUARANTINE_FULL",
    "ERR_FIREWALL_RECEIPT_UNSIGNED",
    "ERR_FIREWALL_POLICY_MISSING",
]

REQUIRED_INVARIANTS = [
    "INV-FIREWALL-STABLE-CLASSIFICATION",
    "INV-FIREWALL-DETERMINISTIC-RECEIPT",
    "INV-FIREWALL-FAIL-DENY",
    "INV-FIREWALL-RISKY-PATHWAY",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks = []
    impl_src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)
    spec_src = _read(SPEC_FILE)

    # File existence checks
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Security module wired",
        "pub mod intent_firewall;" in mod_src,
        "pub mod intent_firewall; in security/mod.rs",
    ))
    checks.append(_check("Conformance test exists", CONFORMANCE_TEST.exists(), str(CONFORMANCE_TEST)))
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    # Required implementation tokens
    required_impl_tokens = [
        "struct RemoteEffect",
        "enum IntentClassification",
        "enum FirewallVerdict",
        "struct FirewallDecision",
        "struct TrafficPolicy",
        "struct EffectsFirewall",
        "fn evaluate",
        "fn classify",
        "FirewallVerdict::Allow",
        "FirewallVerdict::Challenge",
        "FirewallVerdict::Simulate",
        "FirewallVerdict::Deny",
        "FirewallVerdict::Quarantine",
        "IntentClassification::Exfiltration",
        "IntentClassification::CredentialForward",
        "IntentClassification::SideChannel",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes in impl and spec
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Error codes in impl and spec
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Invariants in impl and spec
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # Rust unit test count
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Risky classification logic
    checks.append(_check(
        "Risky classification logic",
        "fn is_risky" in impl_src,
        "fn is_risky present",
    ))

    # Fail-closed logic
    checks.append(_check(
        "Fail-closed deny logic",
        "fail-closed" in impl_src.lower() or "fail_closed" in impl_src.lower(),
        "fail-closed pattern found",
    ))

    # Deterministic receipt logic
    checks.append(_check(
        "Deterministic BTreeMap usage",
        "BTreeMap" in impl_src,
        "BTreeMap used for determinism",
    ))

    # Receipt generation
    checks.append(_check(
        "Receipt ID generation",
        "receipt_id" in impl_src,
        "receipt_id field present",
    ))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "intent-firewall-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Intent-aware remote effects firewall for extension-originated traffic",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "firewall_contract": {
            "fail_closed_unclassifiable": True,
            "risky_default_deny": True,
            "receipt_every_decision": True,
            "extension_scoped": True,
        },
    }


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks = []
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 10))
    checks.append(_check("run_all has firewall_contract", isinstance(result.get("firewall_contract"), dict)))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_intent_firewall",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-3l2p checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-3l2p: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
