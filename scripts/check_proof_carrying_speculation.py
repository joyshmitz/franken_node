#!/usr/bin/env python3
"""bd-1nl1 verification gate for proof-carrying speculation governance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-1nl1"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/proof_carrying_speculation.md"
IMPL_FILE = ROOT / "crates/franken-node/src/runtime/speculation/proof_executor.rs"
MOD_FILE = ROOT / "crates/franken-node/src/runtime/speculation/mod.rs"
RUNTIME_MOD_FILE = ROOT / "crates/franken-node/src/runtime/mod.rs"
CONFORMANCE_TEST = ROOT / "tests/conformance/proof_speculation_guards.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_proof_carrying_speculation.py"
REPORT_FILE = ROOT / "artifacts/10.17/speculation_proof_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-1nl1/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-1nl1/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "SPECULATION_GUARD_START",
    "SPECULATION_PROOF_ACCEPTED",
    "SPECULATION_ACTIVATED",
    "SPECULATION_DEGRADED",
    "SPECULATION_SAFE_BASELINE_USED",
]

REQUIRED_ERROR_CODES = [
    "ERR_SPEC_MISSING_PROOF",
    "ERR_SPEC_EXPIRED_PROOF",
    "ERR_SPEC_SIGNATURE_INVALID",
    "ERR_SPEC_INTERFACE_UNAPPROVED",
    "ERR_SPEC_GUARD_REJECTED",
    "ERR_SPEC_TRANSFORM_MISMATCH",
]

REQUIRED_INVARIANTS = [
    "INV-SPEC-PROOF-REQUIRED",
    "INV-SPEC-APPROVED-INTERFACE-ONLY",
    "INV-SPEC-FAIL-CLOSED-TO-BASELINE",
    "INV-SPEC-DETERMINISTIC-BASELINE",
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
    runtime_mod_src = _read(RUNTIME_MOD_FILE)
    spec_src = _read(SPEC_FILE)

    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Speculation mod file exists", MOD_FILE.exists(), str(MOD_FILE)))
    checks.append(_check(
        "Runtime module wired",
        "pub mod speculation;" in runtime_mod_src,
        "pub mod speculation; in runtime/mod.rs",
    ))
    checks.append(_check(
        "Speculation mod exports proof_executor",
        "pub mod proof_executor;" in mod_src,
        "pub mod proof_executor; in speculation/mod.rs",
    ))

    required_impl_tokens = [
        "struct ProofReceipt",
        "enum ActivationDecision",
        "fn evaluate_activation",
        "fn execute_with_fallback",
        "fn deterministic_baseline_digest",
        "approved_interfaces",
        "ActivationDecision::Degraded",
        "ActivationDecision::Activated",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code}", code in impl_src and code in spec_src, code))

    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code}", code in impl_src and code in spec_src, code))

    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv}", inv in impl_src and inv in spec_src, inv))

    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    checks.append(_check("Conformance test exists", CONFORMANCE_TEST.exists(), str(CONFORMANCE_TEST)))
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "speculation-proof-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Proof-carrying speculative execution governance",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "guard_contract": {
            "requires_receipt": True,
            "requires_approved_interface": True,
            "guard_failure_degrades_to_baseline": True,
            "activation_only_via_approved_franken_engine_interfaces": True,
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

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_proof_carrying_speculation",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-1nl1 checker")
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
        print(f"bd-1nl1: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
