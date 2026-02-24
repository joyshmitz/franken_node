#!/usr/bin/env python3
"""bd-26mk verification gate for security staking and slashing governance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD = "bd-26mk"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/policy/security_staking_and_slashing.md"
IMPL_FILE = ROOT / "crates/franken-node/src/registry/staking_governance.rs"
MOD_FILE = ROOT / "crates/franken-node/src/registry/mod.rs"
MAIN_FILE = ROOT / "crates/franken-node/src/main.rs"
INTEGRATION_TEST = ROOT / "tests/integration/staking_slashing_flows.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_staking_governance.py"
REPORT_FILE = ROOT / "artifacts/10.17/staking_ledger_snapshot.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-26mk/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-26mk/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "STAKE_DEPOSIT_RECEIVED",
    "STAKE_GATE_EVALUATED",
    "SLASH_INITIATED",
    "SLASH_EXECUTED",
    "APPEAL_FILED",
]

REQUIRED_ERROR_CODES = [
    "ERR_STAKE_INSUFFICIENT",
    "ERR_STAKE_GATE_DENIED",
    "ERR_SLASH_EVIDENCE_INVALID",
    "ERR_SLASH_ALREADY_EXECUTED",
    "ERR_APPEAL_EXPIRED",
    "ERR_STAKE_WITHDRAWAL_LOCKED",
]

REQUIRED_INVARIANTS = [
    "INV-STAKE-GATE-REQUIRED",
    "INV-SLASH-DETERMINISTIC",
    "INV-SLASH-AUDIT-TRAIL",
    "INV-APPEAL-WINDOW",
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
    main_src = _read(MAIN_FILE)
    spec_src = _read(SPEC_FILE)

    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Registry mod file exists", MOD_FILE.exists(), str(MOD_FILE)))
    checks.append(_check(
        "Main module wired",
        "pub mod registry;" in main_src,
        "pub mod registry; in main.rs",
    ))
    checks.append(_check(
        "Registry mod exports staking_governance",
        "pub mod staking_governance;" in mod_src,
        "pub mod staking_governance; in registry/mod.rs",
    ))

    # Check required implementation tokens
    required_impl_tokens = [
        "struct StakingLedger",
        "struct SlashingEngine",
        "struct CapabilityStakeGate",
        "struct SlashEvidence",
        "struct StakeRecord",
        "struct StakePolicy",
        "enum RiskTier",
        "enum StakeState",
        "fn deposit",
        "fn slash",
        "fn file_appeal",
        "fn withdraw",
        "fn compute_penalty",
        "fn check_stake",
        "fn generate_snapshot",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Check event codes in implementation and spec
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Check error codes in implementation and spec
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Check invariants in implementation and spec
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # Count Rust unit tests
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Check integration test exists
    checks.append(_check(
        "Integration test exists",
        INTEGRATION_TEST.exists(),
        str(INTEGRATION_TEST),
    ))

    # Check Python checker unit test exists
    checks.append(_check(
        "Python checker unit test exists",
        UNIT_TEST_FILE.exists(),
        str(UNIT_TEST_FILE),
    ))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "staking-governance-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Security staking and slashing framework for publisher trust governance",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "staking_contract": {
            "requires_minimum_stake": True,
            "deterministic_slashing": True,
            "audit_trail_on_every_slash": True,
            "bounded_appeal_window": True,
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
        "name": "check_staking_governance",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_staking_governance")
    parser = argparse.ArgumentParser(description="bd-26mk checker")
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
        print(f"bd-26mk: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
