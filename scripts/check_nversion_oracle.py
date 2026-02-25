#!/usr/bin/env python3
"""bd-al8i verification gate for N-version semantic oracle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD = "bd-al8i"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-al8i_contract.md"
IMPL_FILE = ROOT / "crates/franken-node/src/runtime/nversion_oracle.rs"
RUNTIME_MOD_FILE = ROOT / "crates/franken-node/src/runtime/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_nversion_oracle.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-al8i/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-al8i/verification_summary.md"
CSV_FILE = ROOT / "artifacts/10.17/semantic_oracle_divergence_matrix.csv"

REQUIRED_EVENT_CODES = [
    "FN-NV-001",
    "FN-NV-002",
    "FN-NV-003",
    "FN-NV-004",
    "FN-NV-005",
    "FN-NV-006",
    "FN-NV-007",
    "FN-NV-008",
    "FN-NV-009",
    "FN-NV-010",
    "FN-NV-011",
    "FN-NV-012",
]

REQUIRED_ERROR_CODES = [
    "ERR_NVO_NO_RUNTIMES",
    "ERR_NVO_QUORUM_FAILED",
    "ERR_NVO_RUNTIME_NOT_FOUND",
    "ERR_NVO_CHECK_ALREADY_RUNNING",
    "ERR_NVO_DIVERGENCE_UNRESOLVED",
    "ERR_NVO_POLICY_MISSING",
    "ERR_NVO_INVALID_RECEIPT",
    "ERR_NVO_L1_LINKAGE_BROKEN",
    "ERR_NVO_VOTING_TIMEOUT",
    "ERR_NVO_DUPLICATE_RUNTIME",
]

REQUIRED_INVARIANTS = [
    "INV-NVO-QUORUM",
    "INV-NVO-RISK-TIERED",
    "INV-NVO-BLOCK-HIGH",
    "INV-NVO-POLICY-RECEIPT",
    "INV-NVO-L1-LINKAGE",
    "INV-NVO-DETERMINISTIC",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks: list[dict] = []
    impl_src = _read(IMPL_FILE)
    spec_src = _read(SPEC_FILE)
    runtime_mod_src = _read(RUNTIME_MOD_FILE)

    # --- File existence ---
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Runtime module wired",
        "pub mod nversion_oracle;" in runtime_mod_src,
        "pub mod nversion_oracle; in runtime/mod.rs",
    ))
    checks.append(_check(
        "Python checker unit test exists",
        UNIT_TEST_FILE.exists(),
        str(UNIT_TEST_FILE),
    ))
    checks.append(_check(
        "CSV divergence matrix exists",
        CSV_FILE.exists(),
        str(CSV_FILE),
    ))

    # --- Implementation tokens ---
    required_impl_tokens = [
        "struct RuntimeOracle",
        "struct SemanticDivergence",
        "struct CrossRuntimeCheck",
        "struct VotingResult",
        "enum RiskTier",
        "struct PolicyReceipt",
        "enum OracleVerdict",
        "struct RuntimeEntry",
        "struct L1LinkageProof",
        "struct DivergenceReport",
        "enum CheckOutcome",
        "enum BoundaryScope",
        "fn register_runtime",
        "fn remove_runtime",
        "fn run_cross_check",
        "fn classify_divergence",
        "fn vote",
        "fn tally_votes",
        "fn issue_policy_receipt",
        "fn verify_l1_linkage",
        "fn generate_report",
        "fn check_release_gate",
        "fn resolve_divergence",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # --- Event codes ---
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # --- Error codes ---
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # --- Invariants ---
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # --- Rust unit tests ---
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 25", test_count >= 25, f"found {test_count}"))

    # --- Schema version ---
    checks.append(_check(
        "Schema version nvo-v1.0",
        'nvo-v1.0' in impl_src and 'nvo-v1.0' in spec_src,
        "SCHEMA_VERSION = nvo-v1.0",
    ))

    # --- BTreeMap for determinism ---
    checks.append(_check(
        "BTreeMap used for determinism",
        "BTreeMap" in impl_src,
        "INV-NVO-DETERMINISTIC enforced via BTreeMap",
    ))

    # --- Release gate semantics ---
    checks.append(_check(
        "blocks_release method present",
        "fn blocks_release" in impl_src,
        "blocks_release()",
    ))
    checks.append(_check(
        "requires_receipt method present",
        "fn requires_receipt" in impl_src,
        "requires_receipt()",
    ))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "nvo-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "L2 engine-boundary N-version semantic oracle",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "release_gate_semantics": {
            "critical_blocks": True,
            "high_blocks": True,
            "medium_warns": True,
            "low_requires_receipt": True,
            "info_no_action": True,
        },
    }


def write_report(result: dict) -> None:
    out = ROOT / "artifacts/section_10_17/bd-al8i/check_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks: list[dict] = []
    checks.append(_check("event code count >= 12", len(REQUIRED_EVENT_CODES) >= 12))
    checks.append(_check("error code count >= 10", len(REQUIRED_ERROR_CODES) >= 10))
    checks.append(_check("invariant count >= 6", len(REQUIRED_INVARIANTS) >= 6))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 20))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_nversion_oracle",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_nversion_oracle")
    parser = argparse.ArgumentParser(description="bd-al8i checker")
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
        print(f"bd-al8i: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
