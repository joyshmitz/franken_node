#!/usr/bin/env python3
"""bd-al8i verification gate for L2 engine-boundary N-version semantic oracle."""

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

SPEC_FILE = ROOT / "docs/testing/semantic_oracle_policy.md"
IMPL_FILE = ROOT / "crates/franken-node/src/connector/n_version_oracle.rs"
CONNECTOR_MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
ORACLE_TEST_FILE = ROOT / "tests/oracle/n_version_semantic_oracle.rs"
ORACLE_MOD_FILE = ROOT / "tests/oracle/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_semantic_oracle.py"
DIVERGENCE_MATRIX = ROOT / "artifacts/10.17/semantic_oracle_divergence_matrix.csv"
REPORT_FILE = ROOT / "artifacts/10.17/semantic_oracle_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-al8i/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-al8i/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "ORACLE_HARNESS_START",
    "ORACLE_DIVERGENCE_CLASSIFIED",
    "ORACLE_RISK_TIER_ASSIGNED",
    "ORACLE_RELEASE_BLOCKED",
    "ORACLE_POLICY_RECEIPT_ISSUED",
]

REQUIRED_ERROR_CODES = [
    "ERR_ORACLE_HIGH_RISK_DELTA",
    "ERR_ORACLE_MISSING_RECEIPT",
    "ERR_ORACLE_HARNESS_TIMEOUT",
    "ERR_ORACLE_REFERENCE_UNAVAILABLE",
    "ERR_ORACLE_CLASSIFICATION_AMBIGUOUS",
    "ERR_ORACLE_L1_LINK_BROKEN",
]

REQUIRED_INVARIANTS = [
    "INV-ORACLE-HIGH-RISK-BLOCKS",
    "INV-ORACLE-LOW-RISK-RECEIPTED",
    "INV-ORACLE-DETERMINISTIC-CLASSIFICATION",
    "INV-ORACLE-L1-LINKAGE",
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
    mod_src = _read(CONNECTOR_MOD_FILE)
    spec_src = _read(SPEC_FILE)

    # File existence checks
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Connector mod file exists", CONNECTOR_MOD_FILE.exists(), str(CONNECTOR_MOD_FILE)))
    checks.append(_check(
        "Connector module wired",
        "pub mod n_version_oracle;" in mod_src,
        "pub mod n_version_oracle; in connector/mod.rs",
    ))
    checks.append(_check("Oracle test file exists", ORACLE_TEST_FILE.exists(), str(ORACLE_TEST_FILE)))
    checks.append(_check("Oracle mod file exists", ORACLE_MOD_FILE.exists(), str(ORACLE_MOD_FILE)))
    checks.append(_check("Divergence matrix exists", DIVERGENCE_MATRIX.exists(), str(DIVERGENCE_MATRIX)))

    # Required implementation tokens
    required_impl_tokens = [
        "struct BoundaryDivergence",
        "struct PolicyReceipt",
        "enum RiskTier",
        "enum ReleaseVerdict",
        "enum ReleaseBlockReason",
        "fn classify_divergence",
        "fn run_harness",
        "struct HarnessConfig",
        "struct BoundarySample",
        "struct OracleResult",
        "struct OracleStats",
        "struct ReferenceRuntime",
        "RiskTier::High",
        "RiskTier::Medium",
        "RiskTier::Low",
        "ReleaseVerdict::Passed",
        "ReleaseVerdict::Blocked",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes in impl + spec
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code}", code in impl_src and code in spec_src, code))

    # Error codes in impl + spec
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code}", code in impl_src and code in spec_src, code))

    # Invariants in impl + spec
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv}", inv in impl_src and inv in spec_src, inv))

    # Rust unit test count
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Python checker unit test exists
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    # Divergence matrix has content
    matrix_src = _read(DIVERGENCE_MATRIX)
    matrix_lines = [l for l in matrix_src.strip().splitlines() if l.strip()]
    checks.append(_check(
        "Divergence matrix has header + data",
        len(matrix_lines) >= 2,
        f"{len(matrix_lines)} lines",
    ))
    if matrix_lines:
        header = matrix_lines[0]
        checks.append(_check(
            "Matrix header has risk_tier column",
            "risk_tier" in header,
            header[:80],
        ))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "n-version-oracle-v1.0",
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
        "divergence_contract": {
            "high_risk_blocks_release": True,
            "low_risk_requires_receipt": True,
            "receipts_link_l1_oracle": True,
            "classification_is_deterministic": True,
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
        "name": "check_semantic_oracle",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_semantic_oracle")
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
