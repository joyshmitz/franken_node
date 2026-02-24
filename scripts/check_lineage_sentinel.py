#!/usr/bin/env python3
"""bd-2iyk verification gate for information-flow lineage and exfiltration sentinel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD = "bd-2iyk"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/information_flow_sentinel.md"
IMPL_FILE = ROOT / "crates/franken-node/src/security/lineage_tracker.rs"
SECURITY_MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
SCENARIO_TEST_FILE = ROOT / "tests/security/exfiltration_sentinel_scenarios.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_lineage_sentinel.py"
REPORT_FILE = ROOT / "artifacts/10.17/exfiltration_detector_metrics.csv"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-2iyk/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-2iyk/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "LINEAGE_TAG_ATTACHED",
    "LINEAGE_FLOW_TRACKED",
    "SENTINEL_SCAN_START",
    "SENTINEL_EXFIL_DETECTED",
    "SENTINEL_CONTAINMENT_TRIGGERED",
]

REQUIRED_ERROR_CODES = [
    "ERR_LINEAGE_TAG_MISSING",
    "ERR_LINEAGE_FLOW_BROKEN",
    "ERR_SENTINEL_RECALL_BELOW_THRESHOLD",
    "ERR_SENTINEL_PRECISION_BELOW_THRESHOLD",
    "ERR_SENTINEL_CONTAINMENT_FAILED",
    "ERR_SENTINEL_COVERT_CHANNEL",
]

REQUIRED_INVARIANTS = [
    "INV-LINEAGE-TAG-PERSISTENCE",
    "INV-SENTINEL-RECALL-THRESHOLD",
    "INV-SENTINEL-PRECISION-THRESHOLD",
    "INV-SENTINEL-AUTO-CONTAIN",
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
    spec_src = _read(SPEC_FILE)
    security_mod_src = _read(SECURITY_MOD_FILE)

    # File existence checks
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Security module wired",
        "pub mod lineage_tracker;" in security_mod_src,
        "pub mod lineage_tracker; in security/mod.rs",
    ))
    checks.append(_check(
        "Scenario test file exists",
        SCENARIO_TEST_FILE.exists(),
        str(SCENARIO_TEST_FILE),
    ))
    checks.append(_check(
        "Metrics report exists",
        REPORT_FILE.exists(),
        str(REPORT_FILE),
    ))

    # Core implementation tokens
    required_impl_tokens = [
        "struct TaintLabel",
        "struct TaintSet",
        "struct FlowEdge",
        "struct TaintBoundary",
        "struct ExfiltrationAlert",
        "struct ContainmentReceipt",
        "struct SentinelConfig",
        "struct LineageGraph",
        "struct ExfiltrationSentinel",
        "struct SentinelScanResult",
        "struct SentinelMetrics",
        "struct CovertChannelDetection",
        "enum FlowVerdict",
        "enum LineageError",
        "fn evaluate_edge",
        "fn scan_graph",
        "fn evaluate_metrics",
        "fn detect_covert_channels",
        "fn attach_lineage_tag",
        "fn track_flow",
        "fn propagate_taint",
        "fn assign_taint",
        "fn append_edge",
        "fn snapshot",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes in implementation and spec
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Error codes in implementation and spec
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Invariants in implementation and spec
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # Rust unit test count
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Scenario test count
    scenario_src = _read(SCENARIO_TEST_FILE)
    scenario_test_count = scenario_src.count("#[test]")
    checks.append(_check(
        "Scenario tests >= 10",
        scenario_test_count >= 10,
        f"found {scenario_test_count}",
    ))

    # Python checker unit test exists
    checks.append(_check(
        "Python checker unit test exists",
        UNIT_TEST_FILE.exists(),
        str(UNIT_TEST_FILE),
    ))

    # Metrics CSV check
    if REPORT_FILE.exists():
        csv_content = _read(REPORT_FILE)
        lines = [l.strip() for l in csv_content.strip().split("\n") if l.strip()]
        checks.append(_check(
            "Metrics CSV has header + data rows",
            len(lines) >= 3,
            f"found {len(lines)} lines",
        ))
        # Check aggregate recall/precision in last row
        if lines:
            last_row = lines[-1].split(",")
            if len(last_row) >= 7:
                try:
                    recall_ok = last_row[6].strip().lower() == "true"
                    precision_ok = last_row[7].strip().lower() == "true"
                    checks.append(_check(
                        "Aggregate recall above threshold",
                        recall_ok,
                        f"recall_ok={last_row[6].strip()}",
                    ))
                    checks.append(_check(
                        "Aggregate precision above threshold",
                        precision_ok,
                        f"precision_ok={last_row[7].strip()}",
                    ))
                except (IndexError, ValueError):
                    checks.append(_check("Metrics CSV parseable", False, "parse error"))
    else:
        checks.append(_check("Metrics CSV has header + data rows", False, "file missing"))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "lineage-sentinel-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Information-flow lineage and exfiltration sentinel",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "sentinel_contract": {
            "lineage_tag_persistence": True,
            "auto_containment": True,
            "recall_threshold_pct": 95,
            "precision_threshold_pct": 90,
            "covert_channel_detection": True,
        },
    }


def write_report(result: dict) -> None:
    EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    report_path = EVIDENCE_FILE.parent / "check_report.json"
    report_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


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
        "name": "check_lineage_sentinel",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_lineage_sentinel")
    parser = argparse.ArgumentParser(description="bd-2iyk checker")
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
        print(f"bd-2iyk: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
