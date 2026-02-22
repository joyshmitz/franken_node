#!/usr/bin/env python3
"""Verification gate for bd-21fo optimization governor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-21fo"
SECTION = "10.17"
TITLE = "Self-evolving optimization governor with safety-envelope enforcement"

CONTRACT_FILE = ROOT / "docs/specs/section_10_17/bd-21fo_contract.md"
SPEC_FILE = ROOT / "docs/specs/optimization_governor.md"
IMPL_FILE = ROOT / "crates/franken-node/src/runtime/optimization_governor.rs"
RUNTIME_MOD_FILE = ROOT / "crates/franken-node/src/runtime/mod.rs"
PERF_TEST_FILE = ROOT / "tests/perf/governor_safety_envelope.rs"
PY_TEST_FILE = ROOT / "tests/test_check_optimization_governor.py"
DECISION_LOG_FILE = ROOT / "artifacts/10.17/governor_decision_log.jsonl"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-21fo/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-21fo/verification_summary.md"
REPORT_FILE = ROOT / "artifacts/section_10_17/bd-21fo/check_report.json"

REQUIRED_EVENT_CODES = [
    "GOV_001",
    "GOV_002",
    "GOV_003",
    "GOV_004",
    "GOV_005",
    "GOV_006",
    "GOV_007",
]

REQUIRED_ERROR_CODES = [
    "ERR_GOV_ENVELOPE_VIOLATION",
    "ERR_GOV_NON_BENEFICIAL",
    "ERR_GOV_KNOB_LOCKED",
    "ERR_GOV_REVERT_FAILED",
    "ERR_GOV_SHADOW_TIMEOUT",
    "ERR_GOV_INVALID_PROPOSAL",
]

REQUIRED_INVARIANTS = [
    "INV-GOV-ENVELOPE-NEVER-BREACHED",
    "INV-GOV-SHADOW-BEFORE-APPLY",
    "INV-GOV-EVIDENCE-ON-REJECT",
    "INV-GOV-KNOBS-ONLY",
    "INV-GOV-AUTO-REVERT",
    "INV-GOV-DETERMINISTIC-ORDER",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, passed: bool, detail: str = "") -> dict[str, object]:
    return {
        "check": name,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _load_json(path: Path) -> object | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            return []
        if not isinstance(parsed, dict):
            return []
        rows.append(parsed)
    return rows


def _required_file_checks() -> list[dict[str, object]]:
    required = [
        CONTRACT_FILE,
        SPEC_FILE,
        IMPL_FILE,
        RUNTIME_MOD_FILE,
        PERF_TEST_FILE,
        PY_TEST_FILE,
        DECISION_LOG_FILE,
        EVIDENCE_FILE,
        SUMMARY_FILE,
    ]
    checks = []
    for file_path in required:
        checks.append(
            _check(
                f"required file exists: {file_path.relative_to(ROOT)}",
                file_path.exists(),
                str(file_path.relative_to(ROOT)),
            )
        )
    return checks


def run_all() -> dict[str, object]:
    checks: list[dict[str, object]] = []
    checks.extend(_required_file_checks())

    impl_src = _read(IMPL_FILE)
    contract_src = _read(CONTRACT_FILE)
    spec_src = _read(SPEC_FILE)
    runtime_mod_src = _read(RUNTIME_MOD_FILE)

    checks.append(
        _check(
            "runtime module wired",
            "pub mod optimization_governor;" in runtime_mod_src,
            "pub mod optimization_governor; in runtime/mod.rs",
        )
    )

    impl_tokens = [
        "struct SafetyEnvelope",
        "struct OptimizationProposal",
        "enum GovernorDecision",
        "enum RuntimeKnob",
        "fn submit_proposal",
        "fn complete_shadow_evaluation",
        "fn enforce_live_safety",
        "fn decision_log_as_jsonl",
    ]
    for token in impl_tokens:
        checks.append(_check(f"impl token '{token}'", token in impl_src, token))

    for code in REQUIRED_EVENT_CODES:
        checks.append(
            _check(
                f"event code {code}",
                code in impl_src and code in contract_src and code in spec_src,
                code,
            )
        )

    for code in REQUIRED_ERROR_CODES:
        checks.append(
            _check(
                f"error code {code}",
                code in impl_src and code in contract_src and code in spec_src,
                code,
            )
        )

    for inv in REQUIRED_INVARIANTS:
        checks.append(
            _check(
                f"invariant {inv}",
                inv in impl_src and inv in contract_src and inv in spec_src,
                inv,
            )
        )

    rust_test_count = impl_src.count("#[test]")
    checks.append(_check("rust unit tests >= 20", rust_test_count >= 20, f"found {rust_test_count}"))

    py_test_src = _read(PY_TEST_FILE)
    py_test_methods = py_test_src.count("def test_")
    checks.append(
        _check(
            "python unit tests >= 12",
            py_test_methods >= 12,
            f"found {py_test_methods}",
        )
    )

    decision_rows = _load_jsonl(DECISION_LOG_FILE)
    checks.append(
        _check(
            "decision log jsonl parseable",
            len(decision_rows) > 0,
            f"rows={len(decision_rows)}",
        )
    )

    if decision_rows:
        required_keys = {"sequence", "event_code", "decision", "evidence_hash"}
        key_ok = all(required_keys.issubset(set(row.keys())) for row in decision_rows)
        checks.append(_check("decision rows have required keys", key_ok, str(sorted(required_keys))))

        sequences = [int(row.get("sequence", -1)) for row in decision_rows]
        monotonic = all(a < b for a, b in zip(sequences, sequences[1:]))
        checks.append(_check("decision sequence strictly increasing", monotonic, f"seq={sequences}"))

        events_seen = {str(row.get("event_code", "")) for row in decision_rows}
        checks.append(
            _check(
                "decision log has GOV_001..GOV_007 coverage",
                all(code in events_seen for code in REQUIRED_EVENT_CODES),
                f"seen={sorted(events_seen)}",
            )
        )

    evidence_payload = _load_json(EVIDENCE_FILE)
    checks.append(
        _check(
            "verification evidence parseable",
            isinstance(evidence_payload, dict),
            "json object" if isinstance(evidence_payload, dict) else "invalid/missing",
        )
    )

    summary_src = _read(SUMMARY_FILE)
    checks.append(_check("verification summary non-empty", len(summary_src.strip()) > 0, str(SUMMARY_FILE.relative_to(ROOT))))

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "schema_version": "optimization-governor-check-v1",
        "bead_id": BEAD,
        "section": SECTION,
        "title": TITLE,
        "verdict": verdict,
        "status": verdict.lower(),
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "paths": {
            "contract": str(CONTRACT_FILE.relative_to(ROOT)),
            "spec": str(SPEC_FILE.relative_to(ROOT)),
            "implementation": str(IMPL_FILE.relative_to(ROOT)),
            "perf_test": str(PERF_TEST_FILE.relative_to(ROOT)),
            "python_test": str(PY_TEST_FILE.relative_to(ROOT)),
            "decision_log": str(DECISION_LOG_FILE.relative_to(ROOT)),
        },
    }


def self_test() -> dict[str, object]:
    checks: list[dict[str, object]] = []
    checks.append(_check("event code count == 7", len(REQUIRED_EVENT_CODES) == 7))
    checks.append(_check("error code count == 6", len(REQUIRED_ERROR_CODES) == 6))
    checks.append(_check("invariant count == 6", len(REQUIRED_INVARIANTS) == 6))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all has at least 30 checks", int(result.get("total", 0)) >= 30, f"total={result.get('total')}"))

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_optimization_governor",
        "bead": BEAD,
        "section": SECTION,
        "verdict": verdict,
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def write_report(result: dict[str, object]) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-21fo checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"self-test: {result['verdict']} ({result['passed']}/{result['passed'] + result['failed']})")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{BEAD}: {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "+" if check["passed"] else "x"
            print(f"[{mark}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
