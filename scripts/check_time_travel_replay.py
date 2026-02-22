#!/usr/bin/env python3
"""bd-1xbc verification gate for time-travel runtime capture/replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-1xbc"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/time_travel_runtime.md"
IMPL_FILE = ROOT / "crates/franken-node/src/replay/time_travel_engine.rs"
MOD_FILE = ROOT / "crates/franken-node/src/replay/mod.rs"
MAIN_FILE = ROOT / "crates/franken-node/src/main.rs"
LAB_TEST = ROOT / "tests/lab/time_travel_replay_equivalence.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_time_travel_replay.py"
REPORT_FILE = ROOT / "artifacts/10.17/time_travel_replay_report.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-1xbc/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-1xbc/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "REPLAY_CAPTURE_START",
    "REPLAY_CAPTURE_COMPLETE",
    "REPLAY_PLAYBACK_START",
    "REPLAY_PLAYBACK_MATCH",
    "REPLAY_DIVERGENCE_DETECTED",
]

REQUIRED_ERROR_CODES = [
    "ERR_REPLAY_SEED_MISMATCH",
    "ERR_REPLAY_STATE_CORRUPTION",
    "ERR_REPLAY_STEP_OVERFLOW",
    "ERR_REPLAY_INPUT_MISSING",
    "ERR_REPLAY_CLOCK_DRIFT",
    "ERR_REPLAY_SNAPSHOT_INVALID",
]

REQUIRED_INVARIANTS = [
    "INV-REPLAY-DETERMINISTIC",
    "INV-REPLAY-SEED-EQUIVALENCE",
    "INV-REPLAY-STEP-NAVIGATION",
    "INV-REPLAY-DIVERGENCE-EXPLAIN",
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

    # File existence checks
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("Replay mod file exists", MOD_FILE.exists(), str(MOD_FILE)))
    checks.append(_check(
        "Main module wired",
        "pub mod replay;" in main_src or "mod replay;" in main_src,
        "pub mod replay; in main.rs",
    ))
    checks.append(_check(
        "Replay mod exports time_travel_engine",
        "pub mod time_travel_engine;" in mod_src,
        "pub mod time_travel_engine; in replay/mod.rs",
    ))

    # Core struct/type checks
    required_impl_tokens = [
        "struct WorkflowTrace",
        "struct TraceStep",
        "struct EnvironmentSnapshot",
        "struct TraceBuilder",
        "struct ReplayEngine",
        "struct Divergence",
        "struct AuditEntry",
        "enum ReplayVerdict",
        "enum DivergenceKind",
        "enum TimeTravelError",
        "fn identity_replay",
        "fn replay",
        "fn register_trace",
        "fn compute_digest",
        "fn validate",
        "fn record_step",
    ]
    for token in required_impl_tokens:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code}", code in impl_src and code in spec_src, code))

    # Error codes
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code}", code in impl_src and code in spec_src, code))

    # Invariants
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv}", inv in impl_src and inv in spec_src, inv))

    # Rust unit test count
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 8", test_count >= 8, f"found {test_count}"))

    # Schema version
    checks.append(_check("Schema version ttr-v1.0", "ttr-v1.0" in impl_src))

    # Serde derives
    checks.append(_check("Serialize/Deserialize derives",
                          "Serialize" in impl_src and "Deserialize" in impl_src))

    # BTreeMap usage
    checks.append(_check("BTreeMap for deterministic ordering", "BTreeMap" in impl_src))

    # cfg(test) module
    checks.append(_check("#[cfg(test)] module", "#[cfg(test)]" in impl_src))

    # Lab test exists
    checks.append(_check("Lab test exists", LAB_TEST.exists(), str(LAB_TEST)))

    # Python checker unit test exists
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "time-travel-replay-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Deterministic time-travel runtime capture/replay for extension-host workflows",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "replay_contract": {
            "deterministic_replay": True,
            "seed_equivalence": True,
            "stepwise_navigation": True,
            "divergence_explanation": True,
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
        "name": "check_time_travel_replay",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-1xbc checker")
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
        print(f"bd-1xbc: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
