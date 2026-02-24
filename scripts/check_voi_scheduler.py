#!/usr/bin/env python3
"""Verification script for bd-2nt: VOI-Budgeted Monitor Scheduling.

Checks:
  - Specification document exists and contains required sections
  - Rust module exists with required types, methods, event codes, invariants
  - Module registered in connector/mod.rs
  - >= 10 default diagnostics
  - >= 30 Rust unit tests
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-2nt"
SECTION = "10.11"
TITLE = "VOI-Budgeted Monitor Scheduling"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-2nt_contract.md"
RUST_MODULE = ROOT / "crates" / "franken-node" / "src" / "connector" / "diagnostic_registry.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"

EVENT_CODES = ["VOI-001", "VOI-002", "VOI-003", "VOI-004", "VOI-005", "VOI-006"]

INVARIANTS = [
    "INV-VOI-BUDGET",
    "INV-VOI-ORDER",
    "INV-VOI-PREEMPT",
    "INV-VOI-STORM",
]

ERROR_CODES = [
    "ERR_VOI_INVALID_CONFIG",
    "ERR_VOI_DUPLICATE_DIAG",
    "ERR_VOI_UNKNOWN_DIAG",
    "ERR_VOI_BUDGET_EXCEEDED",
    "ERR_VOI_EMPTY_REGISTRY",
]

REQUIRED_STRUCTS = [
    "VoiConfig",
    "VoiScheduler",
    "DiagnosticDef",
    "DiagnosticState",
    "ScheduleDecision",
    "ScheduleCycleResult",
    "VoiEvent",
    "VoiError",
    "PriorityClass",
]

REQUIRED_METHODS = [
    "new",
    "register_diagnostic",
    "diagnostic_count",
    "compute_voi",
    "schedule",
    "signal_regime_shift",
    "effective_budget",
    "record_finding",
    "is_conservative",
    "events",
    "diagnostic_names",
    "get_diagnostic",
    "validate",
]

PRIORITY_CLASSES = ["Critical", "Standard", "Background"]
VOI_COMPONENTS = ["staleness", "uncertainty", "downstream", "historical"]

MIN_TEST_COUNT = 30
MIN_DIAG_COUNT = 10


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


# ── Spec checks ──────────────────────────────────────────────────────────

def check_spec_exists() -> dict:
    ok = SPEC_PATH.is_file()
    return _check("spec_exists", ok,
                   f"{SPEC_PATH.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_spec_event(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_event:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


def check_spec_invariant(inv: str) -> dict:
    text = _read(SPEC_PATH)
    ok = inv in text
    return _check(f"spec_invariant:{inv}", ok,
                  f"{inv} {'found' if ok else 'MISSING'} in spec")


def check_spec_error(code: str) -> dict:
    text = _read(SPEC_PATH)
    ok = code in text
    return _check(f"spec_error:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in spec")


def check_spec_priority(cls: str) -> dict:
    text = _read(SPEC_PATH)
    ok = cls in text
    return _check(f"spec_priority:{cls}", ok,
                  f"Priority {cls} {'found' if ok else 'MISSING'} in spec")


def check_spec_voi_component(comp: str) -> dict:
    text = _read(SPEC_PATH)
    ok = comp.lower() in text.lower()
    return _check(f"spec_voi:{comp}", ok,
                  f"VOI component {comp} {'found' if ok else 'MISSING'} in spec")


# ── Rust checks ──────────────────────────────────────────────────────────

def check_rust_module_exists() -> dict:
    ok = RUST_MODULE.is_file()
    return _check("rust_module_exists", ok,
                   f"{RUST_MODULE.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_rust_module_registered() -> dict:
    text = _read(MOD_RS)
    ok = "pub mod diagnostic_registry;" in text
    return _check("rust_module_registered", ok,
                   f"pub mod diagnostic_registry; {'found' if ok else 'MISSING'} in mod.rs")


def check_rust_struct(name: str) -> dict:
    text = _read(RUST_MODULE)
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
        rf"struct\s+{name}\b",
    ]
    ok = any(re.search(p, text) for p in patterns)
    return _check(f"rust_struct:{name}", ok,
                  f"{name} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_method(name: str) -> dict:
    text = _read(RUST_MODULE)
    ok = bool(re.search(rf"fn\s+{name}\b", text))
    return _check(f"rust_method:{name}", ok,
                  f"fn {name} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_event(code: str) -> dict:
    text = _read(RUST_MODULE)
    ok = code in text
    return _check(f"rust_event:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_invariant(inv: str) -> dict:
    text = _read(RUST_MODULE)
    ok = inv in text
    return _check(f"rust_invariant:{inv}", ok,
                  f"{inv} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_error(code: str) -> dict:
    text = _read(RUST_MODULE)
    ok = code in text
    return _check(f"rust_error:{code}", ok,
                  f"{code} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_priority(cls: str) -> dict:
    text = _read(RUST_MODULE)
    ok = cls in text
    return _check(f"rust_priority:{cls}", ok,
                  f"Priority {cls} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_test_count() -> dict:
    text = _read(RUST_MODULE)
    tests = re.findall(r"#\[test\]", text)
    count = len(tests)
    ok = count >= MIN_TEST_COUNT
    return _check("rust_test_count", ok,
                  f"{count} tests (>= {MIN_TEST_COUNT} required)")


def check_rust_default_diagnostics() -> dict:
    text = _read(RUST_MODULE)
    ok = "default_diagnostics" in text
    return _check("rust_default_diagnostics", ok,
                  f"default_diagnostics fn {'found' if ok else 'MISSING'}")


def check_rust_default_diag_count() -> dict:
    text = _read(RUST_MODULE)
    # Count DiagnosticDef { in the default_diagnostics function.
    # Look for the function, then count entries.
    fn_match = re.search(
        r"fn\s+default_diagnostics.*?(?=\n(?:fn |#\[cfg))", text, re.DOTALL
    )
    if fn_match:
        fn_text = fn_match.group(0)
        count = fn_text.count('name:')
        ok = count >= MIN_DIAG_COUNT
    else:
        count = 0
        ok = False
    return _check("rust_default_diag_count", ok,
                  f"{count} default diagnostics (>= {MIN_DIAG_COUNT} required)")


def check_rust_storm_protection() -> dict:
    text = _read(RUST_MODULE)
    ok = "conservative_mode" in text and "storm" in text.lower()
    return _check("rust_storm_protection", ok,
                  f"Storm protection {'found' if ok else 'MISSING'}")


def check_rust_regime_boost() -> dict:
    text = _read(RUST_MODULE)
    ok = "regime_boost" in text or "regime_multiplier" in text
    return _check("rust_regime_boost", ok,
                  f"Regime boost {'found' if ok else 'MISSING'}")


def check_rust_preemption() -> dict:
    text = _read(RUST_MODULE)
    ok = "preempt" in text.lower()
    return _check("rust_preemption", ok,
                  f"Preemption logic {'found' if ok else 'MISSING'}")


# ── Run all checks ───────────────────────────────────────────────────────

def run_all() -> dict:
    checks = []

    # Spec checks
    checks.append(check_spec_exists())
    for code in EVENT_CODES:
        checks.append(check_spec_event(code))
    for inv in INVARIANTS:
        checks.append(check_spec_invariant(inv))
    for code in ERROR_CODES:
        checks.append(check_spec_error(code))
    for cls in PRIORITY_CLASSES:
        checks.append(check_spec_priority(cls))
    for comp in VOI_COMPONENTS:
        checks.append(check_spec_voi_component(comp))

    # Rust checks
    checks.append(check_rust_module_exists())
    checks.append(check_rust_module_registered())
    for s in REQUIRED_STRUCTS:
        checks.append(check_rust_struct(s))
    for m in REQUIRED_METHODS:
        checks.append(check_rust_method(m))
    for code in EVENT_CODES:
        checks.append(check_rust_event(code))
    for inv in INVARIANTS:
        checks.append(check_rust_invariant(inv))
    for code in ERROR_CODES:
        checks.append(check_rust_error(code))
    for cls in PRIORITY_CLASSES:
        checks.append(check_rust_priority(cls))
    checks.append(check_rust_test_count())
    checks.append(check_rust_default_diagnostics())
    checks.append(check_rust_default_diag_count())
    checks.append(check_rust_storm_protection())
    checks.append(check_rust_regime_boost())
    checks.append(check_rust_preemption())

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Smoke test: ensure run_all returns a valid structure."""
    result = run_all()
    assert isinstance(result, dict)
    assert "checks" in result
    assert "verdict" in result
    assert isinstance(result["checks"], list)
    assert all("name" in c and "passed" in c and "detail" in c
               for c in result["checks"])
    return True


def main():
    logger = configure_test_logging("check_voi_scheduler")
    import argparse
    parser = argparse.ArgumentParser(description=f"Verify {BEAD_ID}")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2nt VOI-Budgeted Monitor Scheduling — {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
