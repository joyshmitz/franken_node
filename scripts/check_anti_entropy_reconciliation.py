#!/usr/bin/env python3
"""Verification script for bd-390: Anti-Entropy Reconciliation.

Checks:
  - Specification document exists and contains required sections
  - Rust module exists with required types, methods, event codes, invariants
  - Module registered in runtime/mod.rs
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

BEAD_ID = "bd-390"
SECTION = "10.11"
TITLE = "Anti-Entropy Reconciliation"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-390_contract.md"
RUST_MODULE = ROOT / "crates" / "franken-node" / "src" / "runtime" / "anti_entropy.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"

EVENT_CODES = [
    "FN-AE-001", "FN-AE-002", "FN-AE-003", "FN-AE-004",
    "FN-AE-005", "FN-AE-006", "FN-AE-007", "FN-AE-008",
]

INVARIANTS = [
    "INV-AE-DELTA",
    "INV-AE-ATOMIC",
    "INV-AE-EPOCH",
    "INV-AE-PROOF",
]

ERROR_CODES = [
    "ERR_AE_INVALID_CONFIG",
    "ERR_AE_EPOCH_VIOLATION",
    "ERR_AE_PROOF_INVALID",
    "ERR_AE_FORK_DETECTED",
    "ERR_AE_CANCELLED",
    "ERR_AE_BATCH_EXCEEDED",
]

REQUIRED_STRUCTS = [
    "ReconciliationConfig",
    "TrustRecord",
    "TrustState",
    "ReconciliationResult",
    "ReconciliationEvent",
    "ReconciliationError",
    "AntiEntropyReconciler",
]

REQUIRED_METHODS = [
    "new",
    "validate",
    "compute_delta",
    "detect_fork",
    "reconcile",
    "events",
    "reconciliation_count",
    "insert",
    "root_digest",
    "current_epoch",
    "record_ids",
    "verify_mmr_proof",
    "digest",
]

MIN_TEST_COUNT = 30


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


# ── Rust checks ──────────────────────────────────────────────────────────

def check_rust_module_exists() -> dict:
    ok = RUST_MODULE.is_file()
    return _check("rust_module_exists", ok,
                   f"{RUST_MODULE.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_rust_module_registered() -> dict:
    text = _read(MOD_RS)
    ok = "pub mod anti_entropy;" in text
    return _check("rust_module_registered", ok,
                   f"pub mod anti_entropy; {'found' if ok else 'MISSING'} in mod.rs")


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


def check_rust_test_count() -> dict:
    text = _read(RUST_MODULE)
    tests = re.findall(r"#\[test\]", text)
    count = len(tests)
    ok = count >= MIN_TEST_COUNT
    return _check("rust_test_count", ok,
                  f"{count} tests (>= {MIN_TEST_COUNT} required)")


def check_rust_two_phase() -> dict:
    text = _read(RUST_MODULE)
    ok = "phase" in text.lower() or "atomic" in text.lower()
    return _check("rust_two_phase", ok,
                  f"Two-phase/atomic logic {'found' if ok else 'MISSING'}")


def check_rust_cancellation() -> dict:
    text = _read(RUST_MODULE)
    ok = "cancel" in text.lower()
    return _check("rust_cancellation", ok,
                  f"Cancellation support {'found' if ok else 'MISSING'}")


def check_rust_mmr_proof() -> dict:
    text = _read(RUST_MODULE)
    ok = "mmr_proof" in text
    return _check("rust_mmr_proof", ok,
                  f"MMR proof handling {'found' if ok else 'MISSING'}")


def check_rust_epoch_enforcement() -> dict:
    text = _read(RUST_MODULE)
    ok = "epoch" in text and "current_epoch" in text
    return _check("rust_epoch_enforcement", ok,
                  f"Epoch enforcement {'found' if ok else 'MISSING'}")


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
    checks.append(check_rust_test_count())
    checks.append(check_rust_two_phase())
    checks.append(check_rust_cancellation())
    checks.append(check_rust_mmr_proof())
    checks.append(check_rust_epoch_enforcement())

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
    logger = configure_test_logging("check_anti_entropy_reconciliation")
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
        print(f"bd-390 Anti-Entropy Reconciliation — {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
