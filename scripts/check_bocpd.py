#!/usr/bin/env python3
"""Verification script for bd-3u4: BOCPD Regime Detector.

Checks:
  - Specification document exists and contains required sections
  - Rust module exists with required types, methods, event codes, invariants
  - Module registered in connector/mod.rs
  - Golden vectors file present with required test scenarios
  - >= 30 Rust unit tests
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-3u4"
SECTION = "10.11"
TITLE = "BOCPD Regime Detector"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-3u4_contract.md"
RUST_MODULE = ROOT / "crates" / "franken-node" / "src" / "connector" / "bocpd.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
VECTORS_PATH = ROOT / "vectors" / "bocpd_regime_shifts.json"

EVENT_CODES = ["BCP-001", "BCP-002", "BCP-003", "BCP-004", "BCP-005"]

INVARIANTS = [
    "INV-BCP-POSTERIOR",
    "INV-BCP-MONOTONIC",
    "INV-BCP-BOUNDED",
    "INV-BCP-MIN-RUN",
]

ERROR_CODES = [
    "ERR_BCP_INVALID_CONFIG",
    "ERR_BCP_EMPTY_STREAM",
    "ERR_BCP_MODEL_MISMATCH",
]

REQUIRED_STRUCTS = [
    "BocpdConfig",
    "BocpdDetector",
    "RegimeShift",
    "MultiStreamCorrelator",
    "BocpdEvent",
    "BocpdError",
    "HazardFunction",
    "ObservationModel",
    "GaussianModel",
    "PoissonModel",
    "CategoricalModel",
]

REQUIRED_METHODS = [
    "new",
    "observe",
    "map_run_length",
    "changepoint_probability",
    "regime_history",
    "observation_count",
    "events",
    "posterior_sum",
    "stream_name",
    "record_shift",
    "recent_count",
    "validate",
    "evaluate",
    "predictive_prob",
]

HAZARD_VARIANTS = ["Constant", "Geometric"]
OBSERVATION_MODELS = ["Gaussian", "Poisson", "Categorical"]

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


def check_spec_hazard(variant: str) -> dict:
    text = _read(SPEC_PATH)
    ok = variant in text
    return _check(f"spec_hazard:{variant}", ok,
                  f"Hazard {variant} {'found' if ok else 'MISSING'} in spec")


def check_spec_model(model: str) -> dict:
    text = _read(SPEC_PATH)
    ok = model in text
    return _check(f"spec_model:{model}", ok,
                  f"Model {model} {'found' if ok else 'MISSING'} in spec")


# ── Rust checks ──────────────────────────────────────────────────────────

def check_rust_module_exists() -> dict:
    ok = RUST_MODULE.is_file()
    return _check("rust_module_exists", ok,
                   f"{RUST_MODULE.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_rust_module_registered() -> dict:
    text = _read(MOD_RS)
    ok = "pub mod bocpd;" in text
    return _check("rust_module_registered", ok,
                   f"pub mod bocpd; {'found' if ok else 'MISSING'} in mod.rs")


def check_rust_struct(name: str) -> dict:
    text = _read(RUST_MODULE)
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
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


def check_rust_hazard_variant(variant: str) -> dict:
    text = _read(RUST_MODULE)
    ok = variant in text
    return _check(f"rust_hazard:{variant}", ok,
                  f"Hazard {variant} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_observation_model(model: str) -> dict:
    text = _read(RUST_MODULE)
    ok = model in text
    return _check(f"rust_model:{model}", ok,
                  f"Model {model} {'found' if ok else 'MISSING'} in Rust module")


def check_rust_test_count() -> dict:
    text = _read(RUST_MODULE)
    tests = re.findall(r"#\[test\]", text)
    count = len(tests)
    ok = count >= MIN_TEST_COUNT
    return _check("rust_test_count", ok,
                  f"{count} tests (>= {MIN_TEST_COUNT} required)")


def check_rust_ln_gamma() -> dict:
    text = _read(RUST_MODULE)
    ok = "ln_gamma" in text
    return _check("rust_ln_gamma", ok,
                  f"ln_gamma {'found' if ok else 'MISSING'} in Rust module")


def check_rust_student_t() -> dict:
    text = _read(RUST_MODULE)
    ok = "student_t_pdf" in text
    return _check("rust_student_t", ok,
                  f"student_t_pdf {'found' if ok else 'MISSING'} in Rust module")


def check_rust_neg_binomial() -> dict:
    text = _read(RUST_MODULE)
    ok = "neg_binomial_pmf" in text
    return _check("rust_neg_binomial", ok,
                  f"neg_binomial_pmf {'found' if ok else 'MISSING'} in Rust module")


# ── Vectors checks ───────────────────────────────────────────────────────

def check_vectors_exist() -> dict:
    ok = VECTORS_PATH.is_file()
    return _check("vectors_exist", ok,
                  f"{VECTORS_PATH.relative_to(ROOT)} {'exists' if ok else 'MISSING'}")


def check_vectors_valid_json() -> dict:
    text = _read(VECTORS_PATH)
    try:
        json.loads(text)
        ok = True
    except (json.JSONDecodeError, ValueError):
        ok = False
    return _check("vectors_valid_json", ok,
                  f"Golden vectors JSON {'valid' if ok else 'INVALID'}")


def check_vectors_has_scenarios() -> dict:
    text = _read(VECTORS_PATH)
    try:
        data = json.loads(text)
        vectors = data.get("vectors", [])
        ok = len(vectors) >= 4
        detail = f"{len(vectors)} scenarios (>= 4 required)"
    except (json.JSONDecodeError, ValueError):
        ok = False
        detail = "Could not parse JSON"
    return _check("vectors_scenarios", ok, detail)


def check_vectors_invariants() -> dict:
    text = _read(VECTORS_PATH)
    try:
        data = json.loads(text)
        invs = data.get("invariants", {})
        ok = all(inv in invs for inv in INVARIANTS)
        detail = f"All invariants {'present' if ok else 'MISSING some'} in vectors"
    except (json.JSONDecodeError, ValueError):
        ok = False
        detail = "Could not parse JSON"
    return _check("vectors_invariants", ok, detail)


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
    for variant in HAZARD_VARIANTS:
        checks.append(check_spec_hazard(variant))
    for model in OBSERVATION_MODELS:
        checks.append(check_spec_model(model))

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
    for variant in HAZARD_VARIANTS:
        checks.append(check_rust_hazard_variant(variant))
    for model in OBSERVATION_MODELS:
        checks.append(check_rust_observation_model(model))
    checks.append(check_rust_test_count())
    checks.append(check_rust_ln_gamma())
    checks.append(check_rust_student_t())
    checks.append(check_rust_neg_binomial())

    # Vectors checks
    checks.append(check_vectors_exist())
    checks.append(check_vectors_valid_json())
    checks.append(check_vectors_has_scenarios())
    checks.append(check_vectors_invariants())

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
    logger = configure_test_logging("check_bocpd")
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
        print(f"bd-3u4 BOCPD Regime Detector — {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
