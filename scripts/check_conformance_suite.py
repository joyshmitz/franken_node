#!/usr/bin/env python3
"""bd-3i6c: FrankenSQLite-inspired conformance suite verification gate.

Checks both the Rust library module (conformance runner) and the
conformance test/fixture artifacts.

Usage:
    python scripts/check_conformance_suite.py            # human-readable
    python scripts/check_conformance_suite.py --json     # machine-readable JSON
    python scripts/check_conformance_suite.py --self-test # self-test mode
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# ---- Paths: Rust library module (suite runner) ----
SRC = ROOT / "crates" / "franken-node" / "src" / "conformance" / "fsqlite_inspired_suite.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "conformance" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-3i6c_contract.md"

# ---- Paths: Test suite and fixtures ----
RUST_SUITE = ROOT / "tests" / "conformance" / "fsqlite_inspired_suite.rs"
FIXTURE_DIR = ROOT / "fixtures" / "conformance" / "fsqlite_inspired"
FIXTURE_FILES = {
    "determinism": FIXTURE_DIR / "determinism_fixtures.json",
    "idempotency": FIXTURE_DIR / "idempotency_fixtures.json",
    "epoch_validity": FIXTURE_DIR / "epoch_validity_fixtures.json",
    "proof_correctness": FIXTURE_DIR / "proof_correctness_fixtures.json",
}

# ---- Domain configuration ----
DOMAIN_PREFIXES = {
    "determinism": "FSQL-DET",
    "idempotency": "FSQL-IDP",
    "epoch_validity": "FSQL-EPO",
    "proof_correctness": "FSQL-PRF",
}

DOMAIN_MINIMUMS = {
    "determinism": 10,
    "idempotency": 8,
    "epoch_validity": 12,
    "proof_correctness": 10,
}

# ---- Conformance ID regex ----
CONFORMANCE_ID_RE = re.compile(r"^FSQL-(DET|IDP|EPO|PRF)-\d{3}$")

# ---- Rust test domain prefixes ----
RUST_TEST_DOMAINS = {
    "fsql_det_": "determinism",
    "fsql_idp_": "idempotency",
    "fsql_epo_": "epoch_validity",
    "fsql_prf_": "proof_correctness",
}

# ---- Library module expected types ----
LIB_TYPES = [
    "ConformanceDomain", "ConformanceId", "ConformanceTestResult",
    "ConformanceTestRecord", "ConformanceReport", "ConformanceFixture",
    "ConformanceAuditRecord", "ConformanceError", "ConformanceSuiteRunner",
]

# ---- Library module expected operations ----
LIB_OPS = [
    "register_fixture", "register_builtin_fixtures", "run_all",
    "check_release_gate", "domain_coverage", "verify_domain_coverage",
    "export_report_json", "export_audit_log_jsonl",
]

# ---- Event codes ----
EVENT_CODES = [
    "CONFORMANCE_SUITE_START", "CONFORMANCE_TEST_PASS",
    "CONFORMANCE_TEST_FAIL", "CONFORMANCE_SUITE_COMPLETE",
    "CONFORMANCE_FIXTURE_LOADED", "CONFORMANCE_REPORT_EXPORTED",
]

# ---- Error codes ----
ERROR_CODES = [
    "ERR_CONF_DETERMINISM_MISMATCH", "ERR_CONF_IDEMPOTENCY_VIOLATION",
    "ERR_CONF_EPOCH_INVARIANT_BROKEN", "ERR_CONF_PROOF_INVALID",
    "ERR_CONF_DUPLICATE_ID", "ERR_CONF_FIXTURE_PARSE",
    "ERR_CONF_RELEASE_BLOCKED", "ERR_CONF_MISSING_DOMAIN",
]

# ---- Invariants ----
INVARIANTS = [
    "INV-CONF-DETERMINISTIC", "INV-CONF-IDEMPOTENT",
    "INV-CONF-EPOCH-VALID", "INV-CONF-PROOF-CORRECT",
    "INV-CONF-STABLE-IDS", "INV-CONF-RELEASE-GATE",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "missing")}


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text()


# ==========================================================================
# Section A: Library module checks (Rust source at crates/.../conformance/)
# ==========================================================================

def check_lib_files() -> list:
    checks = []
    checks.append(_check("file: spec contract", SPEC.exists(), _safe_rel(SPEC)))
    checks.append(_check("file: library module", SRC.exists(), _safe_rel(SRC)))
    return checks


def check_lib_module_wired() -> list:
    mod_src = _read(MOD)
    return [_check(
        "module wired in conformance/mod.rs",
        "pub mod fsqlite_inspired_suite;" in mod_src,
        "conformance/mod.rs contains pub mod fsqlite_inspired_suite"
    )]


def check_lib_types() -> list:
    src = _read(SRC)
    checks = []
    for t in LIB_TYPES:
        found = f"pub struct {t}" in src or f"pub enum {t}" in src
        checks.append(_check(f"type: {t}", found))
    return checks


def check_lib_domains() -> list:
    src = _read(SRC)
    checks = []
    for d in ["Determinism", "Idempotency", "EpochValidity", "ProofCorrectness"]:
        checks.append(_check(f"domain: {d}", d in src))
    return checks


def check_lib_prefixes() -> list:
    src = _read(SRC)
    checks = []
    for p in DOMAIN_PREFIXES.values():
        checks.append(_check(f"prefix: {p}", p in src))
    return checks


def check_lib_ops() -> list:
    src = _read(SRC)
    checks = []
    for op in LIB_OPS:
        checks.append(_check(f"op: {op}", f"pub fn {op}" in src))
    return checks


def check_lib_event_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in EVENT_CODES if ec in src)
    return [_check(f"event codes ({found}/6)", found == 6, f"{found}/6")]


def check_lib_error_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in ERROR_CODES if ec in src)
    return [_check(f"error codes ({found}/8)", found == 8, f"{found}/8")]


def check_lib_invariants() -> list:
    src = _read(SRC)
    found = sum(1 for inv in INVARIANTS if inv in src)
    return [_check(f"invariants ({found}/6)", found == 6, f"{found}/6")]


def check_lib_schema_version() -> list:
    src = _read(SRC)
    return [_check("schema version cs-v1.0", "cs-v1.0" in src)]


def check_lib_suite_version() -> list:
    src = _read(SRC)
    return [_check("suite version 1.0.0", '"1.0.0"' in src)]


def check_lib_serde() -> list:
    src = _read(SRC)
    return [_check("Serialize/Deserialize derives",
                   "Serialize" in src and "Deserialize" in src)]


def check_lib_test_count() -> list:
    src = _read(SRC)
    count = len(re.findall(r"#\[test\]", src))
    return [_check(f"library inline tests >= 25", count >= 25, f"{count} tests")]


# ==========================================================================
# Section B: Fixture file checks
# ==========================================================================

def check_fixture_files() -> list:
    checks = []
    for domain, path in FIXTURE_FILES.items():
        checks.append(_check(f"file: {domain} fixtures", path.exists(), _safe_rel(path)))
    return checks


def load_fixtures() -> tuple:
    all_fixtures = []
    errors = []
    for domain, path in FIXTURE_FILES.items():
        if not path.exists():
            errors.append(f"missing: {_safe_rel(path)}")
            continue
        try:
            data = json.loads(path.read_text())
            fixtures = data.get("fixtures", [])
            for f in fixtures:
                f["_source_domain"] = domain
            all_fixtures.extend(fixtures)
        except (json.JSONDecodeError, KeyError) as e:
            errors.append(f"parse error in {_safe_rel(path)}: {e}")
    return all_fixtures, errors


def check_fixture_count(all_fixtures: list) -> list:
    total = len(all_fixtures)
    return [_check(f"total fixture count >= 40", total >= 40, f"{total} fixtures")]


def check_domain_minimums(all_fixtures: list) -> list:
    checks = []
    counts = {}
    for f in all_fixtures:
        d = f.get("_source_domain", "unknown")
        counts[d] = counts.get(d, 0) + 1
    for domain, minimum in DOMAIN_MINIMUMS.items():
        count = counts.get(domain, 0)
        checks.append(_check(
            f"domain {domain} >= {minimum} fixtures",
            count >= minimum,
            f"{count} fixtures"
        ))
    return checks


def check_conformance_id_format(all_fixtures: list) -> list:
    bad = [f.get("conformance_id", "") for f in all_fixtures
           if not CONFORMANCE_ID_RE.match(f.get("conformance_id", ""))]
    return [_check(
        "all conformance IDs match FSQL-(DET|IDP|EPO|PRF)-NNN",
        len(bad) == 0,
        f"{len(bad)} bad IDs" if bad else "all valid"
    )]


def check_no_duplicate_ids(all_fixtures: list) -> list:
    seen = set()
    dupes = []
    for f in all_fixtures:
        cid = f.get("conformance_id", "")
        if cid in seen:
            dupes.append(cid)
        seen.add(cid)
    return [_check(
        "no duplicate conformance IDs",
        len(dupes) == 0,
        f"{len(dupes)} duplicates" if dupes else "all unique"
    )]


def check_domain_prefix_alignment(all_fixtures: list) -> list:
    mismatches = []
    for f in all_fixtures:
        domain = f.get("_source_domain", "unknown")
        cid = f.get("conformance_id", "")
        expected = DOMAIN_PREFIXES.get(domain, "")
        if expected and not cid.startswith(expected):
            mismatches.append(f"{cid} in {domain}")
    return [_check(
        "conformance ID prefix matches domain",
        len(mismatches) == 0,
        f"{len(mismatches)} mismatches" if mismatches else "all aligned"
    )]


def check_fixture_schema(all_fixtures: list) -> list:
    required = ["conformance_id", "domain", "description", "input", "expected"]
    missing = []
    for f in all_fixtures:
        for field in required:
            if field not in f:
                missing.append(f"{f.get('conformance_id', '?')}.{field}")
    return [_check(
        "all fixtures have required schema fields",
        len(missing) == 0,
        f"{len(missing)} missing" if missing else "all valid"
    )]


# ==========================================================================
# Section C: Rust test suite checks
# ==========================================================================

def check_rust_suite_file() -> list:
    return [_check("file: Rust test suite", RUST_SUITE.exists(), _safe_rel(RUST_SUITE))]


def check_rust_suite_tests() -> list:
    checks = []
    content = _read(RUST_SUITE)
    if not content:
        checks.append(_check("Rust test suite test count >= 40", False, "file missing"))
        for domain in RUST_TEST_DOMAINS.values():
            checks.append(_check(f"Rust suite {domain} tests", False, "file missing"))
        return checks

    test_count = content.count("#[test]")
    checks.append(_check(
        "Rust test suite test count >= 40",
        test_count >= 40,
        f"{test_count} #[test] annotations"
    ))
    for prefix, domain in RUST_TEST_DOMAINS.items():
        n = content.count(f"fn {prefix}")
        checks.append(_check(f"Rust suite {domain} tests", n > 0, f"{n} tests"))
    return checks


def check_rust_suite_conformance_ids() -> list:
    content = _read(RUST_SUITE)
    if not content:
        return [_check("Rust suite references conformance IDs", False, "file missing")]
    ids = set(re.findall(r"FSQL-(?:DET|IDP|EPO|PRF)-\d{3}", content))
    return [_check(
        "Rust suite references conformance IDs",
        len(ids) >= 40,
        f"{len(ids)} unique IDs"
    )]


# ==========================================================================
# Section D: Spec contract checks
# ==========================================================================

def check_spec_sections() -> list:
    content = _read(SPEC)
    if not content:
        return [_check("spec sections", False, "spec missing")]
    checks = []
    for section in ["Determinism", "Idempotency", "Epoch", "Proof",
                    "Acceptance Criteria", "Invariants"]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


# ==========================================================================
# Main
# ==========================================================================

def run_checks() -> dict:
    checks = []

    # A: Library module
    checks.extend(check_lib_files())
    checks.extend(check_lib_module_wired())
    checks.extend(check_lib_types())
    checks.extend(check_lib_domains())
    checks.extend(check_lib_prefixes())
    checks.extend(check_lib_ops())
    checks.extend(check_lib_event_codes())
    checks.extend(check_lib_error_codes())
    checks.extend(check_lib_invariants())
    checks.extend(check_lib_schema_version())
    checks.extend(check_lib_suite_version())
    checks.extend(check_lib_serde())
    checks.extend(check_lib_test_count())

    # B: Fixture files
    checks.extend(check_fixture_files())
    all_fixtures, load_errors = load_fixtures()
    for err in load_errors:
        checks.append(_check(f"fixture load: {err}", False, err))
    checks.extend(check_fixture_count(all_fixtures))
    checks.extend(check_domain_minimums(all_fixtures))
    checks.extend(check_conformance_id_format(all_fixtures))
    checks.extend(check_no_duplicate_ids(all_fixtures))
    checks.extend(check_domain_prefix_alignment(all_fixtures))
    checks.extend(check_fixture_schema(all_fixtures))

    # C: Rust test suite
    checks.extend(check_rust_suite_file())
    checks.extend(check_rust_suite_tests())
    checks.extend(check_rust_suite_conformance_ids())

    # D: Spec
    checks.extend(check_spec_sections())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": "bd-3i6c",
        "title": "FrankenSQLite-inspired conformance suite",
        "section": "10.14",
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple:
    result = run_checks()
    if not result["overall_pass"]:
        failures = [c for c in result["checks"] if not c["pass"]]
        detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
        return False, f"self_test failed: {detail}"
    return True, "self_test passed"


def main():
    logger = configure_test_logging("check_conformance_suite")
    if "--self-test" in sys.argv:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["pass"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    failing = result["summary"]["failing"]
    total = result["summary"]["total"]
    print(f"\nbd-3i6c verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
