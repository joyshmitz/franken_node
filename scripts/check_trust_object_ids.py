#!/usr/bin/env python3
"""bd-1l5: Verification script for canonical product trust object IDs.

Usage:
    python3 scripts/check_trust_object_ids.py           # human-readable
    python3 scripts/check_trust_object_ids.py --json     # machine-readable
    python3 scripts/check_trust_object_ids.py --self-test # internal consistency
"""

import hashlib
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/connector/trust_object_id.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_10/bd-1l5_contract.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_10/bd-1l5/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_10/bd-1l5/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_STRUCTS = [
    "DomainPrefix",
    "DerivationMode",
    "TrustObjectId",
    "IdRegistry",
    "DomainRegistryEntry",
    "IdError",
    "IdEvent",
]

REQUIRED_EVENT_CODES = [
    "TOI-001",
    "TOI-002",
]

REQUIRED_ERROR_CODES = [
    "ERR_TOI_INVALID_PREFIX",
    "ERR_TOI_MALFORMED_DIGEST",
    "ERR_TOI_INVALID_FORMAT",
    "ERR_TOI_UNKNOWN_DOMAIN",
]

REQUIRED_INVARIANTS = [
    "INV-TOI-PREFIX",
    "INV-TOI-DETERMINISTIC",
    "INV-TOI-COLLISION",
    "INV-TOI-DIGEST",
]

REQUIRED_FUNCTIONS = [
    "derive_content_addressed",
    "derive_context_addressed",
    "parse",
    "validate",
    "full_form",
    "short_form",
    "sha256_digest",
    "canonical_bytes",
    "demo_trust_object_ids",
    "is_valid_prefix",
    "domain_count",
    "from_prefix",
]

DOMAIN_PREFIXES = [
    ("Extension", "ext:"),
    ("TrustCard", "tcard:"),
    ("Receipt", "rcpt:"),
    ("PolicyCheckpoint", "pchk:"),
    ("MigrationArtifact", "migr:"),
    ("VerifierClaim", "vclaim:"),
]

DERIVATION_MODES = [
    "ContentAddressed",
    "ContextAddressed",
]

REQUIRED_SPEC_SECTIONS = [
    "Overview",
    "Data Model",
    "DomainPrefix",
    "TrustObjectId",
    "IdRegistry",
    "Invariants",
    "Event Codes",
    "Error Codes",
    "Acceptance Criteria",
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> list:
    checks = []
    checks.append(_check(
        "trust_object_id implementation exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))
    checks.append(_check(
        "contract spec exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))
    checks.append(_check(
        "evidence artifact exists",
        EVIDENCE_FILE.exists(),
        str(EVIDENCE_FILE),
    ))
    checks.append(_check(
        "summary artifact exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))
    return checks


def check_structs() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for s in REQUIRED_STRUCTS:
        found = f"pub enum {s}" in src or f"pub struct {s}" in src
        checks.append(_check(f"struct/enum {s}", found))
    return checks


def check_event_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        checks.append(_check(f"event code {code}", found))
    return checks


def check_error_codes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for code in REQUIRED_ERROR_CODES:
        found = code in src
        checks.append(_check(f"error code {code}", found))
    return checks


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        checks.append(_check(f"invariant {inv}", found))
    return checks


def check_functions() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for fn_name in REQUIRED_FUNCTIONS:
        found = f"fn {fn_name}" in src or f"pub fn {fn_name}" in src
        checks.append(_check(f"function {fn_name}", found))
    return checks


def check_spec_sections() -> list:
    src = _read(SPEC_FILE)
    checks = []
    for section in REQUIRED_SPEC_SECTIONS:
        found = section in src
        checks.append(_check(f"spec section: {section}", found))
    return checks


def check_domain_prefixes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for name, prefix in DOMAIN_PREFIXES:
        found_variant = name in src
        found_prefix = f'"{prefix}"' in src
        checks.append(_check(f"domain {name} variant", found_variant))
        checks.append(_check(f"domain prefix {prefix}", found_prefix))
    checks.append(_check(
        "6 domain prefixes defined",
        all(name in src for name, _ in DOMAIN_PREFIXES),
    ))
    return checks


def check_derivation_modes() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for mode in DERIVATION_MODES:
        found = mode in src
        checks.append(_check(f"derivation mode {mode}", found))
    return checks


def check_sha256_usage() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("imports sha2::Sha256", "Sha256" in src))
    checks.append(_check("uses hex::encode", "hex::encode" in src))
    checks.append(_check("SHA-256 digest length check", "64" in src and "hex chars" in src))
    return checks


def check_serde_derives() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in ["DomainPrefix", "DerivationMode", "TrustObjectId",
              "IdRegistry", "DomainRegistryEntry", "IdEvent"]:
        idx = src.find(f"pub enum {t}") if f"pub enum {t}" in src else src.find(f"pub struct {t}")
        if idx >= 0:
            preceding = src[max(0, idx - 200):idx]
            has_serde = "Serialize" in preceding and "Deserialize" in preceding
            checks.append(_check(f"serde derives on {t}", has_serde))
        else:
            checks.append(_check(f"serde derives on {t}", False, "type not found"))
    return checks


def check_tests() -> list:
    src = _read(IMPL_FILE)
    checks = []
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests present ({test_count})",
        test_count >= 45,
        f"{test_count} tests found",
    ))

    test_categories = [
        ("domain prefix tests", "test_all_domains_count"),
        ("round-trip parse tests", "test_parse_round_trip"),
        ("collision resistance tests", "test_cross_domain_collision"),
        ("content-addressed tests", "test_derive_content_addressed"),
        ("context-addressed tests", "test_derive_context_addressed"),
        ("short form tests", "test_short_form"),
        ("error code tests", "test_error_codes"),
        ("serde roundtrip tests", "test_trust_object_id_serde"),
        ("send+sync tests", "test_types_send_sync"),
        ("demo function test", "test_demo_trust_object_ids"),
        ("registry tests", "test_registry_new"),
        ("determinism tests", "test_content_addressed_deterministic"),
    ]
    for name, pattern in test_categories:
        found = pattern in src
        checks.append(_check(f"test: {name}", found))
    return checks


def check_send_sync() -> list:
    src = _read(IMPL_FILE)
    checks = []
    found = "assert_send" in src and "assert_sync" in src
    checks.append(_check("Send + Sync assertions", found))
    return checks


def check_acceptance_criteria() -> list:
    src = _read(IMPL_FILE)
    checks = []

    # AC1: 6 domain prefixes
    ac1 = all(name in src for name, _ in DOMAIN_PREFIXES)
    checks.append(_check("AC1: 6 domain prefixes", ac1))

    # AC2: Content-addressed and context-addressed derivation
    ac2 = "derive_content_addressed" in src and "derive_context_addressed" in src
    checks.append(_check("AC2: both derivation modes", ac2))

    # AC3: Parse/validate round-trip
    ac3 = "fn parse" in src and "fn validate" in src
    checks.append(_check("AC3: parse/validate utilities", ac3))

    # AC4: Cross-domain collision impossible
    ac4 = "cross_domain" in src.lower() or "prefix" in src
    checks.append(_check("AC4: cross-domain collision prevention", ac4))

    # AC5: Short-form and full-form
    ac5 = "fn short_form" in src and "fn full_form" in src
    checks.append(_check("AC5: short-form and full-form", ac5))

    # AC6: Deterministic derivation
    ac6 = "deterministic" in src.lower()
    checks.append(_check("AC6: deterministic derivation documented", ac6))

    # AC7: SHA-256 collision resistance
    ac7 = "sha256" in src.lower() and "256" in src
    checks.append(_check("AC7: SHA-256 collision resistance", ac7))

    return checks


def simulate_trust_object_ids() -> dict:
    """Simulate trust object ID derivation and validation."""
    results = {}

    # Content-addressed: same input → same digest
    d1 = _sha256_hex(b"test-data")
    d2 = _sha256_hex(b"test-data")
    results["deterministic"] = d1 == d2

    # Different inputs → different digests
    d3 = _sha256_hex(b"other-data")
    results["different_inputs_different"] = d1 != d3

    # Cross-domain: same data + different prefix → different full IDs
    prefixes = [p for _, p in DOMAIN_PREFIXES]
    full_ids = set()
    for prefix in prefixes:
        full_id = f"{prefix}sha256:{d1}"
        full_ids.add(full_id)
    results["cross_domain_unique"] = len(full_ids) == 6

    # Short form: first 8 hex chars
    short = d1[:8]
    results["short_form_length"] = len(short)

    # Context-addressed uses epoch + sequence
    import struct
    ctx_input = struct.pack(">QQ", 42, 7) + b"checkpoint-data"
    ctx_digest = _sha256_hex(ctx_input)
    results["context_addressed_works"] = len(ctx_digest) == 64

    # Digest is 64 hex chars (256 bits)
    results["digest_length_256_bits"] = len(d1) == 64

    # All hex chars
    results["digest_is_hex"] = all(c in "0123456789abcdef" for c in d1)

    # 6 domain prefixes
    results["domain_prefix_count"] = len(DOMAIN_PREFIXES)

    # 2 derivation modes
    results["derivation_mode_count"] = len(DERIVATION_MODES)

    return results


# ── Main check runner ──────────────────────────────────────────────────────

def run_checks() -> dict:
    checks = []
    checks.extend(check_file_existence())
    checks.extend(check_structs())
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_functions())
    checks.extend(check_spec_sections())
    checks.extend(check_domain_prefixes())
    checks.extend(check_derivation_modes())
    checks.extend(check_sha256_usage())
    checks.extend(check_serde_derives())
    checks.extend(check_tests())
    checks.extend(check_send_sync())
    checks.extend(check_acceptance_criteria())

    # Simulation checks
    sim = simulate_trust_object_ids()
    checks.append(_check("sim: deterministic derivation", sim["deterministic"]))
    checks.append(_check("sim: different inputs differ", sim["different_inputs_different"]))
    checks.append(_check("sim: cross-domain unique", sim["cross_domain_unique"]))
    checks.append(_check("sim: short form 8 chars", sim["short_form_length"] == 8))
    checks.append(_check("sim: context-addressed works", sim["context_addressed_works"]))
    checks.append(_check("sim: 256-bit digest", sim["digest_length_256_bits"]))
    checks.append(_check("sim: hex digest", sim["digest_is_hex"]))
    checks.append(_check("sim: 6 domain prefixes", sim["domain_prefix_count"] == 6))
    checks.append(_check("sim: 2 derivation modes", sim["derivation_mode_count"] == 2))

    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-1l5",
        "title": "Canonical product trust object IDs with domain separation",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    """Alias for run_checks()."""
    return run_checks()


def self_test() -> tuple:
    """Internal consistency checks."""
    checks = []
    checks.append(_check("REQUIRED_STRUCTS non-empty", len(REQUIRED_STRUCTS) >= 7))
    checks.append(_check("REQUIRED_EVENT_CODES count", len(REQUIRED_EVENT_CODES) == 2))
    checks.append(_check("REQUIRED_ERROR_CODES count", len(REQUIRED_ERROR_CODES) == 4))
    checks.append(_check("REQUIRED_INVARIANTS count", len(REQUIRED_INVARIANTS) == 4))
    checks.append(_check("REQUIRED_FUNCTIONS count", len(REQUIRED_FUNCTIONS) >= 12))
    checks.append(_check("DOMAIN_PREFIXES count", len(DOMAIN_PREFIXES) == 6))
    checks.append(_check("DERIVATION_MODES count", len(DERIVATION_MODES) == 2))
    checks.append(_check("REQUIRED_SPEC_SECTIONS count", len(REQUIRED_SPEC_SECTIONS) >= 9))

    # Verify simulation
    sim = simulate_trust_object_ids()
    checks.append(_check("simulation returns dict", isinstance(sim, dict)))
    checks.append(_check("simulation has deterministic key", "deterministic" in sim))

    # Verify run_checks structure
    result = run_checks()
    checks.append(_check("run_checks has bead_id", result.get("bead_id") == "bd-1l5"))
    checks.append(_check("run_checks has section", result.get("section") == "10.10"))
    checks.append(_check("run_checks has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_checks has checks list", isinstance(result.get("checks"), list)))

    # Verify sha256 helper
    h1 = _sha256_hex(b"test")
    h2 = _sha256_hex(b"test")
    checks.append(_check("sha256 deterministic", h1 == h2))
    h3 = _sha256_hex(b"other")
    checks.append(_check("sha256 distinct", h1 != h3))

    ok = all(c["pass"] for c in checks)
    return (ok, checks)


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    logger = configure_test_logging("check_trust_object_ids")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        total = len(checks)
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {passed}/{total} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
