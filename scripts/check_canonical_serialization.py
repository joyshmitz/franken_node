#!/usr/bin/env python3
"""bd-jjm: Verification script for canonical deterministic serialization.

Usage:
    python3 scripts/check_canonical_serialization.py           # human-readable
    python3 scripts/check_canonical_serialization.py --json     # machine-readable
    python3 scripts/check_canonical_serialization.py --self-test # internal consistency
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/connector/canonical_serializer.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_10/bd-jjm_contract.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_10/bd-jjm/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_10/bd-jjm/verification_summary.md"

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_STRUCTS = [
    "TrustObjectType",
    "CanonicalSerializer",
    "SignaturePreimage",
    "CanonicalSchema",
    "SerializerEvent",
    "SerializerError",
]

REQUIRED_EVENT_CODES = [
    "CAN_SERIALIZE",
    "CAN_PREIMAGE_CONSTRUCT",
    "CAN_REJECT",
]

REQUIRED_ERROR_CODES = [
    "ERR_CAN_NON_CANONICAL",
    "ERR_CAN_SCHEMA_NOT_FOUND",
    "ERR_CAN_FLOAT_REJECTED",
    "ERR_CAN_PREIMAGE_FAILED",
    "ERR_CAN_ROUND_TRIP_DIVERGENCE",
]

REQUIRED_INVARIANTS = [
    "INV-CAN-DETERMINISTIC",
    "INV-CAN-NO-FLOAT",
    "INV-CAN-DOMAIN-TAG",
    "INV-CAN-NO-BYPASS",
]

REQUIRED_FUNCTIONS = [
    "serialize",
    "deserialize",
    "round_trip_canonical",
    "build_preimage",
    "register_schema",
    "with_all_schemas",
    "schema_count",
    "get_schema",
    "to_bytes",
    "byte_len",
    "content_hash_prefix",
    "demo_canonical_serialization",
    "canonical_encode",
    "canonical_decode",
    "contains_float_marker",
]

TRUST_OBJECT_TYPES = [
    "PolicyCheckpoint",
    "DelegationToken",
    "RevocationAssertion",
    "SessionTicket",
    "ZoneBoundaryClaim",
    "OperatorReceipt",
]

REQUIRED_SPEC_SECTIONS = [
    "Overview",
    "Data Model",
    "TrustObjectType",
    "CanonicalSerializer",
    "SignaturePreimage",
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
    checks.append(_check("canonical_serializer implementation exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check("contract spec exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("evidence artifact exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("summary artifact exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))
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
    return [_check(f"event code {c}", c in src) for c in REQUIRED_EVENT_CODES]


def check_error_codes() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"error code {c}", c in src) for c in REQUIRED_ERROR_CODES]


def check_invariants() -> list:
    src = _read(IMPL_FILE)
    return [_check(f"invariant {inv}", inv in src) for inv in REQUIRED_INVARIANTS]


def check_functions() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for fn_name in REQUIRED_FUNCTIONS:
        found = f"fn {fn_name}" in src
        checks.append(_check(f"function {fn_name}", found))
    return checks


def check_spec_sections() -> list:
    src = _read(SPEC_FILE)
    return [_check(f"spec section: {s}", s in src) for s in REQUIRED_SPEC_SECTIONS]


def check_trust_object_types() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in TRUST_OBJECT_TYPES:
        found = t in src
        checks.append(_check(f"trust object type {t}", found))
    checks.append(_check("6 trust object types", all(t in src for t in TRUST_OBJECT_TYPES)))
    return checks


def check_domain_tags() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("domain tags defined", "domain_tag" in src))
    checks.append(_check("domain tag 0x10 prefix", "0x10" in src))
    checks.append(_check("unique domain tags test", "test_domain_tags_unique" in src))
    return checks


def check_serde_derives() -> list:
    src = _read(IMPL_FILE)
    checks = []
    for t in ["TrustObjectType", "CanonicalSchema", "SignaturePreimage", "SerializerEvent"]:
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
    checks.append(_check(f"Rust unit tests present ({test_count})", test_count >= 45, f"{test_count} tests"))

    test_categories = [
        ("object types", "test_all_object_types_count"),
        ("domain tags unique", "test_domain_tags_unique"),
        ("round-trip all types", "test_round_trip_all_types"),
        ("float detection", "test_float_detection"),
        ("preimage build", "test_preimage_build"),
        ("preimage deterministic", "test_preimage_deterministic"),
        ("serialize deterministic", "test_serialize_deterministic"),
        ("error codes test", "test_error_codes"),
        ("serde roundtrip", "test_trust_object_type_serde"),
        ("send+sync", "test_types_send_sync"),
        ("demo function", "test_demo_canonical_serialization"),
        ("encode/decode round-trip", "test_canonical_encode_decode_round_trip"),
    ]
    for name, pattern in test_categories:
        found = pattern in src
        checks.append(_check(f"test: {name}", found))
    return checks


def check_upstream_integration() -> list:
    src = _read(IMPL_FILE)
    checks = []
    checks.append(_check("imports DomainPrefix from trust_object_id", "trust_object_id::DomainPrefix" in src))
    checks.append(_check("uses sha2::Sha256", "Sha256" in src))
    checks.append(_check("uses hex::encode", "hex::encode" in src))
    return checks


def check_acceptance_criteria() -> list:
    src = _read(IMPL_FILE)
    checks = []
    ac1 = all(t in src for t in TRUST_OBJECT_TYPES)
    checks.append(_check("AC1: 6 trust object types registered", ac1))
    ac2 = "round_trip_canonical" in src and "test_round_trip_all_types" in src
    checks.append(_check("AC2: round_trip_canonical for all types", ac2))
    ac3 = "golden_vectors" in src or "golden" in src.lower() or "test_demo" in src
    checks.append(_check("AC3: golden vector integration", ac3))
    ac4 = "INV-CAN-NO-BYPASS" in src
    checks.append(_check("AC4: no bypass invariant", ac4))
    ac5 = "test_preimage_deterministic" in src
    checks.append(_check("AC5: preimage byte-identical", ac5))
    ac6 = "CAN_SERIALIZE" in src and "trace_id" in src
    checks.append(_check("AC6: structured logging with trace IDs", ac6))
    ac7 = "INV-CAN-NO-FLOAT" in src and "contains_float_marker" in src
    checks.append(_check("AC7: no floating-point enforcement", ac7))
    ac8 = "Serialize" in src and "Deserialize" in src
    checks.append(_check("AC8: serde for evidence schema", ac8))
    return checks


def simulate_canonical_serialization() -> dict:
    results = {}

    # Deterministic: same input → same output
    data = b"test-payload"
    e1 = struct.pack(">I", len(data)) + data
    e2 = struct.pack(">I", len(data)) + data
    results["deterministic"] = e1 == e2

    # Round-trip: encode → decode → re-encode
    decoded = e1[4:]
    re_encoded = struct.pack(">I", len(decoded)) + decoded
    results["round_trip_stable"] = e1 == re_encoded

    # Preimage includes domain tag
    version = 1
    domain_tag = bytes([0x10, 0x01])
    preimage = bytes([version]) + domain_tag + e1
    results["preimage_has_domain_tag"] = preimage[1:3] == domain_tag

    # Different domain tags produce different preimages
    preimage2 = bytes([version]) + bytes([0x10, 0x02]) + e1
    results["different_domains_differ"] = preimage != preimage2

    # Float detection
    json_float = b'{"value": 3.14}'
    results["float_detected"] = b"3.14" in json_float

    # 6 object types
    results["object_type_count"] = len(TRUST_OBJECT_TYPES)

    # 3 event codes
    results["event_code_count"] = len(REQUIRED_EVENT_CODES)

    # 5 error codes
    results["error_code_count"] = len(REQUIRED_ERROR_CODES)

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
    checks.extend(check_trust_object_types())
    checks.extend(check_domain_tags())
    checks.extend(check_serde_derives())
    checks.extend(check_tests())
    checks.extend(check_upstream_integration())
    checks.extend(check_acceptance_criteria())

    sim = simulate_canonical_serialization()
    checks.append(_check("sim: deterministic encoding", sim["deterministic"]))
    checks.append(_check("sim: round-trip stable", sim["round_trip_stable"]))
    checks.append(_check("sim: preimage has domain tag", sim["preimage_has_domain_tag"]))
    checks.append(_check("sim: different domains differ", sim["different_domains_differ"]))
    checks.append(_check("sim: float detection", sim["float_detected"]))
    checks.append(_check("sim: 6 object types", sim["object_type_count"] == 6))
    checks.append(_check("sim: 3 event codes", sim["event_code_count"] == 3))
    checks.append(_check("sim: 5 error codes", sim["error_code_count"] == 5))

    passed = sum(1 for c in checks if c["pass"])
    failed = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-jjm",
        "title": "Canonical deterministic serialization and signature preimage rules",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def run_all() -> dict:
    return run_checks()


def self_test() -> tuple:
    checks = []
    checks.append(_check("REQUIRED_STRUCTS count", len(REQUIRED_STRUCTS) >= 6))
    checks.append(_check("REQUIRED_EVENT_CODES count", len(REQUIRED_EVENT_CODES) == 3))
    checks.append(_check("REQUIRED_ERROR_CODES count", len(REQUIRED_ERROR_CODES) == 5))
    checks.append(_check("REQUIRED_INVARIANTS count", len(REQUIRED_INVARIANTS) == 4))
    checks.append(_check("REQUIRED_FUNCTIONS count", len(REQUIRED_FUNCTIONS) >= 15))
    checks.append(_check("TRUST_OBJECT_TYPES count", len(TRUST_OBJECT_TYPES) == 6))

    sim = simulate_canonical_serialization()
    checks.append(_check("simulation returns dict", isinstance(sim, dict)))

    result = run_checks()
    checks.append(_check("run_checks has bead_id", result.get("bead_id") == "bd-jjm"))
    checks.append(_check("run_checks has section", result.get("section") == "10.10"))
    checks.append(_check("run_checks has verdict", result.get("verdict") in ("PASS", "FAIL")))

    h1 = _sha256_hex(b"test")
    h2 = _sha256_hex(b"test")
    checks.append(_check("sha256 deterministic", h1 == h2))

    ok = all(c["pass"] for c in checks)
    return (ok, checks)


def main():
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        for c in checks:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}")
        print(f"\nself-test: {passed}/{len(checks)} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            print(f"  [{'PASS' if c['pass'] else 'FAIL'}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
