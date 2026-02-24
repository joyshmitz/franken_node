#!/usr/bin/env python3
"""bd-3cs3 verifier: epoch-scoped key derivation for trust artifacts.

Usage:
  python3 scripts/check_epoch_scoped_keys.py --json
  python3 scripts/check_epoch_scoped_keys.py --self-test
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "crates" / "franken-node" / "src" / "security" / "epoch_scoped_keys.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
CONF_TEST = ROOT / "tests" / "conformance" / "epoch_key_derivation.rs"
VECTORS = ROOT / "artifacts" / "10.14" / "epoch_key_vectors.json"

HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_IMPL_MARKERS = [
    "pub struct RootSecret",
    "pub struct DerivedKey",
    "pub struct Signature",
    "pub fn derive_epoch_key(",
    "pub fn sign_epoch_artifact(",
    "pub fn verify_epoch_signature(",
    "ZeroizeOnDrop",
    "EPOCH_KEY_DERIVED",
    "EPOCH_SIG_VERIFIED",
    "EPOCH_SIG_REJECTED",
]

REQUIRED_CONFORMANCE_MARKERS = [
    "published_epoch_key_vectors_match_derivation",
    "verify_rejects_cross_epoch_and_cross_domain_signatures",
    "derivation_throughput_meets_minimum_budget",
    "artifacts/10.14/epoch_key_vectors.json",
]


def check_file(path: Path, check_id: str, label: str) -> dict[str, Any]:
    ok = path.is_file()
    rel = path.relative_to(ROOT) if ok else path
    return {
        "id": check_id,
        "check": label,
        "pass": ok,
        "detail": f"exists: {rel}" if ok else f"missing: {rel}",
    }


def check_markers(path: Path, markers: list[str], prefix: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return [
            {
                "id": f"{prefix}-FILE-MISSING",
                "check": f"{prefix.lower()} markers",
                "pass": False,
                "detail": f"missing: {path.relative_to(ROOT)}",
            }
        ]
    text = path.read_text(encoding="utf-8")
    out = []
    for marker in markers:
        ok = marker in text
        marker_key = marker.upper().replace(" ", "-").replace("(", "").replace(")", "")
        out.append(
            {
                "id": f"{prefix}-{marker_key[:40]}",
                "check": f"contains: {marker}",
                "pass": ok,
                "detail": "found" if ok else "not found",
            }
        )
    return out


def check_module_registration() -> dict[str, Any]:
    if not MOD_RS.is_file():
        return {
            "id": "EKS-MOD-REG",
            "check": "security module registration",
            "pass": False,
            "detail": f"missing: {MOD_RS.relative_to(ROOT)}",
        }
    text = MOD_RS.read_text(encoding="utf-8")
    ok = "pub mod epoch_scoped_keys;" in text
    return {
        "id": "EKS-MOD-REG",
        "check": "security/mod.rs exports epoch_scoped_keys",
        "pass": ok,
        "detail": "registered" if ok else "not registered",
    }


def check_impl_test_count() -> dict[str, Any]:
    if not IMPL.is_file():
        return {
            "id": "EKS-IMPL-TEST-COUNT",
            "check": "impl unit test count",
            "pass": False,
            "detail": "implementation file missing",
        }
    text = IMPL.read_text(encoding="utf-8")
    count = len(re.findall(r"#\[test\]", text))
    return {
        "id": "EKS-IMPL-TEST-COUNT",
        "check": "impl has >= 10 unit tests",
        "pass": count >= 10,
        "detail": f"{count} tests",
    }


def _is_hex32(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_32_RE.fullmatch(value))


def check_vectors_json() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not VECTORS.is_file():
        return [
            {
                "id": "EKS-VECTOR-FILE",
                "check": "vectors artifact exists",
                "pass": False,
                "detail": f"missing: {VECTORS.relative_to(ROOT)}",
            }
        ]

    raw = VECTORS.read_text(encoding="utf-8")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [
            {
                "id": "EKS-VECTOR-JSON",
                "check": "vectors artifact parses as JSON",
                "pass": False,
                "detail": str(exc),
            }
        ]

    vectors = doc.get("vectors")
    checks.append(
        {
            "id": "EKS-VECTOR-LIST",
            "check": "vectors list exists",
            "pass": isinstance(vectors, list),
            "detail": f"type={type(vectors).__name__}",
        }
    )

    if not isinstance(vectors, list):
        return checks

    checks.append(
        {
            "id": "EKS-VECTOR-COUNT",
            "check": "vector count >= 10",
            "pass": len(vectors) >= 10,
            "detail": f"count={len(vectors)}",
        }
    )

    bad_rows = 0
    for row in vectors:
        if not isinstance(row, dict):
            bad_rows += 1
            continue
        if not _is_hex32(row.get("root_secret_hex")):
            bad_rows += 1
            continue
        if not isinstance(row.get("epoch"), int):
            bad_rows += 1
            continue
        if not isinstance(row.get("domain"), str) or not row.get("domain"):
            bad_rows += 1
            continue
        if not _is_hex32(row.get("expected_key_hex")):
            bad_rows += 1
            continue
    checks.append(
        {
            "id": "EKS-VECTOR-ROWS",
            "check": "all vectors have valid root/epoch/domain/key fields",
            "pass": bad_rows == 0,
            "detail": f"invalid_rows={bad_rows}",
        }
    )

    signature_kat = doc.get("signature_kat")
    kat_ok = isinstance(signature_kat, dict)
    checks.append(
        {
            "id": "EKS-SIG-KAT-PRESENT",
            "check": "signature_kat object exists",
            "pass": kat_ok,
            "detail": "present" if kat_ok else "missing",
        }
    )

    if kat_ok:
        artifact_hex = signature_kat.get("artifact_hex")
        epoch = signature_kat.get("epoch")
        domain = signature_kat.get("domain")
        expected_signature_hex = signature_kat.get("expected_signature_hex")
        row_ok = (
            isinstance(artifact_hex, str)
            and bool(re.fullmatch(r"[0-9a-f]+", artifact_hex))
            and isinstance(epoch, int)
            and isinstance(domain, str)
            and bool(domain)
            and _is_hex32(expected_signature_hex)
        )
        checks.append(
            {
                "id": "EKS-SIG-KAT-FIELDS",
                "check": "signature_kat fields are valid",
                "pass": row_ok,
                "detail": "valid" if row_ok else "invalid fields",
            }
        )

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "EKS-FILE-IMPL", "implementation exists"))
    checks.append(check_file(CONF_TEST, "EKS-FILE-CONFORMANCE", "conformance test exists"))
    checks.append(check_file(VECTORS, "EKS-FILE-VECTORS", "vector artifact exists"))
    checks.append(check_module_registration())
    checks.append(check_impl_test_count())
    checks.extend(check_markers(IMPL, REQUIRED_IMPL_MARKERS, "EKS-IMPL"))
    checks.extend(check_markers(CONF_TEST, REQUIRED_CONFORMANCE_MARKERS, "EKS-CONF"))
    checks.extend(check_vectors_json())

    passed = sum(1 for c in checks if c["pass"])
    total = len(checks)
    return {
        "bead": "bd-3cs3",
        "title": "Epoch-scoped key derivation for trust artifact authentication",
        "section": "10.14",
        "verdict": "PASS" if passed == total else "FAIL",
        "summary": {
            "passing_checks": passed,
            "failing_checks": total - passed,
            "total_checks": total,
        },
        "checks": checks,
    }


def self_test() -> None:
    report = run_checks()
    assert report["bead"] == "bd-3cs3"
    assert report["section"] == "10.14"
    assert isinstance(report["checks"], list)
    assert report["summary"]["total_checks"] >= 12
    print(
        f"self_test passed: {report['summary']['passing_checks']}/"
        f"{report['summary']['total_checks']}"
    )


def main() -> int:
    logger = configure_test_logging("check_epoch_scoped_keys")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    report = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-3cs3 verdict: {report['verdict']}")
        print(
            f"checks: {report['summary']['passing_checks']}/"
            f"{report['summary']['total_checks']} passed"
        )
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
