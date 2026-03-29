#!/usr/bin/env python3
"""bd-12n3 verifier: epoch-bound idempotency key derivation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from typing import Any
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "idempotency.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "mod.rs")
CONF_TEST = os.path.join(ROOT, "tests", "conformance", "idempotency_key_derivation.rs")
VECTORS = os.path.join(ROOT, "artifacts", "10.14", "idempotency_vectors.json")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-12n3_contract.md")

BEAD = "bd-12n3"
SECTION = "10.14"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_ANY = re.compile(r"^[0-9a-f]*$")

REQUIRED_IMPL_MARKERS = [
    "pub const IDEMPOTENCY_DOMAIN_PREFIX",
    "pub struct IdempotencyKey",
    "pub struct IdempotencyKeyDeriver",
    "pub fn derive_key(",
    "pub fn derive_registered_key(",
    "pub fn collision_count(",
    "IK_KEY_DERIVED",
    "IK_DERIVATION_ERROR",
    "IK_VECTOR_VERIFIED",
    "IK_COLLISION_CHECK_PASSED",
]

REQUIRED_CONF_MARKERS = [
    "published_idempotency_vectors_match_derivation",
    "collision_check_10k_is_clean",
    "separator_collision_inputs_do_not_alias_after_derivation_fix",
    "registry_rejection_happens_before_derivation",
    "artifacts/10.14/idempotency_vectors.json",
]


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _len_prefixed(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big", signed=False) + data


def _derive(prefix: str, computation_name: str, epoch: int, request_hex: str) -> str:
    payload = bytes.fromhex(request_hex)
    digest_input = (
        _len_prefixed(prefix.encode("utf-8"))
        + _len_prefixed(computation_name.encode("utf-8"))
        + epoch.to_bytes(8, "big", signed=False)
        + _len_prefixed(payload)
    )
    return hashlib.sha256(b"idempotency_key_derive_v1:" + digest_input).hexdigest()


def _check_vectors_document() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str) -> None:
        out.append({"check": name, "passed": passed, "detail": detail})

    if not os.path.isfile(VECTORS):
        ok("vectors_exists", False, VECTORS)
        return out
    ok("vectors_exists", True, VECTORS)

    raw = _read(VECTORS)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        ok("vectors_parse_json", False, str(exc))
        return out
    ok("vectors_parse_json", True, "parsed")

    prefix = doc.get("domain_prefix")
    ok(
        "vectors_domain_prefix",
        isinstance(prefix, str) and bool(prefix),
        f"prefix={prefix!r}",
    )

    vectors = doc.get("vectors")
    ok("vectors_list_type", isinstance(vectors, list), f"type={type(vectors).__name__}")
    if not isinstance(vectors, list):
        return out

    ok("vectors_count", len(vectors) >= 20, f"count={len(vectors)}")

    invalid_rows = 0
    recompute_mismatch = 0
    for row in vectors:
        if not isinstance(row, dict):
            invalid_rows += 1
            continue
        name = row.get("computation_name")
        epoch = row.get("epoch")
        request_hex = row.get("request_bytes_hex")
        expected_hex = row.get("expected_key_hex")
        row_ok = (
            isinstance(name, str)
            and bool(name)
            and isinstance(epoch, int)
            and isinstance(request_hex, str)
            and bool(HEX_ANY.fullmatch(request_hex))
            and isinstance(expected_hex, str)
            and bool(HEX64.fullmatch(expected_hex))
        )
        if not row_ok:
            invalid_rows += 1
            continue
        if isinstance(prefix, str):
            actual = _derive(prefix, name, epoch, request_hex)
            if actual != expected_hex:
                recompute_mismatch += 1

    ok("vectors_row_shape", invalid_rows == 0, f"invalid_rows={invalid_rows}")
    ok(
        "vectors_recompute_match",
        recompute_mismatch == 0,
        f"mismatched_rows={recompute_mismatch}",
    )

    return out


def _checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    ok("impl_exists", os.path.isfile(IMPL), IMPL)
    ok("mod_exists", os.path.isfile(MOD_RS), MOD_RS)
    ok("conformance_test_exists", os.path.isfile(CONF_TEST), CONF_TEST)
    ok("spec_exists", os.path.isfile(SPEC), SPEC)
    ok("vectors_exists", os.path.isfile(VECTORS), VECTORS)

    src = _read(IMPL) if os.path.isfile(IMPL) else ""
    production_src = src.partition("#[cfg(test)]")[0]
    mod_src = _read(MOD_RS) if os.path.isfile(MOD_RS) else ""
    conf_src = _read(CONF_TEST) if os.path.isfile(CONF_TEST) else ""

    ok(
        "module_wiring",
        "pub mod idempotency;" in mod_src,
        "remote/mod.rs exports idempotency",
    )

    for marker in REQUIRED_IMPL_MARKERS:
        ok(f"impl_marker_{marker}", marker in src, marker)

    for marker in REQUIRED_CONF_MARKERS:
        ok(f"conf_marker_{marker}", marker in conf_src, marker)

    has_len_prefix_helper = "append_len_prefixed_field" in production_src
    uses_raw_separator_framing = "input.push(0x1F)" in production_src
    has_derivation_tag = "idempotency_key_derive_v1:" in production_src
    ok(
        "injective_canonical_framing",
        has_len_prefix_helper and not uses_raw_separator_framing and has_derivation_tag,
        "length-prefixed framing + derivation tag present"
        if has_len_prefix_helper and not uses_raw_separator_framing and has_derivation_tag
        else "missing length-prefixed framing or derivation tag, or raw separator framing still present",
    )

    test_count = len(re.findall(r"#\[test\]", src))
    ok("impl_test_count", test_count >= 12, f"{test_count} tests (>=12)")

    checks.extend(_check_vectors_document())
    return checks


def self_test() -> bool:
    checks = _checks()
    assert len(checks) >= 20, f"expected >=20 checks, got {len(checks)}"
    assert all("check" in c and "passed" in c for c in checks)
    print(f"self_test: {len(checks)} checks OK", file=sys.stderr)
    return True


def main() -> int:
    logger = configure_test_logging("check_idempotency_key_derivation")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"

    if "--json" in sys.argv:
        print(
            json.dumps(
                {
                    "bead_id": BEAD,
                    "section": SECTION,
                    "gate_script": os.path.basename(__file__),
                    "checks_passed": passed,
                    "checks_total": total,
                    "verdict": verdict,
                    "checks": checks,
                },
                indent=2,
            )
        )
    else:
        for c in checks:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
