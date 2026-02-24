#!/usr/bin/env python3
"""Verify bd-11rz: ATC-backed release claim gate contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs" / "conformance" / "atc_release_claim_gate.md"
REPORT_PATH = ROOT / "artifacts" / "10.19" / "atc_release_gate_report.json"

REQUIRED_CLAIM_IDS = {
    "ATC-CLAIM-001",
    "ATC-CLAIM-002",
    "ATC-CLAIM-003",
}

REQUIRED_EVENT_CODES = {
    "ATC-RELEASE-001",
    "ATC-RELEASE-002",
    "ATC-RELEASE-003",
    "ATC-RELEASE-ERR-SIGNATURE",
    "ATC-RELEASE-ERR-INPUT",
}

CANONICAL_FIELDS = (
    "bead_id",
    "generated_at_utc",
    "gate_version",
    "public_key_id",
    "signature_algorithm",
    "designated_claims",
    "summary",
)

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> None:
    CHECKS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("found" if passed else "NOT FOUND"),
        }
    )


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _parse_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _canonical_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {field: report.get(field) for field in CANONICAL_FIELDS}


def _canonical_json(report: dict[str, Any]) -> str:
    return json.dumps(
        _canonical_payload(report),
        sort_keys=True,
        separators=(",", ":"),
    )


def _payload_hash(report: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(report).encode("utf-8")).hexdigest()


def _expected_signature(report: dict[str, Any]) -> str:
    key_id = str(report.get("public_key_id", ""))
    digest = _payload_hash(report)
    return hashlib.sha256(f"{key_id}:{digest}".encode("utf-8")).hexdigest()


def verify_signature(report: dict[str, Any]) -> tuple[bool, str]:
    signing = report.get("signing")
    if not isinstance(signing, dict):
        return False, "signing object missing"

    expected_digest = _payload_hash(report)
    digest = signing.get("canonical_payload_sha256")
    if digest != expected_digest:
        return False, "canonical payload digest mismatch"

    expected_sig = _expected_signature(report)
    signature = signing.get("signature")
    if signature != expected_sig:
        return False, "signature mismatch"

    return True, "signature valid"


def _claim_pass(claim: dict[str, Any], base_dir: Path) -> tuple[bool, str]:
    required_coverage = claim.get("required_coverage_ratio")
    coverage = claim.get("coverage_ratio")
    required_provenance = claim.get("required_provenance_artifacts")
    present_provenance = claim.get("provenance_artifacts_present")
    evidence = claim.get("evidence_refs")

    if not isinstance(required_coverage, (int, float)) or not 0.0 <= float(required_coverage) <= 1.0:
        return False, "required_coverage_ratio must be in [0,1]"
    if not isinstance(coverage, (int, float)) or not 0.0 <= float(coverage) <= 1.0:
        return False, "coverage_ratio must be in [0,1]"

    if not isinstance(required_provenance, int) or required_provenance < 0:
        return False, "required_provenance_artifacts must be >= 0"
    if not isinstance(present_provenance, int) or present_provenance < 0:
        return False, "provenance_artifacts_present must be >= 0"

    if not isinstance(evidence, list) or len(evidence) == 0:
        return False, "evidence_refs must be a non-empty list"

    missing: list[str] = []
    for entry in evidence:
        if not isinstance(entry, str) or not entry.strip():
            missing.append(str(entry))
            continue
        ref = (base_dir / entry).resolve() if not Path(entry).is_absolute() else Path(entry)
        if not ref.is_file():
            missing.append(entry)

    if missing:
        return False, f"missing evidence refs: {sorted(set(missing))}"

    if float(coverage) < float(required_coverage):
        return False, f"coverage_ratio {coverage} below required {required_coverage}"

    if present_provenance < required_provenance:
        return (
            False,
            f"provenance_artifacts_present {present_provenance} below required {required_provenance}",
        )

    return True, "coverage/provenance/evidence satisfied"


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be object")
    return payload


def run_checks(spec_path: Path = SPEC_PATH, report_path: Path = REPORT_PATH) -> dict[str, Any]:
    CHECKS.clear()

    _check("spec file exists", spec_path.is_file(), _safe_rel(spec_path))
    _check("report file exists", report_path.is_file(), _safe_rel(report_path))

    spec_text = spec_path.read_text(encoding="utf-8") if spec_path.is_file() else ""
    for claim_id in sorted(REQUIRED_CLAIM_IDS):
        _check(f"spec claim id {claim_id}", claim_id in spec_text)
    for event_code in sorted(REQUIRED_EVENT_CODES):
        _check(f"spec event code {event_code}", event_code in spec_text)

    report: dict[str, Any] = {}
    parse_error = ""
    if report_path.is_file():
        try:
            report = _load_json(report_path)
        except Exception as exc:  # pragma: no cover - defensive
            parse_error = str(exc)
    _check("report parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for item in CHECKS if item["pass"])
        return {
            "bead_id": "bd-11rz",
            "title": "ATC release claim gate",
            "section": "10.19",
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = {
        "bead_id",
        "generated_at_utc",
        "gate_version",
        "public_key_id",
        "signature_algorithm",
        "designated_claims",
        "summary",
        "signing",
        "events",
    }
    missing_top = sorted(required_top - set(report.keys()))
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-11rz")

    generated_at = report.get("generated_at_utc")
    _check(
        "report generated_at_utc RFC3339",
        isinstance(generated_at, str) and _parse_iso8601(generated_at),
        str(generated_at),
    )

    claims = report.get("designated_claims")
    _check("designated_claims list", isinstance(claims, list))
    if not isinstance(claims, list):
        claims = []

    seen_claims: set[str] = set()
    duplicate_claims: set[str] = set()
    claim_results: list[tuple[str, bool, str]] = []

    for idx, claim in enumerate(claims):
        if not isinstance(claim, dict):
            claim_results.append((f"idx-{idx}", False, "claim entry must be object"))
            continue

        claim_id = str(claim.get("claim_id", "")).strip()
        if not claim_id:
            claim_id = f"idx-{idx}"

        if claim_id in seen_claims:
            duplicate_claims.add(claim_id)
        seen_claims.add(claim_id)

        passed, detail = _claim_pass(claim, ROOT)
        claim_results.append((claim_id, passed, detail))

    _check("no duplicate claim IDs", len(duplicate_claims) == 0)

    missing_required_claims = sorted(REQUIRED_CLAIM_IDS - seen_claims)
    _check(
        "required claim IDs present",
        len(missing_required_claims) == 0,
        "missing: " + ", ".join(missing_required_claims) if missing_required_claims else "ok",
    )

    failed_claims = [entry for entry in claim_results if not entry[1]]
    for claim_id, passed, detail in claim_results:
        _check(f"claim {claim_id}", passed, detail)

    derived_total = len(claim_results)
    derived_failed = len(failed_claims)
    derived_passed = derived_total - derived_failed
    derived_decision = "allow" if derived_failed == 0 else "block"

    summary = report.get("summary")
    _check("summary object", isinstance(summary, dict))
    if not isinstance(summary, dict):
        summary = {}

    _check("summary total_claims", summary.get("total_claims") == derived_total)
    _check("summary passed_claims", summary.get("passed_claims") == derived_passed)
    _check("summary failed_claims", summary.get("failed_claims") == derived_failed)
    _check("summary release_decision", summary.get("release_decision") == derived_decision)

    valid_sig, sig_detail = verify_signature(report)
    _check("signature verification", valid_sig, sig_detail)

    first_sig = _expected_signature(report)
    second_sig = _expected_signature(report)
    _check("signature idempotency", first_sig == second_sig)

    external_ok, external_detail = verify_signature(report)
    _check("external verification", external_ok, external_detail)

    events = report.get("events")
    _check("events list", isinstance(events, list))
    event_codes = {
        str(item.get("code"))
        for item in (events if isinstance(events, list) else [])
        if isinstance(item, dict)
    }

    _check("event includes ATC-RELEASE-001", "ATC-RELEASE-001" in event_codes)
    if derived_decision == "allow":
        _check("event includes allow code", "ATC-RELEASE-002" in event_codes)
    else:
        _check("event includes block code", "ATC-RELEASE-003" in event_codes)

    total = len(CHECKS)
    passed = sum(1 for item in CHECKS if item["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-11rz",
        "title": "ATC release claim gate",
        "section": "10.19",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "summary": {
            "derived_total_claims": derived_total,
            "derived_passed_claims": derived_passed,
            "derived_failed_claims": derived_failed,
            "derived_release_decision": derived_decision,
        },
        "checks": CHECKS,
        "events": sorted(event_codes),
    }


def _signed_report_fixture(
    base_dir: Path,
    *,
    tamper_signature: bool = False,
    drop_evidence: bool = False,
    degrade_coverage: bool = False,
    provenance_shortfall: bool = False,
) -> tuple[Path, Path, Path]:
    base_dir.mkdir(parents=True, exist_ok=True)
    spec_path = base_dir / "atc_release_claim_gate.md"
    report_path = base_dir / "atc_release_gate_report.json"

    evidence_a = base_dir / "evidence_a.json"
    evidence_b = base_dir / "evidence_b.json"
    evidence_c = base_dir / "evidence_c.json"
    evidence_a.write_text('{"ok": true}\n', encoding="utf-8")
    evidence_b.write_text('{"ok": true}\n', encoding="utf-8")
    evidence_c.write_text('{"ok": true}\n', encoding="utf-8")

    if drop_evidence:
        evidence_c.unlink()

    spec_path.write_text(
        "\n".join(
            [
                "# fixture",
                *sorted(REQUIRED_CLAIM_IDS),
                *sorted(REQUIRED_EVENT_CODES),
            ]
        ),
        encoding="utf-8",
    )

    low_coverage = 0.50 if degrade_coverage else 1.0
    shortfall = 1 if provenance_shortfall else 2

    claims = [
        {
            "claim_id": "ATC-CLAIM-001",
            "claim": "federated claim includes required ATC coverage",
            "required_coverage_ratio": 1.0,
            "coverage_ratio": 1.0,
            "required_provenance_artifacts": 1,
            "provenance_artifacts_present": 1,
            "evidence_refs": [str(evidence_a)],
        },
        {
            "claim_id": "ATC-CLAIM-002",
            "claim": "collective metric has verifier-backed provenance",
            "required_coverage_ratio": 0.9,
            "coverage_ratio": low_coverage,
            "required_provenance_artifacts": 1,
            "provenance_artifacts_present": 1,
            "evidence_refs": [str(evidence_b)],
        },
        {
            "claim_id": "ATC-CLAIM-003",
            "claim": "release claim package contains signed artifact chain",
            "required_coverage_ratio": 1.0,
            "coverage_ratio": 1.0,
            "required_provenance_artifacts": 2,
            "provenance_artifacts_present": shortfall,
            "evidence_refs": [str(evidence_c)],
        },
    ]

    report = {
        "bead_id": "bd-11rz",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "gate_version": "1.0.0",
        "public_key_id": "atc-release-gate-v1",
        "signature_algorithm": "sha256-canonical-v1",
        "designated_claims": claims,
        "summary": {
            "total_claims": 3,
            "passed_claims": 3,
            "failed_claims": 0,
            "release_decision": "allow",
        },
        "events": [
            {
                "code": "ATC-RELEASE-001",
                "detail": "gate evaluation started",
            },
            {
                "code": "ATC-RELEASE-002",
                "detail": "all designated claims satisfied",
            },
        ],
    }

    report["signing"] = {
        "canonical_payload_sha256": _payload_hash(report),
        "signature": _expected_signature(report),
    }

    if tamper_signature:
        report["signing"]["signature"] = "tampered-signature"

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return spec_path, report_path, evidence_c


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-11rz-selftest-") as tmp:
        root = Path(tmp)

        spec_ok, report_ok, _ = _signed_report_fixture(root)
        ok_result = run_checks(spec_ok, report_ok)

        spec_sig, report_sig, _ = _signed_report_fixture(root / "sig", tamper_signature=True)
        bad_sig_result = run_checks(spec_sig, report_sig)

        spec_cov, report_cov, _ = _signed_report_fixture(root / "cov", degrade_coverage=True)
        bad_cov_result = run_checks(spec_cov, report_cov)

        spec_prov, report_prov, _ = _signed_report_fixture(root / "prov", provenance_shortfall=True)
        bad_prov_result = run_checks(spec_prov, report_prov)

        spec_evi, report_evi, _ = _signed_report_fixture(root / "evi", drop_evidence=True)
        bad_evidence_result = run_checks(spec_evi, report_evi)

    return (
        ok_result["verdict"] == "PASS"
        and bad_sig_result["verdict"] == "FAIL"
        and bad_cov_result["verdict"] == "FAIL"
        and bad_prov_result["verdict"] == "FAIL"
        and bad_evidence_result["verdict"] == "FAIL"
    )


def main() -> int:
    logger = configure_test_logging("check_atc_claim_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=SPEC_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {
            "bead_id": "bd-11rz",
            "check": "self_test",
            "verdict": "PASS" if ok else "FAIL",
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"self_test verdict: {payload['verdict']}")
        return 0 if ok else 1

    report = run_checks(args.spec, args.report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for item in report["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")
        print(f"\nverdict: {report['verdict']} ({report['passed']}/{report['total']})")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
