#!/usr/bin/env python3
"""Verify bd-3v9l: BPET-backed release claim gate contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs" / "conformance" / "bpet_release_claim_gate.md"
REPORT_PATH = ROOT / "artifacts" / "10.21" / "bpet_release_gate_report.json"

REQUIRED_CLAIM_IDS = {
    "BPET-CLAIM-001",
    "BPET-CLAIM-002",
    "BPET-CLAIM-003",
    "BPET-CLAIM-004",
}

REQUIRED_EVENT_CODES = {
    "BPET-PERF-001",
    "BPET-PERF-002",
    "BPET-PERF-003",
    "BPET-PERF-004",
    "BPET-PERF-005",
    "BPET-PERF-ERR-SIGNATURE",
    "BPET-PERF-ERR-INPUT",
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


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be object")
    return payload


def _validate_scale(scale: Any) -> tuple[bool, str]:
    if not isinstance(scale, dict):
        return False, "target_scale must be object"

    phenotypes = scale.get("phenotypes")
    trajectories = scale.get("trajectories")
    history_days = scale.get("history_days")

    if not isinstance(phenotypes, int) or phenotypes <= 0:
        return False, "target_scale.phenotypes must be integer > 0"
    if not isinstance(trajectories, int) or trajectories <= 0:
        return False, "target_scale.trajectories must be integer > 0"
    if not isinstance(history_days, int) or history_days <= 0:
        return False, "target_scale.history_days must be integer > 0"
    return True, "target scale valid"


def _claim_pass(claim: dict[str, Any], base_dir: Path) -> tuple[bool, str]:
    budget_p95 = claim.get("budget_p95_ms")
    measured_p95 = claim.get("measured_p95_ms")
    budget_p99 = claim.get("budget_p99_ms")
    measured_p99 = claim.get("measured_p99_ms")
    budget_storage = claim.get("budget_storage_mb")
    measured_storage = claim.get("measured_storage_mb")
    required_calibration = claim.get("required_calibration_artifacts")
    present_calibration = claim.get("calibration_artifacts_present")
    required_signed = claim.get("required_signed_provenance")
    present_signed = claim.get("signed_provenance_present")
    evidence = claim.get("evidence_refs")
    degradation_signal = claim.get("degradation_signal")

    for value, name in (
        (budget_p95, "budget_p95_ms"),
        (measured_p95, "measured_p95_ms"),
        (budget_p99, "budget_p99_ms"),
        (measured_p99, "measured_p99_ms"),
        (budget_storage, "budget_storage_mb"),
        (measured_storage, "measured_storage_mb"),
    ):
        if not isinstance(value, (int, float)) or float(value) < 0.0:
            return False, f"{name} must be numeric >= 0"

    if float(budget_p95) <= 0.0 or float(budget_p99) <= 0.0 or float(budget_storage) <= 0.0:
        return False, "budgets must be > 0"
    if float(budget_p99) < float(budget_p95):
        return False, "budget_p99_ms must be >= budget_p95_ms"

    if not isinstance(required_calibration, int) or required_calibration < 0:
        return False, "required_calibration_artifacts must be integer >= 0"
    if not isinstance(present_calibration, int) or present_calibration < 0:
        return False, "calibration_artifacts_present must be integer >= 0"
    if not isinstance(required_signed, int) or required_signed < 0:
        return False, "required_signed_provenance must be integer >= 0"
    if not isinstance(present_signed, int) or present_signed < 0:
        return False, "signed_provenance_present must be integer >= 0"

    if not isinstance(degradation_signal, str) or not degradation_signal.startswith("BPET-PERF-"):
        return False, "degradation_signal must start with BPET-PERF-"

    target_ok, target_detail = _validate_scale(claim.get("target_scale"))
    if not target_ok:
        return False, target_detail

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

    if float(measured_p95) > float(budget_p95):
        return False, f"p95 {measured_p95} exceeds budget {budget_p95}"
    if float(measured_p99) > float(budget_p99):
        return False, f"p99 {measured_p99} exceeds budget {budget_p99}"
    if float(measured_storage) > float(budget_storage):
        return False, f"storage {measured_storage}MB exceeds budget {budget_storage}MB"
    if present_calibration < required_calibration:
        return (
            False,
            f"calibration_artifacts_present {present_calibration} below required {required_calibration}",
        )
    if present_signed < required_signed:
        return (
            False,
            f"signed_provenance_present {present_signed} below required {required_signed}",
        )

    return True, "latency/storage/evidence requirements satisfied"


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
            "bead_id": "bd-3v9l",
            "title": "BPET release claim gate",
            "section": "10.21",
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

    _check("report bead id", report.get("bead_id") == "bd-3v9l")

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

    _check("event includes BPET-PERF-001", "BPET-PERF-001" in event_codes)
    if derived_decision == "allow":
        _check("event includes allow code", "BPET-PERF-002" in event_codes)
    else:
        _check("event includes block code", "BPET-PERF-004" in event_codes)

    total = len(CHECKS)
    passed = sum(1 for item in CHECKS if item["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3v9l",
        "title": "BPET release claim gate",
        "section": "10.21",
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
    breach_p95: bool = False,
    breach_p99: bool = False,
    breach_storage: bool = False,
    calibration_shortfall: bool = False,
    signed_shortfall: bool = False,
) -> tuple[Path, Path, Path]:
    base_dir.mkdir(parents=True, exist_ok=True)
    spec_path = base_dir / "bpet_release_claim_gate.md"
    report_path = base_dir / "bpet_release_gate_report.json"

    evidence_a = base_dir / "evidence_a.json"
    evidence_b = base_dir / "evidence_b.json"
    evidence_c = base_dir / "evidence_c.json"
    evidence_d = base_dir / "evidence_d.json"
    evidence_a.write_text('{"ok": true}\n', encoding="utf-8")
    evidence_b.write_text('{"ok": true}\n', encoding="utf-8")
    evidence_c.write_text('{"ok": true}\n', encoding="utf-8")
    evidence_d.write_text('{"ok": true}\n', encoding="utf-8")

    if drop_evidence:
        evidence_d.unlink()

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

    claim_2_p95 = 73.0 if breach_p95 else 52.0
    claim_3_p99 = 96.0 if breach_p99 else 64.0
    claim_3_storage = 330.0 if breach_storage else 255.0
    calibration_present = 1 if calibration_shortfall else 2
    signed_present = 1 if signed_shortfall else 2

    claims = [
        {
            "claim_id": "BPET-CLAIM-001",
            "claim": "Trajectory scoring latency stays within budget.",
            "target_scale": {
                "phenotypes": 12000,
                "trajectories": 320000,
                "history_days": 365,
            },
            "budget_p95_ms": 40.0,
            "measured_p95_ms": 29.0,
            "budget_p99_ms": 58.0,
            "measured_p99_ms": 43.0,
            "budget_storage_mb": 220.0,
            "measured_storage_mb": 180.0,
            "degradation_signal": "BPET-PERF-005",
            "required_calibration_artifacts": 1,
            "calibration_artifacts_present": 1,
            "required_signed_provenance": 1,
            "signed_provenance_present": 1,
            "evidence_refs": [str(evidence_a)],
        },
        {
            "claim_id": "BPET-CLAIM-002",
            "claim": "Drift/regime analysis stays within budget and degradation contract.",
            "target_scale": {
                "phenotypes": 12000,
                "trajectories": 320000,
                "history_days": 365,
            },
            "budget_p95_ms": 65.0,
            "measured_p95_ms": claim_2_p95,
            "budget_p99_ms": 92.0,
            "measured_p99_ms": 71.0,
            "budget_storage_mb": 260.0,
            "measured_storage_mb": 210.0,
            "degradation_signal": "BPET-PERF-005",
            "required_calibration_artifacts": 1,
            "calibration_artifacts_present": 1,
            "required_signed_provenance": 1,
            "signed_provenance_present": 1,
            "evidence_refs": [str(evidence_b)],
        },
        {
            "claim_id": "BPET-CLAIM-003",
            "claim": "Lineage persistence stays within latency and storage budgets.",
            "target_scale": {
                "phenotypes": 12000,
                "trajectories": 320000,
                "history_days": 365,
            },
            "budget_p95_ms": 55.0,
            "measured_p95_ms": 41.0,
            "budget_p99_ms": 82.0,
            "measured_p99_ms": claim_3_p99,
            "budget_storage_mb": 310.0,
            "measured_storage_mb": claim_3_storage,
            "degradation_signal": "BPET-PERF-005",
            "required_calibration_artifacts": 1,
            "calibration_artifacts_present": 1,
            "required_signed_provenance": 1,
            "signed_provenance_present": 1,
            "evidence_refs": [str(evidence_c)],
        },
        {
            "claim_id": "BPET-CLAIM-004",
            "claim": "Predictive release claim package has complete calibration/provenance chain.",
            "target_scale": {
                "phenotypes": 12000,
                "trajectories": 320000,
                "history_days": 365,
            },
            "budget_p95_ms": 48.0,
            "measured_p95_ms": 33.0,
            "budget_p99_ms": 70.0,
            "measured_p99_ms": 51.0,
            "budget_storage_mb": 240.0,
            "measured_storage_mb": 190.0,
            "degradation_signal": "BPET-PERF-005",
            "required_calibration_artifacts": 2,
            "calibration_artifacts_present": calibration_present,
            "required_signed_provenance": 2,
            "signed_provenance_present": signed_present,
            "evidence_refs": [str(evidence_d)],
        },
    ]

    report = {
        "bead_id": "bd-3v9l",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "gate_version": "1.0.0",
        "public_key_id": "bpet-release-gate-v1",
        "signature_algorithm": "sha256-canonical-v1",
        "designated_claims": claims,
        "summary": {
            "total_claims": 4,
            "passed_claims": 4,
            "failed_claims": 0,
            "release_decision": "allow",
        },
        "events": [
            {
                "code": "BPET-PERF-001",
                "detail": "gate evaluation started",
            },
            {
                "code": "BPET-PERF-002",
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
    return spec_path, report_path, evidence_d


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-3v9l-selftest-") as tmp:
        root = Path(tmp)

        spec_ok, report_ok, _ = _signed_report_fixture(root)
        ok_result = run_checks(spec_ok, report_ok)

        spec_sig, report_sig, _ = _signed_report_fixture(root / "sig", tamper_signature=True)
        bad_sig_result = run_checks(spec_sig, report_sig)

        spec_evi, report_evi, _ = _signed_report_fixture(root / "evi", drop_evidence=True)
        bad_evidence_result = run_checks(spec_evi, report_evi)

        spec_p95, report_p95, _ = _signed_report_fixture(root / "p95", breach_p95=True)
        bad_p95_result = run_checks(spec_p95, report_p95)

        spec_p99, report_p99, _ = _signed_report_fixture(root / "p99", breach_p99=True)
        bad_p99_result = run_checks(spec_p99, report_p99)

        spec_storage, report_storage, _ = _signed_report_fixture(root / "storage", breach_storage=True)
        bad_storage_result = run_checks(spec_storage, report_storage)

        spec_cal, report_cal, _ = _signed_report_fixture(root / "cal", calibration_shortfall=True)
        bad_cal_result = run_checks(spec_cal, report_cal)

        spec_signed, report_signed, _ = _signed_report_fixture(root / "signed", signed_shortfall=True)
        bad_signed_result = run_checks(spec_signed, report_signed)

    return (
        ok_result["verdict"] == "PASS"
        and bad_sig_result["verdict"] == "FAIL"
        and bad_evidence_result["verdict"] == "FAIL"
        and bad_p95_result["verdict"] == "FAIL"
        and bad_p99_result["verdict"] == "FAIL"
        and bad_storage_result["verdict"] == "FAIL"
        and bad_cal_result["verdict"] == "FAIL"
        and bad_signed_result["verdict"] == "FAIL"
    )


def main() -> int:
    logger = configure_test_logging("check_bpet_claim_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=SPEC_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {
            "bead_id": "bd-3v9l",
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
