#!/usr/bin/env python3
"""Verify bd-h93z: asupersync integration release gate contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "conformance" / "asupersync_release_gate.md"
REPORT_PATH = ROOT / "artifacts" / "10.15" / "release_gate_report.json"

REQUIRED_ARTIFACT_TYPES = {
    "evidence_entries",
    "replay_verification",
    "cancellation_injection_report",
    "dpor_results",
    "epoch_validity",
    "obligation_leak_oracle_report",
}

REQUIRED_EVENT_CODES = {
    "RLG-001",
    "RLG-002",
    "RLG-003",
    "RLG-004",
    "RLG-005",
    "RLG-006",
    "RLG-007",
}

CANONICAL_FIELDS = (
    "bead_id",
    "gate_version",
    "generated_at_utc",
    "public_key_id",
    "signature_algorithm",
    "feature_scope",
    "artifact_statuses",
    "waiver",
    "summary",
    "verdict",
    "events",
)

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> None:
    CHECKS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "failed"),
        }
    )


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _parse_iso8601(value: str) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


def _canonical_payload(report: dict[str, Any]) -> dict[str, Any]:
    return {field: report.get(field) for field in CANONICAL_FIELDS}


def _canonical_json(report: dict[str, Any]) -> str:
    return json.dumps(_canonical_payload(report), sort_keys=True, separators=(",", ":"))


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

    digest = signing.get("canonical_payload_sha256")
    expected_digest = _payload_hash(report)
    if digest != expected_digest:
        return False, "canonical payload digest mismatch"

    signature = signing.get("signature")
    expected_sig = _expected_signature(report)
    if signature != expected_sig:
        return False, "signature mismatch"

    return True, "signature valid"


def _validate_waiver(waiver: Any) -> tuple[bool, str]:
    if waiver is None:
        return True, "no waiver"
    if not isinstance(waiver, dict):
        return False, "waiver must be object"

    required = {
        "waiver_id",
        "bead_id",
        "reason",
        "approver",
        "issued_at",
        "expires_at",
        "scope",
    }
    missing = sorted(required - set(waiver.keys()))
    if missing:
        return False, f"waiver missing fields: {', '.join(missing)}"

    if waiver.get("bead_id") != "bd-h93z":
        return False, "waiver bead_id mismatch"

    issued = _parse_iso8601(str(waiver.get("issued_at")))
    expires = _parse_iso8601(str(waiver.get("expires_at")))
    if issued is None or expires is None:
        return False, "waiver timestamps must be RFC3339"

    if expires <= issued:
        return False, "waiver expires_at must be after issued_at"

    if expires > issued + timedelta(days=14):
        return False, "waiver expiry exceeds 14-day policy"

    if expires <= datetime.now(UTC):
        return False, "waiver expired"

    scope = waiver.get("scope")
    if not isinstance(scope, list) or not scope:
        return False, "waiver scope must be non-empty list"

    return True, "waiver valid"


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be object")
    return payload


def _artifact_pass(entry: dict[str, Any], base_dir: Path) -> tuple[bool, str]:
    required_fields = {"artifact_type", "path", "present", "schema_valid", "signed"}
    missing = sorted(required_fields - set(entry.keys()))
    if missing:
        return False, f"missing fields: {', '.join(missing)}"

    artifact_type = entry.get("artifact_type")
    if artifact_type not in REQUIRED_ARTIFACT_TYPES:
        return False, f"unknown artifact type: {artifact_type}"

    rel = entry.get("path")
    if not isinstance(rel, str) or not rel.strip():
        return False, "artifact path must be non-empty string"

    artifact_path = (base_dir / rel).resolve() if not Path(rel).is_absolute() else Path(rel)
    exists = artifact_path.is_file()

    if bool(entry.get("present")) and not exists:
        return False, f"marked present but file missing: {rel}"

    if not bool(entry.get("present")):
        return False, "artifact marked not present"

    if not bool(entry.get("schema_valid")):
        return False, "schema_valid=false"

    if not bool(entry.get("signed")):
        return False, "signed=false"

    return True, "artifact valid"


def run_checks(spec_path: Path = SPEC_PATH, report_path: Path = REPORT_PATH) -> dict[str, Any]:
    CHECKS.clear()

    _check("spec file exists", spec_path.is_file(), _safe_rel(spec_path))
    _check("report file exists", report_path.is_file(), _safe_rel(report_path))

    spec_text = spec_path.read_text(encoding="utf-8") if spec_path.is_file() else ""
    for event_code in sorted(REQUIRED_EVENT_CODES):
        _check(f"spec event code {event_code}", event_code in spec_text)

    report: dict[str, Any] = {}
    parse_error = ""
    if report_path.is_file():
        try:
            report = _load_json(report_path)
        except Exception as exc:  # pragma: no cover
            parse_error = str(exc)
    _check("report parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for c in CHECKS if c["pass"])
        return {
            "bead_id": "bd-h93z",
            "title": "Asupersync integration release gate",
            "section": "10.15",
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = {
        "bead_id",
        "gate_version",
        "generated_at_utc",
        "public_key_id",
        "signature_algorithm",
        "feature_scope",
        "artifact_statuses",
        "summary",
        "verdict",
        "events",
        "signing",
    }
    missing_top = sorted(required_top - set(report.keys()))
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-h93z")
    _check(
        "report generated_at_utc RFC3339",
        _parse_iso8601(str(report.get("generated_at_utc"))) is not None,
        str(report.get("generated_at_utc")),
    )

    statuses = report.get("artifact_statuses")
    _check("artifact_statuses list", isinstance(statuses, list))
    if not isinstance(statuses, list):
        statuses = []

    seen_types: set[str] = set()
    failed_artifacts: list[str] = []
    for idx, entry in enumerate(statuses):
        if not isinstance(entry, dict):
            failed_artifacts.append(f"idx-{idx}: not object")
            continue

        artifact_type = str(entry.get("artifact_type", f"idx-{idx}"))
        seen_types.add(artifact_type)
        passed, detail = _artifact_pass(entry, ROOT)
        _check(f"artifact {artifact_type}", passed, detail)
        if not passed:
            failed_artifacts.append(f"{artifact_type}: {detail}")

    missing_types = sorted(REQUIRED_ARTIFACT_TYPES - seen_types)
    _check(
        "all required artifact types present",
        len(missing_types) == 0,
        "missing: " + ", ".join(missing_types) if missing_types else "ok",
    )

    summary = report.get("summary", {})
    summary_ok = (
        isinstance(summary, dict)
        and isinstance(summary.get("required_count"), int)
        and isinstance(summary.get("passing_count"), int)
        and isinstance(summary.get("failing_count"), int)
        and summary.get("required_count") == len(REQUIRED_ARTIFACT_TYPES)
        and summary.get("passing_count") + summary.get("failing_count") == len(REQUIRED_ARTIFACT_TYPES)
    )
    _check("summary counts valid", summary_ok, json.dumps(summary, sort_keys=True))

    waiver_ok, waiver_detail = _validate_waiver(report.get("waiver"))
    _check("waiver validity", waiver_ok, waiver_detail)

    signature_ok, signature_detail = verify_signature(report)
    _check("signature verification", signature_ok, signature_detail)

    events = report.get("events")
    _check("events list", isinstance(events, list))
    if not isinstance(events, list):
        events = []

    events_set = {str(ev) for ev in events}
    _check("event includes RLG-001", "RLG-001" in events_set)
    _check("event includes RLG-007", "RLG-007" in events_set)

    verdict = str(report.get("verdict", ""))
    if failed_artifacts:
        expected = "PASS_WITH_WAIVER" if waiver_ok and report.get("waiver") else "FAIL"
    else:
        expected = "PASS"
    _check("verdict consistency", verdict == expected, f"expected={expected}, actual={verdict}")

    total = len(CHECKS)
    passed = sum(1 for c in CHECKS if c["pass"])
    final_verdict = "PASS" if passed == total else "FAIL"

    return {
        "bead_id": "bd-h93z",
        "title": "Asupersync integration release gate",
        "section": "10.15",
        "verdict": final_verdict,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "checks": CHECKS,
        "events": list(events),
    }


def _signed_report_fixture(
    base_dir: Path,
    *,
    tamper_signature: bool = False,
    missing_artifact: bool = False,
    expired_waiver: bool = False,
) -> tuple[Path, Path, dict[str, Any]]:
    spec_path = base_dir / "docs" / "conformance" / "asupersync_release_gate.md"
    report_path = base_dir / "artifacts" / "10.15" / "release_gate_report.json"
    inputs_dir = base_dir / "artifacts" / "10.15" / "release_inputs"

    spec_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    inputs_dir.mkdir(parents=True, exist_ok=True)

    spec_path.write_text(
        "\n".join(
            [
                "# asupersync release gate",
                *sorted(REQUIRED_EVENT_CODES),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    artifacts = {
        "evidence_entries": "artifacts/10.15/release_inputs/evidence_entries.json",
        "replay_verification": "artifacts/10.15/release_inputs/replay_verification_results.json",
        "cancellation_injection_report": "artifacts/10.15/release_inputs/cancellation_injection_report.json",
        "dpor_results": "artifacts/10.15/release_inputs/dpor_results.json",
        "epoch_validity": "artifacts/10.15/release_inputs/epoch_validity_results.json",
        "obligation_leak_oracle_report": "artifacts/10.15/release_inputs/obligation_leak_oracle_report.json",
    }

    for rel in artifacts.values():
        path = base_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")

    statuses: list[dict[str, Any]] = []
    for artifact_type, rel in artifacts.items():
        present = not (missing_artifact and artifact_type == "dpor_results")
        statuses.append(
            {
                "artifact_type": artifact_type,
                "path": rel,
                "present": present,
                "schema_valid": present,
                "signed": present,
            }
        )

    now = datetime.now(UTC)
    waiver = None
    verdict = "PASS"
    events = ["RLG-001", "RLG-002", "RLG-007"]

    failing_count = sum(1 for entry in statuses if not entry["present"])
    if failing_count > 0:
        verdict = "FAIL"
        events = ["RLG-001", "RLG-003", "RLG-007"]

    if expired_waiver:
        waiver = {
            "waiver_id": "WAIVER-RLG-TEST-001",
            "bead_id": "bd-h93z",
            "reason": "temporary fixture",
            "approver": "release-owner",
            "issued_at": (now - timedelta(days=10)).isoformat(),
            "expires_at": (now - timedelta(days=1)).isoformat(),
            "scope": ["dpor_results"],
        }
        verdict = "PASS_WITH_WAIVER"
        events = ["RLG-001", "RLG-005", "RLG-007"]

    report: dict[str, Any] = {
        "bead_id": "bd-h93z",
        "gate_version": "rlg-v1.0",
        "generated_at_utc": now.isoformat().replace("+00:00", "Z"),
        "public_key_id": "mock-rlg-key-001",
        "signature_algorithm": "sha256",
        "feature_scope": "T1",
        "artifact_statuses": statuses,
        "waiver": waiver,
        "summary": {
            "required_count": len(REQUIRED_ARTIFACT_TYPES),
            "passing_count": len(REQUIRED_ARTIFACT_TYPES) - failing_count,
            "failing_count": failing_count,
        },
        "verdict": verdict,
        "events": events,
    }

    report["signing"] = {
        "canonical_payload_sha256": _payload_hash(report),
        "signature": _expected_signature(report),
    }

    if tamper_signature:
        report["signing"]["signature"] = "tampered-signature"

    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return spec_path, report_path, report


def write_sample_report(report_path: Path = REPORT_PATH, spec_path: Path = SPEC_PATH) -> dict[str, Any]:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.parent.mkdir(parents=True, exist_ok=True)

    # Reuse fixture generator against the repository root.
    _, _, report = _signed_report_fixture(ROOT)

    # Ensure final report lands at requested path.
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not spec_path.exists():
        spec_path.write_text(
            "\n".join(
                [
                    "# Asupersync Release Gate",
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    return report


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-h93z-self-test-") as tmp:
        base = Path(tmp)

        spec_path, report_path, _ = _signed_report_fixture(base)
        ok_report = run_checks(spec_path, report_path)
        assert ok_report["verdict"] == "PASS", ok_report

        spec_path, report_path, _ = _signed_report_fixture(base, tamper_signature=True)
        bad_sig = run_checks(spec_path, report_path)
        assert bad_sig["verdict"] == "FAIL"
        assert any(c["check"] == "signature verification" and not c["pass"] for c in bad_sig["checks"])

        spec_path, report_path, _ = _signed_report_fixture(base, missing_artifact=True)
        missing = run_checks(spec_path, report_path)
        assert missing["verdict"] == "FAIL"

        spec_path, report_path, _ = _signed_report_fixture(base, expired_waiver=True)
        expired = run_checks(spec_path, report_path)
        assert expired["verdict"] == "FAIL"
        assert any(c["check"] == "waiver validity" and not c["pass"] for c in expired["checks"])

    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test")
    parser.add_argument("--write-sample", action="store_true", help="Write a sample report/spec fixture in-repo")
    parser.add_argument("--spec", type=Path, default=SPEC_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"self_test_pass": ok}, indent=2))
        else:
            print("self_test passed" if ok else "self_test failed")
        return 0 if ok else 1

    if args.write_sample:
        write_sample_report(args.report, args.spec)

    result = run_checks(args.spec, args.report)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
        print(
            f"bd-h93z verification: {result['verdict']} "
            f"({result['passed']}/{result['total']} checks)"
        )

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
