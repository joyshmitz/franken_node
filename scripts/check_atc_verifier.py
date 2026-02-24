#!/usr/bin/env python3
"""Verify bd-2zip: ATC verifier APIs and deterministic proof artifacts."""

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

SPEC_PATH = ROOT / "docs" / "specs" / "atc_verifier_contract.md"
CONFORMANCE_PATH = ROOT / "tests" / "conformance" / "atc_verifier_apis.rs"
REPORT_PATH = ROOT / "artifacts" / "10.19" / "atc_verifier_report.json"

REQUIRED_ENDPOINT_IDS = {
    "ATC-VERIFIER-ENDPOINT-001",
    "ATC-VERIFIER-ENDPOINT-002",
    "ATC-VERIFIER-ENDPOINT-003",
    "ATC-VERIFIER-ENDPOINT-004",
}

REQUIRED_EVENT_CODES = {
    "ATC-VERIFIER-001",
    "ATC-VERIFIER-002",
    "ATC-VERIFIER-003",
    "ATC-VERIFIER-004",
    "ATC-VERIFIER-005",
    "ATC-VERIFIER-006",
}

CONFORMANCE_TOKENS = {
    "atc_verifier_contract_is_deterministic",
    "atc_verifier_contract_validates_proof_chain_continuity",
    "atc_verifier_contract_enforces_aggregate_only_visibility",
}

CANONICAL_FIELDS = (
    "bead_id",
    "generated_at_utc",
    "verifier_version",
    "computation_id",
    "dataset_commitment",
    "metric_snapshots",
    "determinism_checks",
    "proof_chain",
    "verifier_outputs",
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


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON root must be object")
    return payload


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

    digest = signing.get("canonical_payload_sha256")
    expected_digest = _payload_hash(report)
    if digest != expected_digest:
        return False, "canonical payload hash mismatch"

    signature = signing.get("signature")
    expected_signature = _expected_signature(report)
    if signature != expected_signature:
        return False, "signature mismatch"

    return True, "signature valid"


def _is_sha256_marker(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if not value.startswith("sha256:"):
        return False
    digest = value.split(":", 1)[1]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def _validate_metric(snapshot: dict[str, Any]) -> tuple[bool, str]:
    metric_id = snapshot.get("metric_id")
    if not isinstance(metric_id, str) or not metric_id.strip():
        return False, "metric_id missing"

    if snapshot.get("data_visibility") != "aggregate_only":
        return False, "data_visibility must be aggregate_only"

    if snapshot.get("raw_participant_data_included") is not False:
        return False, "raw_participant_data_included must be false"

    if not _is_sha256_marker(snapshot.get("source_commitment")):
        return False, "source_commitment must be sha256:<64-hex>"

    return True, "metric snapshot valid"


def _validate_determinism(section: dict[str, Any]) -> tuple[bool, str]:
    runs = section.get("runs")
    if not isinstance(runs, list) or not runs:
        return False, "determinism runs must be non-empty list"

    digests: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            return False, "determinism run entry must be object"
        digest = run.get("result_digest")
        if not _is_sha256_marker(digest):
            return False, "result_digest must be sha256:<64-hex>"
        digests.append(digest)

    all_equal = len(set(digests)) == 1
    if section.get("all_equal") is not all_equal:
        return False, "all_equal flag does not match observed digests"

    if section.get("max_digest_distance") != 0:
        return False, "max_digest_distance must be 0"

    if not all_equal:
        return False, "determinism digest mismatch across runs"

    return True, "determinism satisfied"


def _validate_proof_chain(chain: list[dict[str, Any]]) -> tuple[bool, str]:
    if not chain:
        return False, "proof_chain must be non-empty"

    for idx, entry in enumerate(chain):
        if not isinstance(entry, dict):
            return False, "proof_chain entry must be object"

        step = entry.get("step")
        if step != idx:
            return False, "proof_chain steps must be contiguous starting at 0"

        artifact_hash = entry.get("artifact_hash")
        if not _is_sha256_marker(artifact_hash):
            return False, "artifact_hash must be sha256:<64-hex>"

        parent_hash = entry.get("parent_hash")
        if idx == 0:
            if parent_hash is not None:
                return False, "root proof entry must have parent_hash=null"
        else:
            expected = chain[idx - 1].get("artifact_hash")
            if parent_hash != expected:
                return False, "proof_chain parent hash mismatch"

    return True, "proof_chain valid"


def run_checks(
    spec_path: Path = SPEC_PATH,
    report_path: Path = REPORT_PATH,
    conformance_path: Path = CONFORMANCE_PATH,
) -> dict[str, Any]:
    CHECKS.clear()

    _check("spec file exists", spec_path.is_file(), _safe_rel(spec_path))
    _check("report file exists", report_path.is_file(), _safe_rel(report_path))
    _check("conformance test file exists", conformance_path.is_file(), _safe_rel(conformance_path))

    spec_text = spec_path.read_text(encoding="utf-8") if spec_path.is_file() else ""
    for endpoint_id in sorted(REQUIRED_ENDPOINT_IDS):
        _check(f"spec endpoint {endpoint_id}", endpoint_id in spec_text)
    for event_code in sorted(REQUIRED_EVENT_CODES):
        _check(f"spec event code {event_code}", event_code in spec_text)

    conformance_text = conformance_path.read_text(encoding="utf-8") if conformance_path.is_file() else ""
    for token in sorted(CONFORMANCE_TOKENS):
        _check(f"conformance token {token}", token in conformance_text)

    parse_error = ""
    report: dict[str, Any] = {}
    if report_path.is_file():
        try:
            report = _load_json(report_path)
        except Exception as exc:  # pragma: no cover - defensive
            parse_error = str(exc)

    _check("report parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for entry in CHECKS if entry["pass"])
        return {
            "bead_id": "bd-2zip",
            "title": "ATC verifier APIs and proof artifacts",
            "section": "10.19",
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "checks": CHECKS,
        }

    required_top = {
        "bead_id",
        "generated_at_utc",
        "verifier_version",
        "public_key_id",
        "signature_algorithm",
        "computation_id",
        "dataset_commitment",
        "metric_snapshots",
        "determinism_checks",
        "proof_chain",
        "verifier_outputs",
        "evidence_refs",
        "events",
        "signing",
    }
    missing_top = sorted(required_top - set(report.keys()))
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-2zip")

    generated_at = report.get("generated_at_utc")
    _check(
        "report generated_at_utc RFC3339",
        isinstance(generated_at, str) and _parse_iso8601(generated_at),
        str(generated_at),
    )

    commitment = report.get("dataset_commitment")
    _check("dataset_commitment object", isinstance(commitment, dict))
    if not isinstance(commitment, dict):
        commitment = {}

    _check(
        "dataset commitment root hash format",
        _is_sha256_marker(commitment.get("root_hash")),
    )
    _check(
        "dataset commitment raw data not included",
        commitment.get("raw_data_included") is False,
    )

    snapshots = report.get("metric_snapshots")
    _check("metric_snapshots list", isinstance(snapshots, list) and len(snapshots) > 0)
    snapshot_errors: list[str] = []
    if isinstance(snapshots, list):
        for idx, item in enumerate(snapshots):
            if not isinstance(item, dict):
                snapshot_errors.append(f"idx-{idx}: not object")
                continue
            ok, detail = _validate_metric(item)
            if not ok:
                snapshot_errors.append(f"idx-{idx}: {detail}")

    _check(
        "metric snapshots aggregate-only",
        len(snapshot_errors) == 0,
        "; ".join(snapshot_errors) if snapshot_errors else "ok",
    )

    determinism = report.get("determinism_checks")
    _check("determinism_checks object", isinstance(determinism, dict))
    if not isinstance(determinism, dict):
        determinism = {}

    det_ok, det_detail = _validate_determinism(determinism)
    _check("determinism checks", det_ok, det_detail)

    proof_chain = report.get("proof_chain")
    _check("proof_chain list", isinstance(proof_chain, list))
    if not isinstance(proof_chain, list):
        proof_chain = []

    chain_ok, chain_detail = _validate_proof_chain(proof_chain)
    _check("proof_chain continuity", chain_ok, chain_detail)

    outputs = report.get("verifier_outputs")
    _check("verifier_outputs object", isinstance(outputs, dict))
    if not isinstance(outputs, dict):
        outputs = {}

    _check("verifier output integrity_valid", outputs.get("integrity_valid") is True)
    _check("verifier output metric_provenance_valid", outputs.get("metric_provenance_valid") is True)
    _check("verifier output deterministic", outputs.get("deterministic") is True)
    _check("verifier output private_raw_data_required=false", outputs.get("private_raw_data_required") is False)

    evidence_refs = report.get("evidence_refs")
    _check("evidence_refs list", isinstance(evidence_refs, list) and len(evidence_refs) > 0)
    missing_refs: list[str] = []
    if isinstance(evidence_refs, list):
        for ref in evidence_refs:
            if not isinstance(ref, str) or not ref.strip():
                missing_refs.append(str(ref))
                continue
            target = ROOT / ref
            if not target.is_file():
                missing_refs.append(ref)
    _check("evidence refs resolve", len(missing_refs) == 0, str(missing_refs) if missing_refs else "ok")

    events = report.get("events")
    _check("events list", isinstance(events, list) and len(events) > 0)
    observed_codes = {
        str(item.get("code"))
        for item in (events if isinstance(events, list) else [])
        if isinstance(item, dict)
    }
    missing_events = sorted(REQUIRED_EVENT_CODES - observed_codes)
    _check(
        "required report events present",
        len(missing_events) == 0,
        "missing: " + ", ".join(missing_events) if missing_events else "ok",
    )

    sig_ok, sig_detail = verify_signature(report)
    _check("signature verification", sig_ok, sig_detail)

    total = len(CHECKS)
    passed = sum(1 for entry in CHECKS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-2zip",
        "title": "ATC verifier APIs and proof artifacts",
        "section": "10.19",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": CHECKS,
        "events": sorted(observed_codes),
    }


def _fixture(
    base_dir: Path,
    *,
    tamper_signature: bool = False,
    determinism_mismatch: bool = False,
    raw_exposure: bool = False,
    broken_chain: bool = False,
    missing_endpoint: bool = False,
) -> tuple[Path, Path, Path]:
    base_dir.mkdir(parents=True, exist_ok=True)

    spec_path = base_dir / "atc_verifier_contract.md"
    conformance_path = base_dir / "atc_verifier_apis.rs"
    report_path = base_dir / "atc_verifier_report.json"

    endpoint_ids = sorted(REQUIRED_ENDPOINT_IDS)
    if missing_endpoint:
        endpoint_ids = endpoint_ids[:-1]

    spec_path.write_text(
        "\n".join(["# fixture", *endpoint_ids, *sorted(REQUIRED_EVENT_CODES)]),
        encoding="utf-8",
    )
    conformance_path.write_text(
        "\n".join(sorted(CONFORMANCE_TOKENS)),
        encoding="utf-8",
    )

    digest_a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    digest_b = (
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        if determinism_mismatch
        else digest_a
    )

    metric_raw = raw_exposure

    chain_parent = (
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        if broken_chain
        else "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )

    report = {
        "bead_id": "bd-2zip",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "verifier_version": "1.0.0",
        "public_key_id": "atc-verifier-v1",
        "signature_algorithm": "sha256-canonical-v1",
        "computation_id": "fixture-comp",
        "dataset_commitment": {
            "root_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "participant_count": 3,
            "raw_data_included": False,
        },
        "metric_snapshots": [
            {
                "metric_id": "m1",
                "value": 1.0,
                "unit": "score",
                "confidence": 1.0,
                "data_visibility": "raw" if metric_raw else "aggregate_only",
                "source_commitment": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "raw_participant_data_included": metric_raw,
            }
        ],
        "determinism_checks": {
            "runs": [
                {"run_id": "run-1", "result_digest": digest_a, "duration_ms": 1},
                {"run_id": "run-2", "result_digest": digest_b, "duration_ms": 1},
            ],
            "all_equal": not determinism_mismatch,
            "max_digest_distance": 0,
        },
        "proof_chain": [
            {
                "step": 0,
                "artifact_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "parent_hash": None,
                "signature": "sig-root",
            },
            {
                "step": 1,
                "artifact_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "parent_hash": chain_parent,
                "signature": "sig-leaf",
            },
        ],
        "verifier_outputs": {
            "integrity_valid": True,
            "metric_provenance_valid": True,
            "deterministic": not determinism_mismatch,
            "private_raw_data_required": False,
        },
        "evidence_refs": [str(spec_path), str(conformance_path)],
        "events": [{"code": code, "detail": "fixture"} for code in sorted(REQUIRED_EVENT_CODES)],
    }

    report["signing"] = {
        "canonical_payload_sha256": _payload_hash(report),
        "signature": _expected_signature(report),
    }

    if tamper_signature:
        report["signing"]["signature"] = "tampered"

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return spec_path, report_path, conformance_path


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-2zip-selftest-") as tmp:
        base = Path(tmp)

        spec_ok, report_ok, conf_ok = _fixture(base / "ok")
        ok = run_checks(spec_ok, report_ok, conf_ok)

        spec_sig, report_sig, conf_sig = _fixture(base / "sig", tamper_signature=True)
        bad_sig = run_checks(spec_sig, report_sig, conf_sig)

        spec_det, report_det, conf_det = _fixture(base / "det", determinism_mismatch=True)
        bad_det = run_checks(spec_det, report_det, conf_det)

        spec_raw, report_raw, conf_raw = _fixture(base / "raw", raw_exposure=True)
        bad_raw = run_checks(spec_raw, report_raw, conf_raw)

        spec_chain, report_chain, conf_chain = _fixture(base / "chain", broken_chain=True)
        bad_chain = run_checks(spec_chain, report_chain, conf_chain)

        spec_ep, report_ep, conf_ep = _fixture(base / "endpoint", missing_endpoint=True)
        bad_ep = run_checks(spec_ep, report_ep, conf_ep)

    return (
        ok["verdict"] == "PASS"
        and bad_sig["verdict"] == "FAIL"
        and bad_det["verdict"] == "FAIL"
        and bad_raw["verdict"] == "FAIL"
        and bad_chain["verdict"] == "FAIL"
        and bad_ep["verdict"] == "FAIL"
    )


def main() -> int:
    logger = configure_test_logging("check_atc_verifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=SPEC_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--conformance", type=Path, default=CONFORMANCE_PATH)
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {
            "bead_id": "bd-2zip",
            "check": "self_test",
            "verdict": "PASS" if ok else "FAIL",
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"self_test verdict: {payload['verdict']}")
        return 0 if ok else 1

    report = run_checks(args.spec, args.report, args.conformance)
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
