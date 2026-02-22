#!/usr/bin/env python3
"""bd-3ohj foundation verification gate: validates all bootstrap beads are complete."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

BOOTSTRAP_ARTIFACTS = ROOT / "artifacts" / "section_bootstrap"

# The gate's own bead directory is excluded from discovery to avoid circular self-reference.
SELF_BEAD = "bd-3ohj"

# Minimum required field -- bead_id must always be present.
# verdict/section may be conveyed via alternative fields in bootstrap evidence.
REQUIRED_EVIDENCE_FIELDS = {"bead_id"}

# Fields that can convey a passing verdict (checked in order).
_VERDICT_FIELDS = ["verdict", "overall_status", "status"]

# Nested object keys whose "verdict" sub-field can convey a passing verdict.
_NESTED_VERDICT_KEYS = [
    "diagnostic_contract_gate",
    "init_contract_gate",
    "foundation_suite",
    "gate_report",
    "verifier_results",
]

KEY_ARTIFACTS = [
    "docs/architecture/tri_kernel_ownership_contract.md",
    "tests/conformance/ownership_boundary_checks.rs",
]

EVENT_CODES = {
    "start": "BOOT-GATE-001",
    "bead_scan": "BOOT-GATE-002",
    "artifact_check": "BOOT-GATE-003",
    "verdict": "BOOT-GATE-004",
    "remediation": "BOOT-GATE-005",
}


def _load_json(path: Path) -> tuple[bool, Any]:
    """Load a JSON file, returning (ok, data)."""
    if not path.is_file():
        return False, None
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, None


def _discover_beads(artifacts_dir: Path) -> list[str]:
    """Discover bead directories under the bootstrap artifacts dir."""
    if not artifacts_dir.is_dir():
        return []
    beads = []
    for child in sorted(artifacts_dir.iterdir()):
        if child.is_dir() and child.name.startswith("bd-") and child.name != SELF_BEAD:
            beads.append(child.name)
    return beads


def _check_evidence(evidence_path: Path) -> dict[str, Any]:
    """Validate a single bead's verification_evidence.json."""
    ok, data = _load_json(evidence_path)
    if not ok:
        return {
            "pass": False,
            "detail": f"missing or invalid JSON: {evidence_path}",
        }

    if not isinstance(data, dict):
        return {
            "pass": False,
            "detail": f"evidence is not a JSON object: {evidence_path}",
        }

    missing_fields = REQUIRED_EVIDENCE_FIELDS - set(data.keys())
    if missing_fields:
        return {
            "pass": False,
            "detail": f"missing required fields: {sorted(missing_fields)}",
        }

    # Check verdict -- accept various pass-equivalent statuses used in bootstrap beads.
    # Strategy: try top-level verdict fields, then nested object verdict fields.

    # 1. Top-level fields: verdict, overall_status, status.
    for field in _VERDICT_FIELDS:
        val = data.get(field, "")
        if isinstance(val, str) and "pass" in val.lower():
            return {"pass": True, "detail": f"{field}={val}"}

    # 2. Nested objects that carry their own verdict (e.g. diagnostic_contract_gate.verdict).
    for key in _NESTED_VERDICT_KEYS:
        nested = data.get(key)
        if isinstance(nested, dict):
            nested_verdict = nested.get("verdict", "")
            if isinstance(nested_verdict, str) and nested_verdict.upper() == "PASS":
                return {"pass": True, "detail": f"{key}.verdict=PASS"}

    # 3. acceptance_criteria list -- all items must have status "pass".
    criteria = data.get("acceptance_criteria")
    if isinstance(criteria, list) and len(criteria) > 0:
        all_pass = all(
            isinstance(c, dict) and isinstance(c.get("status"), str) and c["status"].lower() == "pass"
            for c in criteria
        )
        if all_pass:
            return {"pass": True, "detail": f"acceptance_criteria: {len(criteria)}/{len(criteria)} pass"}

    # No passing signal found.
    verdict = data.get("verdict", "<not set>")
    return {
        "pass": False,
        "detail": f"verdict={verdict!r} (not PASS)",
    }


def _check_key_artifacts(root: Path) -> list[dict[str, Any]]:
    """Check that key architectural artifacts exist."""
    results = []
    for rel_path in KEY_ARTIFACTS:
        full = root / rel_path
        results.append({
            "path": rel_path,
            "exists": full.is_file(),
        })
    return results


def run_checks(
    artifacts_dir: Path | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """Run the full foundation gate and return a report dict."""
    if artifacts_dir is None:
        artifacts_dir = BOOTSTRAP_ARTIFACTS
    if root is None:
        root = ROOT

    events: list[dict[str, Any]] = []
    events.append({
        "event_code": EVENT_CODES["start"],
        "detail": "Bootstrap foundation verification gate started",
    })

    # --- Discover beads ---
    beads = _discover_beads(artifacts_dir)

    # --- Check each bead ---
    bead_results: list[dict[str, Any]] = []
    all_beads_pass = True
    for bead_id in beads:
        evidence_path = artifacts_dir / bead_id / "verification_evidence.json"
        result = _check_evidence(evidence_path)
        bead_results.append({
            "bead_id": bead_id,
            "verdict": "PASS" if result["pass"] else "FAIL",
            "detail": result["detail"],
        })
        events.append({
            "event_code": EVENT_CODES["bead_scan"],
            "bead_id": bead_id,
            "pass": result["pass"],
            "detail": result["detail"],
        })
        if not result["pass"]:
            all_beads_pass = False

    beads_discovered = len(beads)
    beads_passed = sum(1 for r in bead_results if r["verdict"] == "PASS")
    beads_failed = beads_discovered - beads_passed

    # --- Check key artifacts ---
    key_checks = _check_key_artifacts(root)
    all_artifacts_present = all(c["exists"] for c in key_checks)
    events.append({
        "event_code": EVENT_CODES["artifact_check"],
        "all_present": all_artifacts_present,
        "detail": "; ".join(
            f"{c['path']}={'ok' if c['exists'] else 'MISSING'}" for c in key_checks
        ),
    })

    # --- Compute dimension verdicts ---
    dim_evidence = "PASS" if beads_discovered > 0 else "FAIL"
    dim_upstream = "PASS" if all_beads_pass else "FAIL"
    dim_matrix = "PASS" if beads_passed == beads_discovered and beads_discovered > 0 else "FAIL"
    dim_docs = "PASS" if all_artifacts_present else "FAIL"

    dimensions = {
        "evidence_completeness": dim_evidence,
        "upstream_verdicts": dim_upstream,
        "matrix_coverage": dim_matrix,
        "docs_validation": dim_docs,
    }

    gate_pass = all(v == "PASS" for v in dimensions.values())
    verdict = "PASS" if gate_pass else "FAIL"

    events.append({
        "event_code": EVENT_CODES["verdict"],
        "verdict": verdict,
        "detail": f"dimensions={dimensions}",
    })

    if not gate_pass:
        failing = [k for k, v in dimensions.items() if v != "PASS"]
        events.append({
            "event_code": EVENT_CODES["remediation"],
            "failing_dimensions": failing,
            "detail": "See docs/specs/bootstrap_verification_gate.md for remediation guidance.",
        })

    return {
        "bead": "bd-3ohj",
        "title": "Bootstrap Foundation Verification Gate",
        "section": "bootstrap",
        "gate_type": "bootstrap_foundation",
        "verdict": verdict,
        "summary": {
            "beads_discovered": beads_discovered,
            "beads_passed": beads_passed,
            "beads_failed": beads_failed,
            "key_artifacts_present": all_artifacts_present,
            "dimensions": dimensions,
        },
        "bead_results": bead_results,
        "key_artifact_checks": key_checks,
        "event_log": events,
    }


def self_test() -> None:
    """Built-in self-test using synthetic data."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        art_dir = tmp / "artifacts" / "section_bootstrap"

        # Create synthetic bead evidence files.
        for bead_id in ["bd-aaa", "bd-bbb", "bd-ccc"]:
            bead_dir = art_dir / bead_id
            bead_dir.mkdir(parents=True)
            evidence = {
                "bead_id": bead_id,
                "section": "bootstrap",
                "verdict": "PASS",
            }
            (bead_dir / "verification_evidence.json").write_text(
                json.dumps(evidence), encoding="utf-8"
            )

        # Create key artifacts.
        for rel in KEY_ARTIFACTS:
            p = tmp / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("stub", encoding="utf-8")

        report = run_checks(artifacts_dir=art_dir, root=tmp)
        assert report["verdict"] == "PASS", f"self_test expected PASS, got {report['verdict']}"
        assert report["summary"]["beads_discovered"] == 3
        assert report["summary"]["beads_passed"] == 3
        assert report["summary"]["key_artifacts_present"] is True
        assert all(
            d == "PASS" for d in report["summary"]["dimensions"].values()
        ), f"self_test dimensions: {report['summary']['dimensions']}"

        # Test failure case: one bead with FAIL verdict.
        fail_dir = art_dir / "bd-ddd"
        fail_dir.mkdir(parents=True)
        (fail_dir / "verification_evidence.json").write_text(
            json.dumps({"bead_id": "bd-ddd", "section": "bootstrap", "verdict": "FAIL"}),
            encoding="utf-8",
        )
        fail_report = run_checks(artifacts_dir=art_dir, root=tmp)
        assert fail_report["verdict"] == "FAIL", "self_test expected FAIL for bad bead"

        # Test failure case: missing key artifact.
        (tmp / KEY_ARTIFACTS[0]).unlink()
        missing_report = run_checks(artifacts_dir=art_dir, root=tmp)
        assert missing_report["summary"]["key_artifacts_present"] is False

    print("self_test passed: all assertions hold")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    report = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-3ohj foundation gate verdict: {report['verdict']}")
        dims = report["summary"]["dimensions"]
        for dim, status in dims.items():
            print(f"  {dim}: {status}")
        print(
            f"beads: {report['summary']['beads_passed']}/"
            f"{report['summary']['beads_discovered']} passed"
        )
        if report["bead_results"]:
            for br in report["bead_results"]:
                marker = "ok" if br["verdict"] == "PASS" else "FAIL"
                print(f"  [{marker}] {br['bead_id']}: {br['detail']}")

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
