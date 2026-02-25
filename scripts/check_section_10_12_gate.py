#!/usr/bin/env python3
"""Section 10.12 verification gate: Frontier Programs Execution Track.

Aggregates evidence from all Section 10.12 frontier beads and emits a
deterministic machine-readable gate verdict.

Usage:
    python3 scripts/check_section_10_12_gate.py
    python3 scripts/check_section_10_12_gate.py --json
    python3 scripts/check_section_10_12_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


BEAD = "bd-1d6x"
SECTION = "10.12"

SECTION_BEADS: list[tuple[str, str]] = [
    ("bd-3hm", "Migration singularity artifact contract and verifier format"),
    ("bd-3j4", "End-to-end migration singularity pipeline for pilot cohorts"),
    ("bd-5si", "Trust fabric convergence protocol and degraded-mode semantics"),
    ("bd-3c2", "Verifier-economy SDK with independent validation workflows"),
    ("bd-y0v", "Operator intelligence recommendation engine with rollback proofs"),
    ("bd-2aj", "Ecosystem network-effect APIs"),
    ("bd-n1w", "Frontier demo gates with external reproducibility requirements"),
]

FRONTIER_PROGRAMS = [
    "migration_singularity",
    "trust_fabric",
    "verifier_economy",
    "operator_intelligence",
    "ecosystem_network_effects",
]

DEGRADED_MODE_SIGNAL_RULES: dict[str, dict[str, Any]] = {
    "migration_singularity": {
        "beads": ["bd-3hm", "bd-3j4"],
        "tokens": [
            "inv-ma-rollback-present",
            "inv-pipe-rollback-any-stage",
            "err_pipe_rollback_failed",
        ],
    },
    "trust_fabric": {
        "beads": ["bd-5si"],
        "tokens": [
            "inv-tfc-degraded-deny",
            "err_tfc_degraded_reject",
            "degraded mode",
        ],
    },
    "verifier_economy": {
        "beads": ["bd-3c2"],
        "tokens": [
            "inv-ver-offline-capable",
            "offline",
        ],
    },
    "operator_intelligence": {
        "beads": ["bd-y0v"],
        "tokens": [
            "err_oir_degraded",
            "degraded mode",
            "degraded_confidence_penalty",
        ],
    },
    "ecosystem_network_effects": {
        "beads": ["bd-2aj", "bd-n1w"],
        "tokens": [
            "replay capsule support enables external reproducibility",
            "deterministic_reputation_score",
        ],
    },
}

KEY_ARTIFACTS = [
    ("frontier_manifest", "artifacts/10.12/frontier_demo_manifest.json"),
    ("migration_schema", "spec/migration_artifact_schema.json"),
    ("evidence_bundle_schema", "spec/evidence_bundle_schema.json"),
    ("trust_fabric_policy", "docs/policy/trust_fabric_convergence.md"),
    ("operator_intelligence_policy", "docs/policy/operator_intelligence.md"),
    ("migration_checker", "scripts/check_migration_artifacts.py"),
    ("migration_pipeline_checker", "scripts/check_migration_pipeline.py"),
    ("trust_fabric_checker", "scripts/check_trust_fabric.py"),
    ("verifier_sdk_checker", "scripts/check_verifier_sdk.py"),
    ("operator_intelligence_checker", "scripts/check_operator_intelligence.py"),
    ("ecosystem_checker", "scripts/check_ecosystem_apis.py"),
    ("frontier_demo_checker", "scripts/check_frontier_demo_gates.py"),
]

REQUIRED_GATE_EVENTS = {
    "GATE_10_12_EVALUATION_STARTED",
    "GATE_10_12_BEAD_CHECKED",
    "GATE_10_12_REPRODUCIBILITY_AUDIT",
    "GATE_10_12_VERDICT_EMITTED",
}

RESULTS: list[dict[str, Any]] = []
EVENTS: list[dict[str, str]] = []


def _event(name: str, detail: str) -> None:
    EVENTS.append({"event": name, "detail": detail})


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _find_evidence(bead_id: str) -> Path | None:
    base = ROOT / "artifacts" / "section_10_12" / bead_id
    for name in ("verification_evidence.json", "check_report.json"):
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def _evidence_pass(data: dict[str, Any]) -> bool:
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    if data.get("all_passed") is True:
        return True

    raw_status = str(data.get("status", "")).lower()
    if raw_status in {"pass", "completed"}:
        return True
    if raw_status.startswith("completed_with_"):
        return True

    vr = data.get("verification_results", {})
    if isinstance(vr, dict) and vr:
        py_checker = vr.get("python_checker", {})
        py_tests = vr.get("python_unit_tests", {})
        if isinstance(py_checker, dict) and isinstance(py_tests, dict):
            if py_checker.get("verdict") == "PASS" and py_tests.get("verdict") == "PASS":
                return True

    return False


def _bead_corpus(bead_id: str) -> str:
    parts: list[str] = []
    evidence = _find_evidence(bead_id)
    if evidence is not None:
        parts.append(_read_text(evidence))

    summary = ROOT / "artifacts" / "section_10_12" / bead_id / "verification_summary.md"
    parts.append(_read_text(summary))

    for spec_path in sorted((ROOT / "docs" / "specs" / "section_10_12").glob(f"{bead_id}*.md")):
        parts.append(_read_text(spec_path))

    return "\n".join(parts).lower()


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = _find_evidence(bead_id)
    if evidence_path is None:
        fallback = ROOT / "artifacts" / "section_10_12" / bead_id / "verification_evidence.json"
        _event("GATE_10_12_BEAD_CHECKED", f"{bead_id}:missing_evidence")
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(fallback)}")

    data = _load_json(evidence_path)
    if data is None:
        _event("GATE_10_12_BEAD_CHECKED", f"{bead_id}:parse_error")
        return _check(f"evidence_{bead_id}", False, f"parse error: {_safe_relative(evidence_path)}")

    passed = _evidence_pass(data)
    _event("GATE_10_12_BEAD_CHECKED", f"{bead_id}:{'PASS' if passed else 'FAIL'}")
    return _check(
        f"evidence_{bead_id}",
        passed,
        f"PASS: {title[:64]}" if passed else f"FAIL: {title[:64]}",
    )


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / "section_10_12" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


def check_all_evidence_present() -> dict[str, Any]:
    count = sum(1 for bead_id, _ in SECTION_BEADS if _find_evidence(bead_id) is not None)
    passed = count == len(SECTION_BEADS)
    return _check("all_evidence_present", passed, f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    failed: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = _find_evidence(bead_id)
        if evidence_path is None:
            failed.append(bead_id)
            continue
        data = _load_json(evidence_path)
        if data is not None and _evidence_pass(data):
            pass_count += 1
        else:
            failed.append(bead_id)

    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(failed)}"
    return _check("all_verdicts_pass", passed, detail)


def check_key_artifacts() -> list[dict[str, Any]]:
    checks = []
    for name, rel_path in KEY_ARTIFACTS:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"artifact_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_gate_deliverables() -> list[dict[str, Any]]:
    checks = []
    gate_files = [
        ("gate_script", "scripts/check_section_10_12_gate.py"),
        ("gate_tests", "tests/test_check_section_10_12_gate.py"),
        ("gate_spec", "docs/specs/section_10_12/bd-1d6x_contract.md"),
        ("gate_evidence", "artifacts/section_10_12/bd-1d6x/verification_evidence.json"),
        ("gate_summary", "artifacts/section_10_12/bd-1d6x/verification_summary.md"),
    ]
    for name, rel_path in gate_files:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            name,
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_reproducibility_audit() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    manifest_path = ROOT / "artifacts" / "10.12" / "frontier_demo_manifest.json"
    manifest_exists = manifest_path.is_file()
    checks.append(_check("repro_manifest_exists", manifest_exists, _safe_relative(manifest_path)))

    manifest = _load_json(manifest_path) if manifest_exists else None
    checks.append(_check(
        "repro_manifest_parseable",
        manifest is not None,
        "JSON parsed" if manifest is not None else "manifest parse error",
    ))

    if manifest is None:
        checks.append(_check("repro_required_programs", False, "manifest unavailable"))
        checks.append(_check("repro_program_gate_status_pass", False, "manifest unavailable"))
        checks.append(_check("repro_program_fingerprints", False, "manifest unavailable"))
        checks.append(_check("repro_manifest_metadata", False, "manifest unavailable"))
        checks.append(_check("repro_manifest_timing_coverage", False, "manifest unavailable"))
    else:
        schema_ok = manifest.get("schema_version") == "demo-v1.0"
        checks.append(_check(
            "repro_manifest_schema",
            schema_ok,
            f"schema_version={manifest.get('schema_version', '<missing>')}",
        ))

        programs = manifest.get("programs", [])
        names = {str(p.get("name", "")) for p in programs if isinstance(p, dict)}
        missing_programs = [name for name in FRONTIER_PROGRAMS if name not in names]
        checks.append(_check(
            "repro_required_programs",
            len(missing_programs) == 0,
            "all 5 programs present" if not missing_programs else f"missing: {', '.join(missing_programs)}",
        ))

        selected = [p for p in programs if isinstance(p, dict) and p.get("name") in FRONTIER_PROGRAMS]
        all_pass = len(selected) == len(FRONTIER_PROGRAMS) and all(
            str(p.get("gate_status", "")).lower() == "pass" for p in selected
        )
        checks.append(_check(
            "repro_program_gate_status_pass",
            all_pass,
            "all frontier program gates PASS" if all_pass else "one or more frontier programs not PASS",
        ))

        fingerprints_ok = len(selected) == len(FRONTIER_PROGRAMS) and all(
            bool(str(p.get("input_fingerprint", ""))) and bool(str(p.get("output_fingerprint", "")))
            for p in selected
        )
        checks.append(_check(
            "repro_program_fingerprints",
            fingerprints_ok,
            "input/output fingerprints present for all frontier programs"
            if fingerprints_ok
            else "missing program fingerprints",
        ))

        metadata_ok = all(
            key in manifest for key in ("manifest_fingerprint", "git_commit_hash", "environment", "timing")
        )
        checks.append(_check(
            "repro_manifest_metadata",
            metadata_ok,
            "manifest metadata complete" if metadata_ok else "manifest metadata missing fields",
        ))

        per_gate = {}
        timing = manifest.get("timing", {})
        if isinstance(timing, dict):
            candidate = timing.get("per_gate", {})
            if isinstance(candidate, dict):
                per_gate = candidate
        timing_ok = all(program in per_gate for program in FRONTIER_PROGRAMS)
        checks.append(_check(
            "repro_manifest_timing_coverage",
            timing_ok,
            "timing.per_gate covers all frontier programs"
            if timing_ok
            else "timing.per_gate missing frontier programs",
        ))

    n1w_path = _find_evidence("bd-n1w")
    n1w_evidence = _load_json(n1w_path) if n1w_path is not None else None
    n1w_invariant_ok = (
        n1w_evidence is not None
        and "INV-DEMO-REPRODUCIBLE" in n1w_evidence.get("invariants", [])
    )
    checks.append(_check(
        "repro_n1w_invariant",
        n1w_invariant_ok,
        "INV-DEMO-REPRODUCIBLE present in bd-n1w evidence"
        if n1w_invariant_ok
        else "bd-n1w reproducibility invariant missing",
    ))

    n1w_summary = _read_text(ROOT / "artifacts" / "section_10_12" / "bd-n1w" / "verification_summary.md").lower()
    summary_ok = "external reproducibility" in n1w_summary or "external re-execution" in n1w_summary
    checks.append(_check(
        "repro_n1w_summary_external",
        summary_ok,
        "bd-n1w summary documents external reproducibility"
        if summary_ok
        else "bd-n1w summary missing external reproducibility signal",
    ))

    audit_checks = [c for c in checks if c["check"].startswith("repro_")]
    audit_pass = all(c["pass"] for c in audit_checks)
    _event("GATE_10_12_REPRODUCIBILITY_AUDIT", "PASS" if audit_pass else "FAIL")

    return checks


def check_degraded_mode_contracts() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    passing = 0

    for capability, rule in DEGRADED_MODE_SIGNAL_RULES.items():
        corpus_parts = [_bead_corpus(bead_id) for bead_id in rule["beads"]]
        corpus = "\n".join(corpus_parts)
        missing = [token for token in rule["tokens"] if token.lower() not in corpus]
        ok = len(missing) == 0
        if ok:
            passing += 1
        checks.append(_check(
            f"degraded_contract_{capability}",
            ok,
            f"signals present: {len(rule['tokens']) - len(missing)}/{len(rule['tokens'])}"
            if ok
            else f"missing: {', '.join(missing)}",
        ))

    checks.append(_check(
        "degraded_contracts_all_capabilities",
        passing == len(DEGRADED_MODE_SIGNAL_RULES),
        f"{passing}/{len(DEGRADED_MODE_SIGNAL_RULES)} capabilities have explicit degraded/fallback signals",
    ))
    return checks


def check_structured_logging() -> dict[str, Any]:
    required = {
        "GATE_10_12_EVALUATION_STARTED",
        "GATE_10_12_BEAD_CHECKED",
        "GATE_10_12_REPRODUCIBILITY_AUDIT",
    }
    present = {entry["event"] for entry in EVENTS}
    missing = sorted(required - present)
    return _check(
        "structured_logging_phase_events",
        len(missing) == 0,
        "all phase events emitted" if not missing else f"missing: {', '.join(missing)}",
    )


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()
    EVENTS.clear()

    _event("GATE_10_12_EVALUATION_STARTED", f"section={SECTION}")

    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    check_all_evidence_present()
    check_all_verdicts_pass()
    check_key_artifacts()
    check_reproducibility_audit()
    check_degraded_mode_contracts()
    check_structured_logging()
    check_gate_deliverables()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    verdict = "PASS" if overall else "FAIL"

    _event("GATE_10_12_VERDICT_EMITTED", f"{verdict} ({passed}/{total})")

    event_names = {entry["event"] for entry in EVENTS}
    missing_events = sorted(REQUIRED_GATE_EVENTS - event_names)

    return {
        "bead_id": BEAD,
        "title": "Section 10.12 verification gate: Frontier Programs Execution Track",
        "section": SECTION,
        "gate": True,
        "verdict": verdict,
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [bead_id for bead_id, _ in SECTION_BEADS],
        "frontier_programs": FRONTIER_PROGRAMS,
        "events": EVENTS,
        "events_complete": len(missing_events) == 0,
        "missing_events": missing_events,
        "checks": results,
    }


def self_test() -> bool:
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for result in results:
        if not isinstance(result, dict) or not all(k in result for k in ("check", "pass", "detail")):
            print(f"SELF-TEST FAIL: bad result payload: {result}", file=sys.stderr)
            return False
    if len(results) < 40:
        print(f"SELF-TEST FAIL: expected >= 40 checks, got {len(results)}", file=sys.stderr)
        return False

    full = run_all()
    if not full["events_complete"]:
        print(f"SELF-TEST FAIL: missing events {full['missing_events']}", file=sys.stderr)
        return False

    print(f"SELF-TEST OK: {len(full['checks'])} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_section_10_12_gate")
    parser = argparse.ArgumentParser(description=f"Section {SECTION} verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"\n  Section {SECTION} Gate: "
            f"{'PASS' if result['verdict'] == 'PASS' else 'FAIL'} "
            f"({result['passed']}/{result['total']})\n"
        )
        for entry in result["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
