#!/usr/bin/env python3
"""
Verifier for bd-2d17 (DGIS migration admission/progression gate).

Checks:
- Required source/test/artifact files exist.
- Rust gate contract exports required entry points + event codes.
- Migration health report is machine-readable and structurally valid.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

REQUIRED_FILES = [
    "crates/franken-node/src/migration/mod.rs",
    "crates/franken-node/src/migration/dgis_migration_gate.rs",
    "tests/integration/dgis_migration_gate.rs",
    "crates/franken-node/tests/dgis_migration_gate.rs",
    "artifacts/10.20/dgis_migration_health_report.json",
]

REQUIRED_EVENT_CODES = [
    "DGIS-MIGRATE-001",
    "DGIS-MIGRATE-002",
    "DGIS-MIGRATE-003",
    "DGIS-MIGRATE-004",
    "DGIS-MIGRATE-005",
    "DGIS-MIGRATE-006",
]

REQUIRED_RUST_SYMBOLS = [
    "pub fn evaluate_admission",
    "pub fn evaluate_progression_phase",
    "pub fn suggest_replans",
    "pub fn build_migration_health_report",
]

ALLOWED_VERDICTS = {"allow", "block", "replan_required"}


def _check(condition: bool, check_id: str, detail: str = "") -> dict:
    return {
        "id": check_id,
        "status": "PASS" if condition else "FAIL",
        "detail": detail,
    }


def check_required_files(root: Path) -> list[dict]:
    checks = []
    for rel in REQUIRED_FILES:
        path = root / rel
        checks.append(_check(path.exists(), f"BD2D17-FILE-{rel}", str(path)))
    return checks


def check_rust_contract(root: Path) -> list[dict]:
    checks = []
    gate_path = root / "crates/franken-node/src/migration/dgis_migration_gate.rs"
    if not gate_path.exists():
        return [
            _check(
                False,
                "BD2D17-RUST-FILE",
                "missing crates/franken-node/src/migration/dgis_migration_gate.rs",
            )
        ]

    text = gate_path.read_text(encoding="utf-8")
    for symbol in REQUIRED_RUST_SYMBOLS:
        checks.append(
            _check(
                symbol in text,
                f"BD2D17-RUST-SYMBOL-{symbol}",
                "required API symbol present",
            )
        )
    for code in REQUIRED_EVENT_CODES:
        checks.append(
            _check(
                code in text,
                f"BD2D17-RUST-EVENT-{code}",
                "required event code present",
            )
        )
    return checks


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_report(root: Path) -> list[dict]:
    report_path = root / "artifacts/10.20/dgis_migration_health_report.json"
    checks: list[dict] = []

    if not report_path.exists():
        return [_check(False, "BD2D17-REPORT-EXISTS", str(report_path))]

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [_check(False, "BD2D17-REPORT-JSON", f"invalid json: {exc}")]

    checks.append(_check(isinstance(report, dict), "BD2D17-REPORT-OBJECT", "root object"))
    checks.append(
        _check(
            isinstance(report.get("plan_id"), str) and bool(report.get("plan_id")),
            "BD2D17-REPORT-PLAN-ID",
            "non-empty plan_id",
        )
    )

    evaluation = report.get("evaluation", {})
    checks.append(
        _check(
            isinstance(evaluation, dict),
            "BD2D17-REPORT-EVALUATION-OBJECT",
            "evaluation object present",
        )
    )
    checks.append(
        _check(
            isinstance(evaluation.get("phase"), str) and bool(evaluation.get("phase")),
            "BD2D17-REPORT-PHASE",
            "phase present",
        )
    )
    checks.append(
        _check(
            evaluation.get("verdict") in ALLOWED_VERDICTS,
            "BD2D17-REPORT-VERDICT",
            "valid verdict enum",
        )
    )

    baseline = evaluation.get("baseline", {})
    projected = evaluation.get("projected", {})
    delta = evaluation.get("delta", {})
    thresholds = evaluation.get("thresholds", {})

    for key in ("cascade_risk", "fragility_findings", "articulation_points"):
        checks.append(
            _check(
                key in baseline and _is_number(baseline.get(key)),
                f"BD2D17-REPORT-BASELINE-{key}",
                "baseline metrics populated",
            )
        )
        checks.append(
            _check(
                key in projected and _is_number(projected.get(key)),
                f"BD2D17-REPORT-PROJECTED-{key}",
                "projected metrics populated",
            )
        )

    checks.append(
        _check(
            _is_number(delta.get("cascade_risk_delta")),
            "BD2D17-REPORT-DELTA-cascade",
            "cascade risk delta present",
        )
    )
    checks.append(
        _check(
            _is_number(delta.get("new_fragility_findings")),
            "BD2D17-REPORT-DELTA-fragility",
            "fragility delta present",
        )
    )
    checks.append(
        _check(
            _is_number(delta.get("new_articulation_points")),
            "BD2D17-REPORT-DELTA-articulation",
            "articulation delta present",
        )
    )

    for key in (
        "max_cascade_risk_delta",
        "max_new_fragility_findings",
        "max_new_articulation_points",
    ):
        checks.append(
            _check(
                key in thresholds and _is_number(thresholds.get(key)),
                f"BD2D17-REPORT-THRESHOLD-{key}",
                "threshold present",
            )
        )

    events = evaluation.get("events", [])
    checks.append(
        _check(
            isinstance(events, list) and len(events) >= 2,
            "BD2D17-REPORT-EVENTS",
            "at least baseline + verdict events",
        )
    )
    codes = {event.get("code") for event in events if isinstance(event, dict)}
    checks.append(
        _check(
            "DGIS-MIGRATE-001" in codes
            and (
                "DGIS-MIGRATE-002" in codes
                or "DGIS-MIGRATE-003" in codes
                or "DGIS-MIGRATE-005" in codes
            ),
            "BD2D17-REPORT-EVENT-CODES",
            "baseline + gate decision code present",
        )
    )

    return checks


def run_checks(root: Path = ROOT) -> dict:
    checks = []
    checks.extend(check_required_files(root))
    checks.extend(check_rust_contract(root))
    checks.extend(check_report(root))

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "bead_id": "bd-2d17",
        "gate": "dgis_migration_gate_verification",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if not failing else "FAIL",
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
        "checks": checks,
    }


def self_test() -> dict:
    import tempfile

    checks = []

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        for rel in REQUIRED_FILES:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if rel.endswith(".json"):
                path.write_text(
                    json.dumps(
                        {
                            "plan_id": "plan-self-test",
                            "evaluation": {
                                "phase": "admission",
                                "verdict": "replan_required",
                                "baseline": {
                                    "cascade_risk": 0.2,
                                    "fragility_findings": 3,
                                    "articulation_points": 2,
                                },
                                "projected": {
                                    "cascade_risk": 0.41,
                                    "fragility_findings": 7,
                                    "articulation_points": 5,
                                },
                                "delta": {
                                    "cascade_risk_delta": 0.21,
                                    "new_fragility_findings": 4,
                                    "new_articulation_points": 3,
                                },
                                "thresholds": {
                                    "max_cascade_risk_delta": 0.12,
                                    "max_new_fragility_findings": 2,
                                    "max_new_articulation_points": 1,
                                },
                                "rejection_reasons": [{"code": "DGIS-MIGRATE-RISK-DELTA"}],
                                "replan_suggestions": [{"path_id": "path-safe"}],
                                "events": [
                                    {"code": "DGIS-MIGRATE-001"},
                                    {"code": "DGIS-MIGRATE-003"},
                                    {"code": "DGIS-MIGRATE-006"},
                                ],
                            },
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            elif rel.endswith("dgis_migration_gate.rs"):
                path.write_text(
                    "\n".join(REQUIRED_RUST_SYMBOLS + REQUIRED_EVENT_CODES),
                    encoding="utf-8",
                )
            else:
                path.write_text("ok", encoding="utf-8")

        result = run_checks(root)
        checks.append(_check(result["verdict"] == "PASS", "BD2D17-SELFTEST-PASS", "pass case"))

        broken = root / "artifacts/10.20/dgis_migration_health_report.json"
        broken.write_text("{}", encoding="utf-8")
        result2 = run_checks(root)
        checks.append(
            _check(
                result2["verdict"] == "FAIL",
                "BD2D17-SELFTEST-FAIL-DETECT",
                "detects malformed report",
            )
        )

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "gate": "dgis_migration_gate_self_test",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if not failing else "FAIL",
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
        "checks": checks,
    }


def main() -> int:
    logger = configure_test_logging("check_dgis_migration_gate")
    json_output = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    result = self_test() if run_self_test else run_checks()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Verifier: {result['gate']}")
        for check in result["checks"]:
            marker = "OK" if check["status"] == "PASS" else "FAIL"
            print(f"  [{marker}] {check['id']}")
        print(f"\nVerdict: {result['verdict']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
