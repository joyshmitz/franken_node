#!/usr/bin/env python3
"""Validate deterministic frankentui snapshot + interaction replay coverage (bd-1719)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any


import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
DEFAULT_INVENTORY = ROOT / "artifacts" / "10.16" / "frankentui_surface_inventory.csv"
DEFAULT_TEST_SOURCE = ROOT / "tests" / "tui" / "frankentui_snapshots.rs"
DEFAULT_SNAPSHOT_DIR = ROOT / "fixtures" / "tui" / "snapshots"
DEFAULT_REPORT = ROOT / "artifacts" / "10.16" / "frankentui_snapshot_report.json"

MANDATORY_PATTERNS = {"navigation", "confirmation", "cancellation", "scrolling"}
SNAPSHOT_STATUSES = {"pass", "fail", "new"}


def load_inventory(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"inventory not found: {path}")
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        surfaces = {row.get("surface_name", "").strip() for row in reader}
    surfaces.discard("")
    return sorted(surfaces)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"json file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _trace_id(inventory: list[str], report: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(inventory, sort_keys=True).encode("utf-8"))
    digest.update(json.dumps(report, sort_keys=True).encode("utf-8"))
    return digest.hexdigest()


def evaluate(
    inventory_surfaces: list[str],
    report: dict[str, Any],
    test_source_text: str,
    snapshot_dir: Path,
) -> tuple[bool, dict[str, Any]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    trace = _trace_id(inventory_surfaces, report)
    snapshots = report.get("snapshots", [])
    replays = report.get("interaction_replays", [])

    if not isinstance(snapshots, list):
        raise ValueError("report.snapshots must be a list")
    if not isinstance(replays, list):
        raise ValueError("report.interaction_replays must be a list")

    by_surface: dict[str, dict[str, Any]] = {}
    for entry in snapshots:
        surface = entry.get("surface_name")
        if isinstance(surface, str):
            by_surface[surface] = entry

    for surface in inventory_surfaces:
        present_in_tests = f'"{surface}"' in test_source_text
        checks.append(
            {
                "check": f"surface in test source: {surface}",
                "pass": present_in_tests,
            }
        )
        if not present_in_tests:
            errors.append(f"surface missing from test source: {surface}")

        baseline = snapshot_dir / f"{surface}.snap"
        baseline_exists = baseline.exists()
        checks.append(
            {
                "check": f"baseline snapshot exists: {surface}",
                "pass": baseline_exists,
            }
        )
        if not baseline_exists:
            errors.append(f"baseline snapshot missing: {baseline}")

        entry = by_surface.get(surface)
        if entry is None:
            errors.append(f"snapshot report missing surface entry: {surface}")
            checks.append(
                {
                    "check": f"snapshot report entry: {surface}",
                    "pass": False,
                }
            )
            continue

        status = entry.get("status")
        status_valid = status in SNAPSHOT_STATUSES
        checks.append(
            {
                "check": f"snapshot status valid: {surface}",
                "pass": status_valid,
                "status": status,
            }
        )
        if not status_valid:
            errors.append(f"invalid snapshot status `{status}` for {surface}")
            continue

        if status == "pass":
            events.append(
                {
                    "event_code": "TUI_SNAPSHOT_PASS",
                    "severity": "info",
                    "surface_name": surface,
                    "trace_correlation": trace,
                }
            )
        elif status == "fail":
            events.append(
                {
                    "event_code": "TUI_SNAPSHOT_FAIL",
                    "severity": "error",
                    "surface_name": surface,
                    "trace_correlation": trace,
                }
            )
            errors.append(f"snapshot failed for surface: {surface}")
        elif status == "new":
            events.append(
                {
                    "event_code": "TUI_SNAPSHOT_NEW",
                    "severity": "warning",
                    "surface_name": surface,
                    "trace_correlation": trace,
                }
            )
            warnings.append(f"new (unapproved) snapshot for surface: {surface}")
            errors.append(f"gate rejects unapproved new snapshot: {surface}")

    patterns_seen: set[str] = set()
    for replay in replays:
        replay_name = replay.get("replay_name", "<unknown>")
        status = replay.get("status")
        final_match = bool(replay.get("final_snapshot_match", False))
        pattern = replay.get("pattern")
        if isinstance(pattern, str) and pattern:
            patterns_seen.add(pattern)

        replay_ok = status == "pass" and final_match
        checks.append(
            {
                "check": f"interaction replay pass: {replay_name}",
                "pass": replay_ok,
                "status": status,
                "final_snapshot_match": final_match,
            }
        )
        if replay_ok:
            events.append(
                {
                    "event_code": "TUI_INTERACTION_REPLAY_PASS",
                    "severity": "info",
                    "replay_name": replay_name,
                    "trace_correlation": trace,
                }
            )
        else:
            events.append(
                {
                    "event_code": "TUI_INTERACTION_REPLAY_FAIL",
                    "severity": "error",
                    "replay_name": replay_name,
                    "trace_correlation": trace,
                }
            )
            errors.append(f"interaction replay failed: {replay_name}")

    missing_patterns = sorted(MANDATORY_PATTERNS - patterns_seen)
    checks.append(
        {
            "check": "mandatory interaction pattern coverage",
            "pass": len(missing_patterns) == 0,
            "missing_patterns": missing_patterns,
        }
    )
    if missing_patterns:
        errors.append(
            f"missing mandatory interaction patterns: {', '.join(missing_patterns)}"
        )

    declared_summary = report.get("summary", {})
    if isinstance(declared_summary, dict):
        computed_snapshot_total = len(snapshots)
        declared_snapshot_total = declared_summary.get("snapshot_total")
        checks.append(
            {
                "check": "summary snapshot_total matches",
                "pass": declared_snapshot_total == computed_snapshot_total,
                "declared": declared_snapshot_total,
                "computed": computed_snapshot_total,
            }
        )
        if declared_snapshot_total != computed_snapshot_total:
            warnings.append(
                "report.summary.snapshot_total does not match snapshots array length"
            )

    ok = len(errors) == 0
    payload = {
        "ok": ok,
        "trace_correlation": trace,
        "inventory_count": len(inventory_surfaces),
        "snapshot_count": len(snapshots),
        "interaction_replay_count": len(replays),
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "events": events,
        "patterns_seen": sorted(patterns_seen),
    }
    return ok, payload


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="fn-snapshot-selftest-") as tmp:
        tmp_root = Path(tmp)
        inventory = tmp_root / "inventory.csv"
        snapshots = tmp_root / "snapshots"
        test_source = tmp_root / "frankentui_snapshots.rs"
        report_path = tmp_root / "report.json"

        snapshots.mkdir(parents=True)
        inventory.write_text(
            "module_path,surface_name,migration_status,frankentui_component,boundary_type,notes\n"
            "src/main.rs,main_panel_render,complete,Panel,renderer,x\n"
            "src/main.rs,main_table_render,complete,Table,renderer,x\n",
            encoding="utf-8",
        )
        test_source.write_text(
            '"main_panel_render"\n"main_table_render"\n', encoding="utf-8"
        )
        (snapshots / "main_panel_render.snap").write_text("panel\n", encoding="utf-8")
        (snapshots / "main_table_render.snap").write_text("table\n", encoding="utf-8")

        passing_report = {
            "snapshots": [
                {"surface_name": "main_panel_render", "status": "pass"},
                {"surface_name": "main_table_render", "status": "pass"},
            ],
            "interaction_replays": [
                {
                    "replay_name": "r1",
                    "pattern": "navigation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "r2",
                    "pattern": "confirmation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "r3",
                    "pattern": "cancellation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "r4",
                    "pattern": "scrolling",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
            ],
            "summary": {"snapshot_total": 2},
        }
        report_path.write_text(
            json.dumps(passing_report, indent=2) + "\n", encoding="utf-8"
        )

        inv = load_inventory(inventory)
        rep = load_json(report_path)
        src = test_source.read_text(encoding="utf-8")
        ok, _payload = evaluate(inv, rep, src, snapshots)
        assert ok, "self_test pass case failed"

        failing_report = dict(passing_report)
        failing_report["snapshots"] = [
            {"surface_name": "main_panel_render", "status": "new"},
            {"surface_name": "main_table_render", "status": "pass"},
        ]
        failing_report["interaction_replays"] = [
            {
                "replay_name": "r1",
                "pattern": "navigation",
                "status": "pass",
                "final_snapshot_match": True,
            }
        ]
        report_path.write_text(
            json.dumps(failing_report, indent=2) + "\n", encoding="utf-8"
        )
        rep_fail = load_json(report_path)
        ok_fail, payload_fail = evaluate(inv, rep_fail, src, snapshots)
        assert not ok_fail, "self_test fail case unexpectedly passed"
        assert payload_fail["errors"], "self_test fail case should produce errors"


def main() -> int:
    logger = configure_test_logging("check_frankentui_snapshots")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--test-source", type=Path, default=DEFAULT_TEST_SOURCE)
    parser.add_argument("--snapshot-dir", type=Path, default=DEFAULT_SNAPSHOT_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--json", action="store_true", help="Emit JSON result payload.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test.")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        out = {"ok": True, "self_test": "passed"}
        if args.json:
            print(json.dumps(out, indent=2, sort_keys=True))
        else:
            print("self_test: passed")
        return 0

    inventory_surfaces = load_inventory(args.inventory)
    report = load_json(args.report)
    test_source_text = args.test_source.read_text(encoding="utf-8")
    ok, payload = evaluate(inventory_surfaces, report, test_source_text, args.snapshot_dir)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        status = "PASS" if ok else "FAIL"
        print(
            f"{status}: {len(payload['errors'])} errors, "
            f"{len(payload['warnings'])} warnings, "
            f"{len(payload['events'])} events"
        )
        for error in payload["errors"]:
            print(f"error: {error}")
        for warning in payload["warnings"]:
            print(f"warning: {warning}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
