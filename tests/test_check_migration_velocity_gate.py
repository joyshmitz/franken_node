"""Unit tests for scripts/check_migration_velocity_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_migration_velocity_gate",
    ROOT / "scripts" / "check_migration_velocity_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _base_spec_text() -> str:
    return "\n".join(
        [
            "# test spec",
            ">= 3.0x",
            *sorted(mod.REQUIRED_ARCHETYPES),
            *sorted(mod.REQUIRED_EVENT_CODES),
        ]
    )


def _make_project(archetype: str, idx: int, *, ci_sample: bool = False) -> dict:
    return {
        "project_id": f"p-{idx}",
        "archetype": archetype,
        "start_time_utc": "2026-02-20T00:00:00Z",
        "end_time_utc": "2026-02-20T01:00:00Z",
        "first_passing_test_time_utc": "2026-02-20T01:05:00Z",
        "manual_migration_minutes": 300 + idx,
        "tooled_migration_minutes": 90 + (idx % 2),
        "manual_intervention_points": ["manual tweak"],
        "blockers_encountered": [],
        "ci_release_sample": ci_sample,
    }


def _make_report(*, drop_archetype: str | None = None, ratio_fail: bool = False, ci_samples: int = 3) -> dict:
    archetypes = [a for a in sorted(mod.REQUIRED_ARCHETYPES) if a != drop_archetype]
    projects = []
    for idx, archetype in enumerate(archetypes):
        projects.append(_make_project(archetype, idx, ci_sample=idx < ci_samples))

    total_manual = sum(p["manual_migration_minutes"] for p in projects)
    total_tooled = sum(p["tooled_migration_minutes"] for p in projects)
    ratio = total_manual / total_tooled if total_tooled else 0.0

    if ratio_fail:
        # Inflate tooled effort to force <3x ratio.
        for p in projects:
            p["tooled_migration_minutes"] = int(p["tooled_migration_minutes"] * 2)
        total_tooled = sum(p["tooled_migration_minutes"] for p in projects)
        ratio = total_manual / total_tooled if total_tooled else 0.0

    return {
        "bead_id": "bd-3agp",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "measurement_unit": "minutes",
        "trace_id": "test-trace",
        "required_velocity_ratio": 3.0,
        "overall_velocity_ratio": round(ratio, 4),
        "total_manual_minutes": total_manual,
        "total_tooled_minutes": total_tooled,
        "cohort_size": len(projects),
        "projects": projects,
    }


class TestMigrationVelocityGate(TestCase):
    def test_run_checks_passes_repo_artifacts(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3agp")
        self.assertEqual(result["verdict"], "PASS")

    def test_missing_required_archetype_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3agp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(
                json.dumps(_make_report(drop_archetype="monorepo"), indent=2),
                encoding="utf-8",
            )

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("required archetypes covered" == c["check"] and not c["pass"] for c in result["checks"]))

    def test_velocity_ratio_below_threshold_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3agp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(
                json.dumps(_make_report(ratio_fail=True), indent=2),
                encoding="utf-8",
            )

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("velocity threshold >= 3x" == c["check"] and not c["pass"] for c in result["checks"]))

    def test_ci_sample_count_below_three_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3agp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(
                json.dumps(_make_report(ci_samples=2), indent=2),
                encoding="utf-8",
            )

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("ci sample coverage >= 3" == c["check"] and not c["pass"] for c in result["checks"]))

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    main()
