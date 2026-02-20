from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def _load_checker_module():
    script_path = Path("scripts/check_frankentui_snapshots.py")
    spec = importlib.util.spec_from_file_location("check_frankentui_snapshots", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FrankentuiSnapshotCheckerTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load_checker_module()

    def _make_fixture_set(self):
        tmp = tempfile.TemporaryDirectory(prefix="check-frankentui-snapshots-")
        root = Path(tmp.name)
        inventory = root / "inventory.csv"
        test_source = root / "frankentui_snapshots.rs"
        snapshot_dir = root / "snapshots"
        report = root / "report.json"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        inventory.write_text(
            "module_path,surface_name,migration_status,frankentui_component,boundary_type,notes\n"
            "src/main.rs,main_panel_render,complete,Panel,renderer,x\n"
            "src/main.rs,main_table_render,complete,Table,renderer,x\n",
            encoding="utf-8",
        )
        test_source.write_text(
            '"main_panel_render"\n"main_table_render"\n',
            encoding="utf-8",
        )
        (snapshot_dir / "main_panel_render.snap").write_text("panel\n", encoding="utf-8")
        (snapshot_dir / "main_table_render.snap").write_text("table\n", encoding="utf-8")

        report_payload = {
            "snapshots": [
                {"surface_name": "main_panel_render", "status": "pass"},
                {"surface_name": "main_table_render", "status": "pass"},
            ],
            "interaction_replays": [
                {
                    "replay_name": "navigation_case",
                    "pattern": "navigation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "confirmation_case",
                    "pattern": "confirmation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "cancellation_case",
                    "pattern": "cancellation",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
                {
                    "replay_name": "scrolling_case",
                    "pattern": "scrolling",
                    "status": "pass",
                    "final_snapshot_match": True,
                },
            ],
            "summary": {"snapshot_total": 2},
        }
        report.write_text(json.dumps(report_payload, indent=2) + "\n", encoding="utf-8")
        return tmp, inventory, test_source, snapshot_dir, report, report_payload

    def test_load_inventory_returns_unique_surface_names(self):
        tmp, inventory, *_rest = self._make_fixture_set()
        try:
            surfaces = self.mod.load_inventory(inventory)
            self.assertEqual(surfaces, ["main_panel_render", "main_table_render"])
        finally:
            tmp.cleanup()

    def test_evaluate_passes_for_valid_report(self):
        tmp, inventory, test_source, snapshot_dir, report, _payload = self._make_fixture_set()
        try:
            surfaces = self.mod.load_inventory(inventory)
            report_json = self.mod.load_json(report)
            source = test_source.read_text(encoding="utf-8")
            ok, payload = self.mod.evaluate(surfaces, report_json, source, snapshot_dir)
            self.assertTrue(ok)
            self.assertEqual(payload["errors"], [])
        finally:
            tmp.cleanup()

    def test_evaluate_fails_on_new_snapshot_status(self):
        tmp, inventory, test_source, snapshot_dir, report, payload = self._make_fixture_set()
        try:
            payload["snapshots"][0]["status"] = "new"
            report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            surfaces = self.mod.load_inventory(inventory)
            report_json = self.mod.load_json(report)
            source = test_source.read_text(encoding="utf-8")
            ok, result = self.mod.evaluate(surfaces, report_json, source, snapshot_dir)
            self.assertFalse(ok)
            self.assertTrue(any("unapproved new snapshot" in e for e in result["errors"]))
        finally:
            tmp.cleanup()

    def test_evaluate_fails_on_missing_pattern_coverage(self):
        tmp, inventory, test_source, snapshot_dir, report, payload = self._make_fixture_set()
        try:
            payload["interaction_replays"] = [
                {
                    "replay_name": "navigation_case",
                    "pattern": "navigation",
                    "status": "pass",
                    "final_snapshot_match": True,
                }
            ]
            report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            surfaces = self.mod.load_inventory(inventory)
            report_json = self.mod.load_json(report)
            source = test_source.read_text(encoding="utf-8")
            ok, result = self.mod.evaluate(surfaces, report_json, source, snapshot_dir)
            self.assertFalse(ok)
            self.assertTrue(
                any("missing mandatory interaction patterns" in e for e in result["errors"])
            )
        finally:
            tmp.cleanup()

    def test_evaluate_fails_if_baseline_snapshot_missing(self):
        tmp, inventory, test_source, snapshot_dir, report, _payload = self._make_fixture_set()
        try:
            (snapshot_dir / "main_table_render.snap").unlink()
            surfaces = self.mod.load_inventory(inventory)
            report_json = self.mod.load_json(report)
            source = test_source.read_text(encoding="utf-8")
            ok, result = self.mod.evaluate(surfaces, report_json, source, snapshot_dir)
            self.assertFalse(ok)
            self.assertTrue(any("baseline snapshot missing" in e for e in result["errors"]))
        finally:
            tmp.cleanup()

    def test_self_test_passes(self):
        self.mod.self_test()


if __name__ == "__main__":
    unittest.main()
