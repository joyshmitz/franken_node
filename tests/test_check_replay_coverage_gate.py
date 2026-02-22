"""Unit tests for scripts/check_replay_coverage_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_replay_coverage_gate",
    ROOT / "scripts" / "check_replay_coverage_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _base_spec_text() -> str:
    return "\n".join(
        [
            "# test spec",
            "100%",
            *sorted(mod.REQUIRED_INCIDENT_TYPES),
            *sorted(mod.REQUIRED_EVENT_CODES),
        ]
    )


def _matrix_fixture(root: Path) -> tuple[Path, Path]:
    spec_path = root / "spec.md"
    matrix_path = root / "matrix.json"
    artifacts_dir = root / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    records = []
    required = sorted(mod.REQUIRED_INCIDENT_TYPES)
    for idx, incident in enumerate(required):
        artifact_rel = f"artifacts/{incident}.json"
        artifact_abs = root / artifact_rel
        artifact_abs.write_text(
            json.dumps(
                {
                    "incident_type": incident,
                    "initial_state_snapshot": f"snap-{incident}",
                    "input_sequence": ["seed", "execute", "trace"],
                    "expected_behavior_trace": ["a", "b", "c"],
                    "actual_behavior_trace": ["a", "b", "c"],
                    "divergence_point": "none",
                    "last_verified_utc": "2026-02-21T00:00:00Z",
                    "deterministic_runs": 10,
                    "deterministic_match": True,
                    "reproduction_command": f"python3 scripts/check_replay_coverage_gate.py --replay-incident {incident}",
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        records.append(
            {
                "incident_type": incident,
                "artifact_path": artifact_rel,
                "last_verified_utc": "2026-02-21T00:00:00Z",
                "deterministic_runs": 10,
                "deterministic_match": True,
                "initial_state_snapshot": f"snap-{incident}",
                "input_sequence": ["seed", "execute", "trace"],
                "expected_behavior_trace": ["a", "b", "c"],
                "actual_behavior_trace": ["a", "b", "c"],
                "divergence_point": "none",
                "reproduction_command": f"python3 scripts/check_replay_coverage_gate.py --replay-incident {incident}",
                "discovered_at_utc": f"2026-02-{10 + idx:02d}T00:00:00Z",
            }
        )

    matrix = {
        "bead_id": "bd-2l1k",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "trace_id": "test-trace",
        "minimum_required_coverage_ratio": 1.0,
        "new_incident_type_sla_days": 14,
        "required_incident_types": required,
        "replay_artifacts": records,
        "coverage_summary": {
            "required_count": len(required),
            "covered_count": len(required),
            "coverage_ratio": 1.0,
        },
    }

    spec_path.write_text(_base_spec_text(), encoding="utf-8")
    matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")
    return spec_path, matrix_path


class TestReplayCoverageGate(TestCase):
    def test_run_checks_passes_repo_artifacts(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2l1k")
        self.assertEqual(result["verdict"], "PASS")

    def test_missing_incident_type_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-2l1k-test-") as tmp:
            root = Path(tmp)
            spec_path, matrix_path = _matrix_fixture(root)
            data = json.loads(matrix_path.read_text(encoding="utf-8"))
            data["replay_artifacts"] = data["replay_artifacts"][:-1]
            data["coverage_summary"]["covered_count"] = len(data["replay_artifacts"])
            data["coverage_summary"]["coverage_ratio"] = round(
                len(data["replay_artifacts"]) / len(data["required_incident_types"]),
                4,
            )
            matrix_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, matrix_path=matrix_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(check["check"] == "100% required incident coverage" and not check["pass"] for check in result["checks"])
        )

    def test_deterministic_runs_below_ten_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-2l1k-test-") as tmp:
            root = Path(tmp)
            spec_path, matrix_path = _matrix_fixture(root)
            data = json.loads(matrix_path.read_text(encoding="utf-8"))
            data["replay_artifacts"][0]["deterministic_runs"] = 9
            matrix_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, matrix_path=matrix_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(check["check"] == "deterministic replay requirements" and not check["pass"] for check in result["checks"])
        )

    def test_missing_artifact_file_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-2l1k-test-") as tmp:
            root = Path(tmp)
            spec_path, matrix_path = _matrix_fixture(root)
            data = json.loads(matrix_path.read_text(encoding="utf-8"))
            data["replay_artifacts"][0]["artifact_path"] = "artifacts/missing.json"
            matrix_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, matrix_path=matrix_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(check["check"] == "artifact files exist" and not check["pass"] for check in result["checks"]))

    def test_missing_content_field_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-2l1k-test-") as tmp:
            root = Path(tmp)
            spec_path, matrix_path = _matrix_fixture(root)
            data = json.loads(matrix_path.read_text(encoding="utf-8"))
            data["replay_artifacts"][0]["expected_behavior_trace"] = []
            matrix_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, matrix_path=matrix_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(check["check"] == "replay artifact content completeness" and not check["pass"] for check in result["checks"])
        )

    def test_replay_incident_success(self) -> None:
        payload = mod.replay_incident("rce")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["trace_match"])

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    main()
