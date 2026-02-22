"""Unit tests for scripts/check_benchmark_specs_package.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_benchmark_specs_package",
    ROOT / "scripts" / "check_benchmark_specs_package.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _contract_text() -> str:
    return "\n".join(
        [
            "# test contract",
            "INV-BSP-TRACK-COVERAGE",
            "INV-BSP-TRACK-WEIGHTS",
            "INV-BSP-HARNESS-REPRO",
            "INV-BSP-DATASET-INTEGRITY",
            "INV-BSP-SCORING-FORMULA",
            "INV-BSP-QUALITY-GATES",
            "INV-BSP-DETERMINISM",
            "INV-BSP-ADVERSARIAL",
            *sorted(mod.REQUIRED_EVENT_CODES),
        ]
    )


class TestBenchmarkSpecsPackage(TestCase):
    def test_run_checks_passes_repo_artifacts(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3h1g")
        self.assertEqual(result["verdict"], "PASS")

    def test_weight_sum_violation_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3h1g-test-") as tmp:
            root = Path(tmp)
            contract_path = root / "contract.md"
            package_path = root / "package.json"

            contract_path.write_text(_contract_text(), encoding="utf-8")
            payload = mod.sample_package()
            payload["benchmark_tracks"][0]["weight"] = 0.40
            package_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(contract_path=contract_path, package_path=package_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(c["check"] == "track weights sum to 1.0" and not c["pass"] for c in result["checks"]))

    def test_missing_dataset_track_coverage_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3h1g-test-") as tmp:
            root = Path(tmp)
            contract_path = root / "contract.md"
            package_path = root / "package.json"

            contract_path.write_text(_contract_text(), encoding="utf-8")
            payload = mod.sample_package()
            payload["datasets"] = [d for d in payload["datasets"] if d["track_id"] != "adversarial_resilience"]
            package_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(contract_path=contract_path, package_path=package_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(c["check"] == "dataset track coverage exact" and not c["pass"] for c in result["checks"]))

    def test_low_track_score_fails_quality_gate(self) -> None:
        with TemporaryDirectory(prefix="bd-3h1g-test-") as tmp:
            root = Path(tmp)
            contract_path = root / "contract.md"
            package_path = root / "package.json"

            contract_path.write_text(_contract_text(), encoding="utf-8")
            payload = mod.sample_package()
            payload["sample_scores"]["security_trust"] = 0.70
            payload["sample_overall_score"] = 0.8723
            package_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(contract_path=contract_path, package_path=package_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(c["check"] == "sample score gates pass" and not c["pass"] for c in result["checks"]))

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    main()
