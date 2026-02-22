"""Unit tests for scripts/check_independent_replications_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_independent_replications_gate",
    ROOT / "scripts" / "check_independent_replications_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _spec_text() -> str:
    return "\n".join(
        [
            "# test contract",
            "INV-IRG-MIN-REPLICATIONS",
            "INV-IRG-REQUIRED-CLAIMS",
            "INV-IRG-INDEPENDENCE",
            "INV-IRG-CONFLICT-DISCLOSURE",
            "INV-IRG-EVIDENCE-LINKS",
            "INV-IRG-DETERMINISM",
            "INV-IRG-ADVERSARIAL",
            *sorted(mod.REQUIRED_EVENT_CODES),
        ]
    )


class TestIndependentReplicationsGate(TestCase):
    def test_run_checks_passes_repo_artifacts(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-whxp")
        self.assertEqual(result["verdict"], "PASS")

    def test_insufficient_independent_replications_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            payload = mod.sample_report()
            payload["replications"][1]["independent"] = False
            payload["summary"]["independent_replication_count"] = 1
            payload["summary"]["independent_replications_passing"] = 1
            payload["summary"]["verdict"] = "FAIL"
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == ">=2 independent passing replications"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_duplicate_independent_org_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            payload = mod.sample_report()
            payload["replications"][1]["organization"] = payload["replications"][0]["organization"]
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "independent organizations unique"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_claim_failure_in_independent_replication_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            payload = mod.sample_report()
            payload["replications"][0]["claim_results"]["compromise_reduction_10x"]["pass"] = False
            payload["summary"]["independent_replications_passing"] = 1
            payload["summary"]["verdict"] = "FAIL"
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == ">=2 independent passing replications"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    main()
