"""Unit tests for scripts/check_fastapi_contract.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_fastapi_contract",
    ROOT / "scripts" / "check_fastapi_contract.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_contract_and_checklist_exist(self) -> None:
        self.assertTrue(mod.CONTRACT_PATH.is_file())
        self.assertTrue(mod.CHECKLIST_PATH.is_file())
        self.assertTrue(mod.ERROR_REGISTRY_PATH.is_file())

    def test_required_event_codes_declared(self) -> None:
        self.assertIn("FASTAPI_CONTRACT_LOADED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("FASTAPI_ENDPOINT_UNMAPPED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("FASTAPI_ERROR_MAPPING_INCOMPLETE", mod.REQUIRED_EVENT_CODES)
        self.assertIn("FASTAPI_AUTH_UNDEFINED", mod.REQUIRED_EVENT_CODES)


class TestDiscovery(TestCase):
    def test_extract_registry_error_codes(self) -> None:
        codes = mod.extract_registry_error_codes(mod.ERROR_REGISTRY_PATH)
        self.assertIn("FRANKEN_PROTOCOL_AUTH_TIMEOUT", codes)
        self.assertGreaterEqual(len(codes), 5)


class TestVerification(TestCase):
    def test_run_checks_passes(self) -> None:
        ok, report = mod.run_checks()
        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-3ndj")
        self.assertFalse(report["errors"])

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")

    def test_pending_checklist_item_is_rejected(self) -> None:
        checklist = json.loads(mod.CHECKLIST_PATH.read_text(encoding="utf-8"))
        checklist["checklist"][0]["status"] = "pending"

        with TemporaryDirectory(prefix="fastapi-contract-test-") as tmp:
            tmp_path = Path(tmp)
            checklist_path = tmp_path / "checklist.json"
            checklist_path.write_text(json.dumps(checklist, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                checklist_path=checklist_path,
                contract_path=mod.CONTRACT_PATH,
                registry_path=mod.ERROR_REGISTRY_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("pending checklist requirements" in err for err in report["errors"]))

    def test_missing_error_mapping_is_rejected(self) -> None:
        checklist = json.loads(mod.CHECKLIST_PATH.read_text(encoding="utf-8"))
        checklist["error_mapping"] = checklist["error_mapping"][1:]

        with TemporaryDirectory(prefix="fastapi-contract-test-") as tmp:
            tmp_path = Path(tmp)
            checklist_path = tmp_path / "checklist.json"
            checklist_path.write_text(json.dumps(checklist, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                checklist_path=checklist_path,
                contract_path=mod.CONTRACT_PATH,
                registry_path=mod.ERROR_REGISTRY_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("missing HTTP mapping" in err for err in report["errors"]))

    def test_missing_auth_method_is_rejected(self) -> None:
        checklist = json.loads(mod.CHECKLIST_PATH.read_text(encoding="utf-8"))
        checklist["endpoint_groups"][0]["auth_method"] = ""

        with TemporaryDirectory(prefix="fastapi-contract-test-") as tmp:
            tmp_path = Path(tmp)
            checklist_path = tmp_path / "checklist.json"
            checklist_path.write_text(json.dumps(checklist, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                checklist_path=checklist_path,
                contract_path=mod.CONTRACT_PATH,
                registry_path=mod.ERROR_REGISTRY_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("auth_method is required" in err for err in report["errors"]))


if __name__ == "__main__":
    main()
