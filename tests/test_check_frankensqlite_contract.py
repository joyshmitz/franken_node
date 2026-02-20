"""Unit tests for scripts/check_frankensqlite_contract.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_frankensqlite_contract",
    ROOT / "scripts" / "check_frankensqlite_contract.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_contract_and_matrix_exist(self) -> None:
        self.assertTrue(mod.CONTRACT_PATH.is_file())
        self.assertTrue(mod.MATRIX_PATH.is_file())

    def test_required_event_codes_declared(self) -> None:
        self.assertIn("PERSISTENCE_CONTRACT_LOADED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("PERSISTENCE_CLASS_UNMAPPED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("PERSISTENCE_TIER_INVALID", mod.REQUIRED_EVENT_CODES)
        self.assertIn("PERSISTENCE_REPLAY_UNSUPPORTED", mod.REQUIRED_EVENT_CODES)


class TestDiscovery(TestCase):
    def test_discover_stateful_modules_includes_expected(self) -> None:
        modules = mod.discover_stateful_modules(mod.MODULE_ROOT)
        self.assertIn("crates/franken-node/src/connector/fencing.rs", modules)
        self.assertIn("crates/franken-node/src/connector/health_gate.rs", modules)
        self.assertGreaterEqual(len(modules), 10)


class TestVerification(TestCase):
    def test_run_checks_passes(self) -> None:
        ok, report = mod.run_checks()
        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-1a1j")
        self.assertFalse(report["errors"])

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")

    def test_duplicate_table_ownership_is_rejected(self) -> None:
        matrix = json.loads(mod.MATRIX_PATH.read_text(encoding="utf-8"))
        matrix["persistence_classes"][1]["tables"].append(
            matrix["persistence_classes"][0]["tables"][0]
        )

        with TemporaryDirectory(prefix="frankensqlite-test-") as tmp:
            tmp_path = Path(tmp)
            matrix_path = tmp_path / "matrix.json"
            matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                matrix_path=matrix_path,
                contract_path=mod.CONTRACT_PATH,
                module_root=mod.MODULE_ROOT,
            )

        self.assertFalse(ok)
        self.assertTrue(any("table ownership conflict" in err for err in report["errors"]))

    def test_invalid_tier_mode_pair_is_rejected(self) -> None:
        matrix = json.loads(mod.MATRIX_PATH.read_text(encoding="utf-8"))
        matrix["durability_modes"]["tier_1"]["journal_mode"] = "DELETE"

        with TemporaryDirectory(prefix="frankensqlite-test-") as tmp:
            tmp_path = Path(tmp)
            matrix_path = tmp_path / "matrix.json"
            matrix_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                matrix_path=matrix_path,
                contract_path=mod.CONTRACT_PATH,
                module_root=mod.MODULE_ROOT,
            )

        self.assertFalse(ok)
        self.assertTrue(any("invalid pair" in err for err in report["errors"]))

    def test_unclassified_new_stateful_module_is_detected(self) -> None:
        matrix = json.loads(mod.MATRIX_PATH.read_text(encoding="utf-8"))

        with TemporaryDirectory(prefix="frankensqlite-test-") as tmp:
            tmp_path = Path(tmp)
            module_root = tmp_path / "crates" / "franken-node" / "src" / "connector"
            module_root.mkdir(parents=True, exist_ok=True)

            # Baseline mapped module
            (module_root / "fencing.rs").write_text("pub struct FenceState;\n", encoding="utf-8")
            # New stateful module that is intentionally unmapped
            (module_root / "lease_service.rs").write_text(
                "pub struct LeaseService;\n", encoding="utf-8"
            )

            custom_matrix = {
                "durability_modes": matrix["durability_modes"],
                "mode_catalog": matrix["mode_catalog"],
                "concurrency_model": matrix["concurrency_model"],
                "event_codes": matrix["event_codes"],
                "checklist": [{"requirement": "x", "status": "defined"}],
                "persistence_classes": [
                    {
                        "domain": "fencing_only",
                        "owner_module": "crates/franken-node/src/connector/fencing.rs",
                        "safety_tier": "tier_1",
                        "durability_mode": "wal_full",
                        "tables": ["fencing_only_table"],
                        "replay_support": True,
                        "replay_strategy": "ordered",
                    }
                ],
            }

            matrix_path = tmp_path / "matrix.json"
            matrix_path.write_text(json.dumps(custom_matrix, indent=2), encoding="utf-8")

            contract_path = tmp_path / "contract.md"
            contract_path.write_text(
                "\n".join(mod.REQUIRED_CONTRACT_SECTIONS),
                encoding="utf-8",
            )

            ok, report = mod.run_checks(
                matrix_path=matrix_path,
                contract_path=contract_path,
                module_root=module_root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("missing persistence class mapping" in err for err in report["errors"]))


if __name__ == "__main__":
    main()
