"""Unit tests for scripts/check_sqlmodel_policy.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_sqlmodel_policy",
    ROOT / "scripts" / "check_sqlmodel_policy.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_policy_files_exist(self) -> None:
        self.assertTrue(mod.POLICY_DOC_PATH.is_file())
        self.assertTrue(mod.POLICY_MATRIX_PATH.is_file())
        self.assertTrue(mod.PERSISTENCE_MATRIX_PATH.is_file())

    def test_required_event_codes_declared(self) -> None:
        self.assertIn("SQLMODEL_POLICY_LOADED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("SQLMODEL_DOMAIN_UNCLASSIFIED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("SQLMODEL_OWNERSHIP_CONFLICT", mod.REQUIRED_EVENT_CODES)
        self.assertIn("SQLMODEL_CODEGEN_STALE", mod.REQUIRED_EVENT_CODES)


class TestVerification(TestCase):
    def test_run_checks_passes(self) -> None:
        ok, report = mod.run_checks()
        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-bt82")
        self.assertFalse(report["errors"])

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")

    def test_missing_domain_classification_is_rejected(self) -> None:
        policy = json.loads(mod.POLICY_MATRIX_PATH.read_text(encoding="utf-8"))
        source = json.loads(mod.PERSISTENCE_MATRIX_PATH.read_text(encoding="utf-8"))
        source["persistence_classes"].append({"domain": "new_unclassified_domain"})

        with TemporaryDirectory(prefix="sqlmodel-policy-test-") as tmp:
            tmp_path = Path(tmp)
            policy_path = tmp_path / "policy.json"
            source_path = tmp_path / "source.json"
            doc_path = tmp_path / "policy.md"

            policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
            source_path.write_text(json.dumps(source, indent=2), encoding="utf-8")
            doc_path.write_text(mod.POLICY_DOC_PATH.read_text(encoding="utf-8"), encoding="utf-8")

            ok, report = mod.run_checks(
                policy_matrix_path=policy_path,
                policy_doc_path=doc_path,
                source_persistence_matrix_path=source_path,
            )

        self.assertFalse(ok)
        self.assertTrue(any("missing sqlmodel classification" in err for err in report["errors"]))

    def test_mandatory_domain_without_model_is_rejected(self) -> None:
        policy = json.loads(mod.POLICY_MATRIX_PATH.read_text(encoding="utf-8"))
        policy["domains"][0]["typed_model_defined"] = False

        with TemporaryDirectory(prefix="sqlmodel-policy-test-") as tmp:
            tmp_path = Path(tmp)
            policy_path = tmp_path / "policy.json"
            policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                policy_matrix_path=policy_path,
                policy_doc_path=mod.POLICY_DOC_PATH,
                source_persistence_matrix_path=mod.PERSISTENCE_MATRIX_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("mandatory domain must set typed_model_defined=true" in e for e in report["errors"]))

    def test_model_ownership_conflict_is_rejected(self) -> None:
        policy = json.loads(mod.POLICY_MATRIX_PATH.read_text(encoding="utf-8"))
        # Force a duplicate model name with different owner module.
        policy["domains"][1]["model_name"] = policy["domains"][0]["model_name"]

        with TemporaryDirectory(prefix="sqlmodel-policy-test-") as tmp:
            tmp_path = Path(tmp)
            policy_path = tmp_path / "policy.json"
            policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                policy_matrix_path=policy_path,
                policy_doc_path=mod.POLICY_DOC_PATH,
                source_persistence_matrix_path=mod.PERSISTENCE_MATRIX_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("model ownership conflict" in e for e in report["errors"]))

    def test_invalid_classification_is_rejected(self) -> None:
        policy = json.loads(mod.POLICY_MATRIX_PATH.read_text(encoding="utf-8"))
        policy["domains"][0]["classification"] = "required"

        with TemporaryDirectory(prefix="sqlmodel-policy-test-") as tmp:
            tmp_path = Path(tmp)
            policy_path = tmp_path / "policy.json"
            policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                policy_matrix_path=policy_path,
                policy_doc_path=mod.POLICY_DOC_PATH,
                source_persistence_matrix_path=mod.PERSISTENCE_MATRIX_PATH,
            )

        self.assertFalse(ok)
        self.assertTrue(any("invalid classification" in e for e in report["errors"]))


if __name__ == "__main__":
    main()
