#!/usr/bin/env python3
"""Unit tests for scripts/check_epoch_scoped_keys.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_epoch_scoped_keys.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_epoch_scoped_keys", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class EpochScopedKeyCheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()

    def test_run_checks_shape(self):
        report = self.checker.run_checks()
        self.assertEqual(report["bead"], "bd-3cs3")
        self.assertEqual(report["section"], "10.14")
        self.assertIn(report["verdict"], {"PASS", "FAIL"})
        self.assertIn("summary", report)
        self.assertIsInstance(report["checks"], list)
        self.assertGreater(len(report["checks"]), 10)

    def test_vectors_missing_file(self):
        original = self.checker.VECTORS
        try:
            self.checker.VECTORS = ROOT / "artifacts" / "10.14" / "_definitely_missing_.json"
            checks = self.checker.check_vectors_json()
            self.assertFalse(checks[0]["pass"])
            self.assertEqual(checks[0]["id"], "EKS-VECTOR-FILE")
        finally:
            self.checker.VECTORS = original

    def test_vectors_reject_short_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vectors.json"
            p.write_text(
                json.dumps(
                    {
                        "vectors": [
                            {
                                "root_secret_hex": "00" * 32,
                                "epoch": 1,
                                "domain": "marker",
                                "expected_key_hex": "11" * 32,
                            }
                        ],
                        "signature_kat": {
                            "artifact_hex": "aa",
                            "epoch": 1,
                            "domain": "marker",
                            "expected_signature_hex": "22" * 32,
                        },
                    }
                ),
                encoding="utf-8",
            )
            original = self.checker.VECTORS
            try:
                self.checker.VECTORS = p
                checks = self.checker.check_vectors_json()
            finally:
                self.checker.VECTORS = original

            count_check = next(c for c in checks if c["id"] == "EKS-VECTOR-COUNT")
            self.assertFalse(count_check["pass"])

    def test_vectors_accept_valid_shape(self):
        vectors = []
        for i in range(10):
            vectors.append(
                {
                    "root_secret_hex": "ab" * 32,
                    "epoch": i + 1,
                    "domain": "marker" if i % 2 == 0 else "manifest",
                    "expected_key_hex": "cd" * 32,
                }
            )
        doc = {
            "vectors": vectors,
            "signature_kat": {
                "artifact_hex": "61626364",
                "epoch": 9,
                "domain": "marker",
                "expected_signature_hex": "ef" * 32,
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vectors.json"
            p.write_text(json.dumps(doc), encoding="utf-8")
            original = self.checker.VECTORS
            try:
                self.checker.VECTORS = p
                checks = self.checker.check_vectors_json()
            finally:
                self.checker.VECTORS = original

        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(failing, [])

    def test_module_registration_requires_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mod.rs"
            p.write_text("pub mod remote_cap;\n", encoding="utf-8")
            original = self.checker.MOD_RS
            try:
                self.checker.MOD_RS = p
                result = self.checker.check_module_registration()
                self.assertFalse(result["pass"])

                p.write_text("pub mod remote_cap;\npub mod epoch_scoped_keys;\n", encoding="utf-8")
                result = self.checker.check_module_registration()
                self.assertTrue(result["pass"])
            finally:
                self.checker.MOD_RS = original

    def test_self_test(self):
        self.checker.self_test()


if __name__ == "__main__":
    unittest.main()
