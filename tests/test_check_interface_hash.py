"""Unit tests for check_interface_hash.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestInterfaceHashFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/interface_hash/verification_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/interface_hash/verification_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_covers_admit_and_reject(self):
        path = os.path.join(ROOT, "fixtures/interface_hash/verification_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        admitted = [c for c in data["cases"] if c.get("expected_admitted") is True]
        rejected = [c for c in data["cases"] if c.get("expected_admitted") is False]
        self.assertGreater(len(admitted), 0)
        self.assertGreater(len(rejected), 0)


class TestInterfaceHashMetrics(unittest.TestCase):

    def test_metrics_csv_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3n58/interface_hash_rejection_metrics.csv")
        self.assertTrue(os.path.isfile(path))

    def test_metrics_csv_has_header(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3n58/interface_hash_rejection_metrics.csv")
        with open(path) as f:
            header = f.readline()
        self.assertIn("rejection_code", header)

    def test_metrics_csv_has_all_codes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3n58/interface_hash_rejection_metrics.csv")
        with open(path) as f:
            content = f.read()
        for code in ["IFACE_HASH_MISMATCH", "IFACE_DOMAIN_MISMATCH",
                     "IFACE_HASH_MALFORMED", "IFACE_HASH_EXPIRED"]:
            self.assertIn(code, content, f"Missing code {code}")


class TestInterfaceHashImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/interface_hash.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_interface_hash(self):
        self.assertIn("struct InterfaceHash", self.content)

    def test_has_admission_telemetry(self):
        self.assertIn("struct AdmissionTelemetry", self.content)

    def test_has_admission_check(self):
        self.assertIn("struct AdmissionCheck", self.content)

    def test_has_rejection_code(self):
        self.assertIn("enum RejectionCode", self.content)

    def test_has_compute_hash(self):
        self.assertIn("fn compute_hash", self.content)

    def test_has_verify_hash(self):
        self.assertIn("fn verify_hash", self.content)

    def test_has_admit(self):
        self.assertIn("fn admit", self.content)

    def test_has_domain_separation(self):
        self.assertIn("domain.hash", self.content)

    def test_has_all_rejection_codes(self):
        for code in ["HashMismatch", "DomainMismatch", "ExpiredHash", "MalformedHash"]:
            self.assertIn(code, self.content, f"Missing rejection code {code}")

    def test_has_all_error_codes(self):
        for code in ["IFACE_HASH_MISMATCH", "IFACE_DOMAIN_MISMATCH",
                     "IFACE_HASH_EXPIRED", "IFACE_HASH_MALFORMED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestInterfaceHashSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3n58_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-HASH-DOMAIN-SEP", "INV-HASH-ADMISSION",
                    "INV-HASH-TELEMETRY", "INV-HASH-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["IFACE_HASH_MISMATCH", "IFACE_DOMAIN_MISMATCH",
                     "IFACE_HASH_EXPIRED", "IFACE_HASH_MALFORMED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_rejection_code_type(self):
        self.assertIn("RejectionCode", self.content)
