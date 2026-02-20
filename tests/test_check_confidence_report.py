#!/usr/bin/env python3
"""Unit tests for migration_confidence_report.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_confidence_report as report


class TestComputeConfidence(unittest.TestCase):
    def test_perfect_inputs_high_score(self):
        c = report.compute_confidence(0, 1.0, 1.0, 1.0)
        self.assertGreaterEqual(c["confidence_score"], 80)

    def test_worst_inputs_low_score(self):
        c = report.compute_confidence(100, 0.0, 0.0, 0.0)
        self.assertLessEqual(c["confidence_score"], 20)

    def test_score_bounded(self):
        c = report.compute_confidence(0, 1.0, 1.0, 1.0)
        self.assertGreaterEqual(c["confidence_score"], 0)
        self.assertLessEqual(c["confidence_score"], 100)

    def test_uncertainty_band_present(self):
        c = report.compute_confidence(50, 0.5, 0.5, 0.5)
        self.assertIn("uncertainty_band", c)
        self.assertGreaterEqual(c["uncertainty_band"]["width"], 0)

    def test_uncertainty_wider_with_less_data(self):
        c_good = report.compute_confidence(50, 0.9, 0.9, 0.9)
        c_bad = report.compute_confidence(50, 0.1, 0.1, 0.1)
        self.assertGreater(c_bad["uncertainty_band"]["width"], c_good["uncertainty_band"]["width"])

    def test_components_sum_to_score(self):
        c = report.compute_confidence(30, 0.8, 0.7, 0.9)
        comp_sum = sum(c["components"].values())
        self.assertAlmostEqual(c["confidence_score"], min(100, comp_sum), places=0)


class TestClassifyConfidence(unittest.TestCase):
    def test_high(self):
        self.assertEqual(report.classify_confidence(85)["level"], "high")

    def test_medium(self):
        self.assertEqual(report.classify_confidence(60)["level"], "medium")

    def test_low(self):
        self.assertEqual(report.classify_confidence(30)["level"], "low")

    def test_insufficient(self):
        self.assertEqual(report.classify_confidence(10)["level"], "insufficient")


class TestGenerateReport(unittest.TestCase):
    def test_has_required_fields(self):
        r = report.generate_report()
        self.assertIn("confidence", r)
        self.assertIn("classification", r)
        self.assertIn("go_decision", r)
        self.assertIn("uncertainty_sources", r)

    def test_go_decision_bool(self):
        r = report.generate_report()
        self.assertIsInstance(r["go_decision"]["proceed"], bool)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = report.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
