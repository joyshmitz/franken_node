#!/usr/bin/env python3
"""Unit tests for migration_risk_scorer.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_risk_scorer as scorer


class TestExtractFeatures(unittest.TestCase):
    def test_extracts_from_clean(self):
        report = {
            "summary": {"risk_distribution": {"low": 3, "medium": 0, "high": 0, "critical": 0}},
            "api_usage": [],
            "dependencies": [],
        }
        f = scorer.extract_features(report)
        self.assertEqual(f["critical_api_count"], 0)
        self.assertEqual(f["native_addon_count"], 0)

    def test_counts_unsafe(self):
        report = {
            "summary": {"risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 1}},
            "api_usage": [{"api_family": "unsafe", "api_name": "eval"}],
            "dependencies": [],
        }
        f = scorer.extract_features(report)
        self.assertEqual(f["unsafe_api_count"], 1)

    def test_counts_native_addons(self):
        report = {
            "summary": {"risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0}},
            "api_usage": [],
            "dependencies": [
                {"name": "sharp", "has_native_addon": True},
                {"name": "express", "has_native_addon": False},
            ],
        }
        f = scorer.extract_features(report)
        self.assertEqual(f["native_addon_count"], 1)
        self.assertEqual(f["total_dependency_count"], 2)


class TestComputeScore(unittest.TestCase):
    def test_zero_features_zero_score(self):
        features = {k: 0 for k in scorer.WEIGHTS}
        score, expl = scorer.compute_score(features)
        self.assertEqual(score, 0.0)
        self.assertEqual(len(expl), 0)

    def test_positive_features_positive_score(self):
        features = {k: 0 for k in scorer.WEIGHTS}
        features["critical_api_count"] = 2
        score, expl = scorer.compute_score(features)
        self.assertGreater(score, 0)
        self.assertGreater(len(expl), 0)

    def test_score_capped_at_100(self):
        features = {k: 1000 for k in scorer.WEIGHTS}
        score, _ = scorer.compute_score(features)
        self.assertEqual(score, 100.0)

    def test_explanations_include_contribution(self):
        features = {k: 0 for k in scorer.WEIGHTS}
        features["high_risk_api_count"] = 3
        _, expl = scorer.compute_score(features)
        self.assertEqual(len(expl), 1)
        self.assertEqual(expl[0]["contribution"], 15.0)


class TestClassifyDifficulty(unittest.TestCase):
    def test_low(self):
        self.assertEqual(scorer.classify_difficulty(10)["level"], "low")

    def test_medium(self):
        self.assertEqual(scorer.classify_difficulty(25)["level"], "medium")

    def test_high(self):
        self.assertEqual(scorer.classify_difficulty(50)["level"], "high")

    def test_critical(self):
        self.assertEqual(scorer.classify_difficulty(85)["level"], "critical")

    def test_boundary_low(self):
        self.assertEqual(scorer.classify_difficulty(15)["level"], "low")

    def test_boundary_medium(self):
        self.assertEqual(scorer.classify_difficulty(40)["level"], "medium")


class TestScoreReport(unittest.TestCase):
    def test_produces_complete_report(self):
        scan = {
            "project": "test",
            "summary": {"risk_distribution": {"low": 1, "medium": 0, "high": 0, "critical": 0}},
            "api_usage": [],
            "dependencies": [],
        }
        result = scorer.score_report(scan)
        self.assertIn("risk_score", result)
        self.assertIn("difficulty", result)
        self.assertIn("features", result)
        self.assertIn("explanations", result)
        self.assertIn("weights_used", result)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = scorer.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
