#!/usr/bin/env python3
"""Unit tests for rewrite_suggestion_engine.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rewrite_suggestion_engine as engine


class TestGenerateSuggestions(unittest.TestCase):
    def test_known_api_gets_rule(self):
        scan = {"api_usage": [
            {"api_family": "fs", "api_name": "readFileSync", "source_file": "a.js", "risk_level": "low"}
        ]}
        suggestions = engine.generate_suggestions(scan)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["category"], "direct-replacement")

    def test_unsafe_gets_removal(self):
        scan = {"api_usage": [
            {"api_family": "unsafe", "api_name": "eval", "source_file": "b.js", "risk_level": "critical"}
        ]}
        suggestions = engine.generate_suggestions(scan)
        self.assertEqual(suggestions[0]["category"], "removal-needed")

    def test_unknown_api_gets_manual_review(self):
        scan = {"api_usage": [
            {"api_family": "weird", "api_name": "thing", "source_file": "c.js", "risk_level": "medium"}
        ]}
        suggestions = engine.generate_suggestions(scan)
        self.assertEqual(suggestions[0]["category"], "manual-review")

    def test_priority_ordering(self):
        scan = {"api_usage": [
            {"api_family": "path", "api_name": "join", "source_file": "a.js", "risk_level": "low"},
            {"api_family": "unsafe", "api_name": "eval", "source_file": "b.js", "risk_level": "critical"},
            {"api_family": "http", "api_name": "createServer", "source_file": "c.js", "risk_level": "high"},
        ]}
        suggestions = engine.generate_suggestions(scan)
        risks = [s["risk_level"] for s in suggestions]
        self.assertEqual(risks, ["critical", "high", "low"])

    def test_rollback_included(self):
        scan = {"api_usage": [
            {"api_family": "fs", "api_name": "readFileSync", "source_file": "a.js", "risk_level": "low"}
        ]}
        suggestions = engine.generate_suggestions(scan)
        self.assertIn("rollback", suggestions[0])
        self.assertIn("command", suggestions[0]["rollback"])

    def test_empty_scan_empty_suggestions(self):
        suggestions = engine.generate_suggestions({"api_usage": []})
        self.assertEqual(len(suggestions), 0)


class TestGenerateRollbackPlan(unittest.TestCase):
    def test_rollback_has_files(self):
        suggestions = [
            {"source_file": "a.js", "category": "direct-replacement"},
            {"source_file": "b.js", "category": "removal-needed"},
        ]
        plan = engine.generate_rollback_plan(suggestions, "test")
        self.assertEqual(len(plan["affected_files"]), 2)
        self.assertEqual(len(plan["rollback_commands"]), 2)

    def test_deduplicates_files(self):
        suggestions = [
            {"source_file": "a.js", "category": "direct-replacement"},
            {"source_file": "a.js", "category": "adapter-needed"},
        ]
        plan = engine.generate_rollback_plan(suggestions, "test")
        self.assertEqual(len(plan["affected_files"]), 1)


class TestProduceReport(unittest.TestCase):
    def test_complete_report(self):
        scan = {
            "project": "test",
            "api_usage": [{"api_family": "fs", "api_name": "readFileSync", "source_file": "a.js", "risk_level": "low"}],
        }
        report = engine.produce_report(scan)
        self.assertIn("suggestions", report)
        self.assertIn("rollback_plan", report)
        self.assertIn("summary", report)


class TestRewriteRules(unittest.TestCase):
    def test_rules_have_required_fields(self):
        for key, rule in engine.REWRITE_RULES.items():
            self.assertIn("category", rule)
            self.assertIn("description", rule)
            self.assertIn("before", rule)
            self.assertIn("after", rule)

    def test_unsafe_rules_have_required_fields(self):
        for key, rule in engine.UNSAFE_REWRITES.items():
            self.assertIn("category", rule)
            self.assertEqual(rule["category"], "removal-needed")


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = engine.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
