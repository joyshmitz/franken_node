#!/usr/bin/env python3
"""Unit tests for project_scanner.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import project_scanner as scanner


class TestClassifyRisk(unittest.TestCase):
    def test_core_native_is_low(self):
        self.assertEqual(scanner.classify_risk("core", "native"), "low")

    def test_core_stub_is_medium(self):
        self.assertEqual(scanner.classify_risk("core", "stub"), "medium")

    def test_high_value_stub_is_high(self):
        self.assertEqual(scanner.classify_risk("high-value", "stub"), "high")

    def test_high_value_native_is_low(self):
        self.assertEqual(scanner.classify_risk("high-value", "native"), "low")

    def test_unsafe_is_critical(self):
        self.assertEqual(scanner.classify_risk("core", "native", is_unsafe=True), "critical")

    def test_unknown_band_is_medium(self):
        self.assertEqual(scanner.classify_risk(None, None), "medium")

    def test_edge_is_medium(self):
        self.assertEqual(scanner.classify_risk("edge", "stub"), "medium")


class TestScanFile(unittest.TestCase):
    def test_detects_fs_readFileSync(self):
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write("const data = fs.readFileSync('file.txt', 'utf8');\n")
            f.flush()
            results = scanner.scan_file(Path(f.name), {})
        apis = [r["api_name"] for r in results]
        self.assertIn("readFileSync", apis)

    def test_detects_process_env(self):
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write("const env = process.env.NODE_ENV;\n")
            f.flush()
            results = scanner.scan_file(Path(f.name), {})
        apis = [r["api_name"] for r in results]
        self.assertIn("env", apis)

    def test_detects_unsafe_eval(self):
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write("eval('alert(1)');\n")
            f.flush()
            results = scanner.scan_file(Path(f.name), {})
        unsafe = [r for r in results if r["api_family"] == "unsafe"]
        self.assertTrue(len(unsafe) > 0)
        self.assertEqual(unsafe[0]["risk_level"], "critical")

    def test_empty_file_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
            f.write("")
            f.flush()
            results = scanner.scan_file(Path(f.name), {})
        self.assertEqual(len(results), 0)


class TestScanDependencies(unittest.TestCase):
    def test_detects_native_addon(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = Path(tmpdir) / "package.json"
            pkg.write_text(json.dumps({"dependencies": {"sharp": "^0.32.0", "express": "^4.18.0"}}))
            deps = scanner.scan_dependencies(Path(tmpdir))
        native = [d for d in deps if d["has_native_addon"]]
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0]["name"], "sharp")
        self.assertEqual(native[0]["risk_level"], "critical")

    def test_no_package_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            deps = scanner.scan_dependencies(Path(tmpdir))
        self.assertEqual(len(deps), 0)


class TestComputeReadiness(unittest.TestCase):
    def test_critical_is_not_ready(self):
        self.assertEqual(scanner.compute_readiness({"low": 5, "medium": 0, "high": 0, "critical": 1}), "not-ready")

    def test_high_is_partial(self):
        self.assertEqual(scanner.compute_readiness({"low": 5, "medium": 0, "high": 1, "critical": 0}), "partial")

    def test_all_low_is_ready(self):
        self.assertEqual(scanner.compute_readiness({"low": 5, "medium": 0, "high": 0, "critical": 0}), "ready")


class TestScanProject(unittest.TestCase):
    def test_full_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)
            (project / "index.js").write_text("const p = path.join('a', 'b');\n")
            report = scanner.scan_project(project)
        self.assertIn("project", report)
        self.assertIn("summary", report)
        self.assertIn("api_usage", report)
        self.assertIn("dependencies", report)

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = scanner.scan_project(Path(tmpdir))
        self.assertEqual(report["summary"]["total_apis_detected"], 0)
        self.assertEqual(report["summary"]["migration_readiness"], "ready")


class TestLoadRegistry(unittest.TestCase):
    def test_loads_entries(self):
        registry = scanner.load_registry()
        self.assertGreater(len(registry), 0)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = scanner.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
