"""Tests for scripts/check_tokio_bootstrap_guardrail.py (bd-1now.3.2)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_tokio_bootstrap_guardrail.py"

spec = importlib.util.spec_from_file_location("check_tokio_bootstrap_guardrail", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


def _write_blueprint(path: Path, *, include_exception_section: bool = True) -> None:
    text = """\
## 8.6 Selective Asupersync Leverage Decision Record

Selective Asupersync record.
"""
    if include_exception_section:
        text += """
### Runtime Guardrail Exception Path

1. Update the blueprint.
2. Update the checker.
3. Add proof.
"""
    path.write_text(text, encoding="utf-8")


def _write_main(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run_with_paths(source_root: Path, blueprint: Path) -> dict[str, object]:
    old_source_root = mod.SOURCE_ROOT
    old_blueprint = mod.BLUEPRINT
    try:
        mod.SOURCE_ROOT = source_root
        mod.BLUEPRINT = blueprint
        return mod.run_all()
    finally:
        mod.SOURCE_ROOT = old_source_root
        mod.BLUEPRINT = old_blueprint


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestLiveTree:
    def test_live_tree_passes(self):
        result = mod.run_all()
        assert result["verdict"] == "PASS", json.dumps(result, indent=2)
        assert result["metrics"]["unapproved_violation_count"] == 0


class TestSyntheticRuns:
    def test_detects_tokio_main(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint)
        _write_main(
            source_root / "main.rs",
            """\
#[tokio::main]
async fn main() {}
""",
        )
        result = _run_with_paths(source_root, blueprint)
        assert result["verdict"] == "FAIL"
        assert result["metrics"]["unapproved_violation_count"] == 1
        assert result["violations"][0]["reason_code"] == "TKG-001"
        assert result["violations"][0]["rule_id"] == "tokio-attr-main"

    def test_detects_aliased_runtime_builder(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint)
        _write_main(
            source_root / "main.rs",
            """\
use tokio::runtime::{Builder as TokioBuilder, Runtime};

fn main() {
    let _ = TokioBuilder::new_current_thread();
    let _ = Runtime::new();
}
""",
        )
        result = _run_with_paths(source_root, blueprint)
        reason_codes = {item["reason_code"] for item in result["violations"]}
        assert result["verdict"] == "FAIL"
        assert "TKG-005" in reason_codes
        assert "TKG-006" in reason_codes

    def test_ignores_comments_and_strings(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint)
        _write_main(
            source_root / "main.rs",
            """\
fn main() {
    // #[tokio::main]
    let _message = "tokio::runtime::Builder::new_current_thread()";
}
""",
        )
        result = _run_with_paths(source_root, blueprint)
        assert result["verdict"] == "PASS", json.dumps(result, indent=2)
        assert result["violations"] == []

    def test_missing_exception_section_fails(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint, include_exception_section=False)
        _write_main(source_root / "main.rs", "fn main() {}\n")
        result = _run_with_paths(source_root, blueprint)
        checks = {item["check"]: item for item in result["checks"]}
        assert result["verdict"] == "FAIL"
        assert checks["blueprint_exception_path_present"]["pass"] is False


class TestCliJsonOutput:
    @pytest.fixture()
    def clean_env(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint)
        _write_main(source_root / "main.rs", "fn main() {}\n")
        env = os.environ.copy()
        env["TOKIO_BOOTSTRAP_GUARDRAIL_SOURCE_ROOT"] = str(source_root)
        env["TOKIO_BOOTSTRAP_GUARDRAIL_BLUEPRINT"] = str(blueprint)
        return env

    def test_cli_json_pass(self, clean_env):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=clean_env,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["bead_id"] == "bd-1now.3.1"
        assert data["verdict"] == "PASS"

    def test_cli_json_fail(self, tmp_path: Path):
        source_root = tmp_path / "src"
        blueprint = tmp_path / "blueprint.md"
        _write_blueprint(blueprint)
        _write_main(
            source_root / "main.rs",
            "use tokio::runtime::Runtime;\nfn main() { let _ = Runtime::new(); }\n",
        )
        env = os.environ.copy()
        env["TOKIO_BOOTSTRAP_GUARDRAIL_SOURCE_ROOT"] = str(source_root)
        env["TOKIO_BOOTSTRAP_GUARDRAIL_BLUEPRINT"] = str(blueprint)
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
        )
        assert proc.returncode == 1
        data = json.loads(proc.stdout)
        assert data["verdict"] == "FAIL"
        assert data["violations"][0]["reason_code"] == "TKG-005"
