from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_checker_module():
    script_path = Path("scripts/check_substrate_dependency_map.py")
    spec = importlib.util.spec_from_file_location("check_substrate_dependency_map", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_discover_modules_includes_directories_and_rs_files(tmp_path: Path):
    checker = _load_checker_module()

    root = tmp_path / "src"
    (root / "alpha").mkdir(parents=True)
    (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    (root / "alpha" / "mod.rs").write_text("pub fn x() {}\n", encoding="utf-8")

    discovered = checker.discover_modules(str(root))
    all_paths = discovered["all_paths"]

    assert str(root).replace("\\", "/") in all_paths
    assert str(root / "alpha").replace("\\", "/") in all_paths
    assert str(root / "main.rs").replace("\\", "/") in all_paths
    assert str(root / "alpha" / "mod.rs").replace("\\", "/") in all_paths


def test_evaluate_map_detects_unmapped_module(tmp_path: Path):
    checker = _load_checker_module()

    root = tmp_path / "src"
    (root / "main.rs").parent.mkdir(parents=True, exist_ok=True)
    (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    discovered = checker.discover_modules(str(root))
    matrix = {
        "modules": [
            {
                "path": str(root).replace("\\", "/"),
                "substrates": [
                    {
                        "name": "frankentui",
                        "plane": "presentation",
                        "integration_type": "mandatory",
                    },
                    {
                        "name": "frankensqlite",
                        "plane": "persistence",
                        "integration_type": "mandatory",
                    },
                    {
                        "name": "sqlmodel_rust",
                        "plane": "model",
                        "integration_type": "should_use",
                    },
                    {
                        "name": "fastapi_rust",
                        "plane": "service",
                        "integration_type": "optional",
                    },
                ],
            }
        ],
        "unmapped_modules": [],
    }

    ok, report = checker.evaluate_map(matrix, discovered)
    assert not ok
    assert report["unmapped_modules"]


def test_evaluate_map_passes_with_full_plane_coverage(tmp_path: Path):
    checker = _load_checker_module()

    root = tmp_path / "src"
    (root / "main.rs").parent.mkdir(parents=True, exist_ok=True)
    (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

    root_norm = str(root).replace("\\", "/")
    main_norm = str(root / "main.rs").replace("\\", "/")
    discovered = checker.discover_modules(str(root))
    matrix = {
        "modules": [
            {
                "path": root_norm,
                "substrates": [
                    {
                        "name": "frankentui",
                        "plane": "presentation",
                        "integration_type": "mandatory",
                    },
                    {
                        "name": "frankensqlite",
                        "plane": "persistence",
                        "integration_type": "mandatory",
                    },
                    {
                        "name": "sqlmodel_rust",
                        "plane": "model",
                        "integration_type": "should_use",
                    },
                    {
                        "name": "fastapi_rust",
                        "plane": "service",
                        "integration_type": "optional",
                    },
                ],
            },
            {"path": main_norm, "substrates": []},
        ],
        "unmapped_modules": [],
    }

    ok, report = checker.evaluate_map(matrix, discovered)
    assert ok
    assert not report["errors"]


def test_self_test_passes():
    checker = _load_checker_module()
    checker.self_test()
