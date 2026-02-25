#!/usr/bin/env python3
"""Validate adjacent-substrate dependency coverage for franken_node source modules."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


ALLOWED_SUBSTRATES = {"frankentui", "frankensqlite", "sqlmodel_rust", "fastapi_rust"}
ALLOWED_PLANES = {"presentation", "persistence", "model", "service"}
ALLOWED_INTEGRATION_TYPES = {"mandatory", "should_use", "optional"}


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def discover_modules(module_root: str = "crates/franken-node/src") -> dict[str, list[str]]:
    root = Path(module_root)
    if not root.exists():
        raise FileNotFoundError(f"module root not found: {module_root}")

    directories = [_norm(root)]
    directories.extend(_norm(path) for path in sorted(p for p in root.rglob("*") if p.is_dir()))
    files = [_norm(path) for path in sorted(root.rglob("*.rs"))]
    all_paths = sorted(set(directories + files))

    return {
        "module_root": _norm(root),
        "directories": directories,
        "files": files,
        "all_paths": all_paths,
    }


def _map_hash(matrix: dict[str, Any]) -> str:
    canonical = json.dumps(matrix, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_map(
    matrix: dict[str, Any], discovered: dict[str, list[str]]
) -> tuple[bool, dict[str, Any]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    warnings: list[str] = []

    module_entries = matrix.get("modules", [])
    if not isinstance(module_entries, list):
        raise ValueError("matrix.modules must be a list")

    trace = _map_hash(matrix)
    events.append(
        {
            "event_code": "DEPENDENCY_MAP_LOADED",
            "severity": "info",
            "trace_correlation": trace,
            "message": "Loaded substrate dependency matrix.",
        }
    )

    by_path: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for entry in module_entries:
        path = entry.get("path")
        if not isinstance(path, str):
            errors.append("module entry missing string path")
            continue
        if path in by_path:
            duplicates.append(path)
        by_path[path] = entry
    if duplicates:
        for path in duplicates:
            events.append(
                {
                    "event_code": "DEPENDENCY_MAP_DUPLICATE_PATH",
                    "severity": "error",
                    "trace_correlation": trace,
                    "path": path,
                    "message": f"Duplicate module path in matrix: {path}",
                }
            )
        errors.extend(f"duplicate path: {path}" for path in duplicates)

    discovered_paths = set(discovered["all_paths"])
    mapped_paths = set(by_path.keys())

    unmapped = sorted(discovered_paths - mapped_paths)
    stale_entries = sorted(mapped_paths - discovered_paths)

    for path in unmapped:
        events.append(
            {
                "event_code": "DEPENDENCY_MAP_MODULE_UNMAPPED",
                "severity": "error",
                "trace_correlation": trace,
                "path": path,
                "message": f"Discovered module missing from matrix: {path}",
            }
        )
    if unmapped:
        errors.extend(f"unmapped module: {path}" for path in unmapped)

    for path in stale_entries:
        events.append(
            {
                "event_code": "DEPENDENCY_MAP_STALE_ENTRY",
                "severity": "warning",
                "trace_correlation": trace,
                "path": path,
                "message": f"Matrix contains path not present in source tree: {path}",
            }
        )
    if stale_entries:
        warnings.extend(f"stale matrix path: {path}" for path in stale_entries)

    plane_counts = {plane: 0 for plane in ALLOWED_PLANES}
    substrate_counts = {name: 0 for name in ALLOWED_SUBSTRATES}

    for path, entry in by_path.items():
        substrates = entry.get("substrates", [])
        if not isinstance(substrates, list):
            errors.append(f"{path}: substrates must be a list")
            continue
        for spec in substrates:
            if not isinstance(spec, dict):
                errors.append(f"{path}: substrate spec must be an object")
                continue
            name = spec.get("name")
            plane = spec.get("plane")
            integration_type = spec.get("integration_type")
            if name not in ALLOWED_SUBSTRATES:
                errors.append(f"{path}: invalid substrate name `{name}`")
            if plane not in ALLOWED_PLANES:
                errors.append(f"{path}: invalid plane `{plane}`")
            if integration_type not in ALLOWED_INTEGRATION_TYPES:
                errors.append(f"{path}: invalid integration_type `{integration_type}`")
            if name in substrate_counts:
                substrate_counts[name] += 1
            if plane in plane_counts:
                plane_counts[plane] += 1

    for plane, count in plane_counts.items():
        if count == 0:
            events.append(
                {
                    "event_code": "DEPENDENCY_MAP_PLANE_EMPTY",
                    "severity": "warning",
                    "trace_correlation": trace,
                    "plane": plane,
                    "message": f"No mappings found for plane `{plane}`.",
                }
            )
            errors.append(f"plane has zero mappings: {plane}")

    declared_unmapped = matrix.get("unmapped_modules", [])
    if declared_unmapped != unmapped:
        errors.append("matrix.unmapped_modules does not match computed unmapped module list")

    computed_summary = {
        "module_count": len(module_entries),
        "directory_count": len(discovered["directories"]),
        "file_count": len(discovered["files"]),
        "planes": plane_counts,
        "substrates": substrate_counts,
    }

    matrix_summary = matrix.get("coverage_summary")
    if matrix_summary is not None and matrix_summary != computed_summary:
        warnings.append("coverage_summary does not match computed summary")

    success = len(errors) == 0
    report = {
        "ok": success,
        "module_root": discovered["module_root"],
        "trace_correlation": trace,
        "discovered_module_count": len(discovered["all_paths"]),
        "mapped_module_count": len(module_entries),
        "unmapped_modules": unmapped,
        "stale_entries": stale_entries,
        "errors": errors,
        "warnings": warnings,
        "events": events,
        "coverage_summary": computed_summary,
    }
    return success, report


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="dep-map-selftest-") as tmp_dir:
        root = Path(tmp_dir) / "src"
        (root / "mod_a").mkdir(parents=True)
        (root / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (root / "mod_a" / "mod.rs").write_text("pub fn x() {}\n", encoding="utf-8")

        discovered = discover_modules(str(root))

        matrix_pass = {
            "modules": [
                {
                    "path": _norm(root),
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
                {"path": _norm(root / "mod_a"), "substrates": []},
                {"path": _norm(root / "main.rs"), "substrates": []},
                {"path": _norm(root / "mod_a" / "mod.rs"), "substrates": []},
            ],
            "unmapped_modules": [],
        }
        ok, _ = evaluate_map(matrix_pass, discovered)
        assert ok, "self_test pass case failed"

        matrix_fail = {
            "modules": [
                {
                    "path": _norm(root),
                    "substrates": [
                        {
                            "name": "frankentui",
                            "plane": "presentation",
                            "integration_type": "mandatory",
                        }
                    ],
                }
            ],
            "unmapped_modules": [],
        }
        ok_fail, report_fail = evaluate_map(matrix_fail, discovered)
        assert not ok_fail, "self_test fail case unexpectedly passed"
        assert report_fail["unmapped_modules"], "self_test fail case missing unmapped modules"


def main() -> int:
    logger = configure_test_logging("check_substrate_dependency_map")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        default="artifacts/10.16/substrate_dependency_matrix.json",
        help="Path to substrate dependency matrix JSON.",
    )
    parser.add_argument(
        "--module-root",
        default="crates/franken-node/src",
        help="Source module root to scan.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal checker self-test and exit.",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        payload = {"ok": True, "self_test": "passed"}
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("self_test: passed")
        return 0

    with Path(args.matrix).open("r", encoding="utf-8") as handle:
        matrix = json.load(handle)
    discovered = discover_modules(args.module_root)
    ok, report = evaluate_map(matrix, discovered)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        status = "PASS" if ok else "FAIL"
        print(f"{status}: {len(report['errors'])} errors, {len(report['warnings'])} warnings")
        if report["errors"]:
            for err in report["errors"]:
                print(f"error: {err}")
        if report["warnings"]:
            for warn in report["warnings"]:
                print(f"warning: {warn}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
