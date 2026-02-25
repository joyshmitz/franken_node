#!/usr/bin/env python3
"""bd-s6y verifier: canonical trust vectors release/publication gate."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_MANIFEST = ROOT / "vectors" / "canonical_manifest.toml"
DEFAULT_CHANGELOG = ROOT / "vectors" / "CHANGELOG.md"

BEAD_ID = "bd-s6y"
SECTION = "10.7"


@dataclass(frozen=True)
class SourceSpec:
    source_id: str
    section: str
    source_bead_id: str
    source_version: str
    suite_kind: str
    required: bool
    globs: tuple[str, ...]
    paths: tuple[str, ...]
    entry_keys: tuple[str, ...]
    required_keys: tuple[str, ...]
    minimum_entries: int
    parity_targets: tuple[str, ...]
    publication_tag: str


def _now_rfc3339() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_sources(manifest: dict[str, Any]) -> list[SourceSpec]:
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list):
        return []

    policy = manifest.get("policy", {})
    default_targets = tuple(str(t) for t in policy.get("default_parity_targets", []))

    parsed: list[SourceSpec] = []
    for source in raw_sources:
        if not isinstance(source, dict):
            continue
        parsed.append(
            SourceSpec(
                source_id=str(source.get("source_id", "")).strip(),
                section=str(source.get("section", "")).strip(),
                source_bead_id=str(source.get("source_bead_id", "")).strip(),
                source_version=str(source.get("source_version", "")).strip(),
                suite_kind=str(source.get("suite_kind", "json_vectors")).strip(),
                required=bool(source.get("required", True)),
                globs=tuple(str(x) for x in source.get("globs", [])),
                paths=tuple(str(x) for x in source.get("paths", [])),
                entry_keys=tuple(str(x) for x in source.get("entry_keys", [])),
                required_keys=tuple(str(x) for x in source.get("required_keys", [])),
                minimum_entries=int(source.get("minimum_entries", 1)),
                parity_targets=tuple(
                    str(x) for x in source.get("parity_targets", default_targets)
                ),
                publication_tag=str(source.get("publication_tag", "")).strip(),
            )
        )
    return parsed


def _parse_overrides(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    raw = manifest.get("metadata_overrides", {})
    if not isinstance(raw, dict):
        return {}

    parsed: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        parsed[str(key)] = {
            "source_bead_id": str(value.get("source_bead_id", "")).strip(),
            "source_version": str(value.get("source_version", "")).strip(),
        }
    return parsed


def _discover_targets(source: SourceSpec, root: Path) -> list[Path]:
    found: dict[str, Path] = {}

    for rel_path in source.paths:
        candidate = (root / rel_path).resolve()
        found[_relative(candidate, root)] = candidate

    for pattern in source.globs:
        for candidate in sorted(root.glob(pattern)):
            resolved = candidate.resolve()
            found[_relative(resolved, root)] = resolved

    return [found[key] for key in sorted(found)]


def _entry_count(payload: Any, entry_keys: tuple[str, ...]) -> int:
    if isinstance(payload, list):
        return len(payload)
    if not isinstance(payload, dict):
        return 0

    counts: list[int] = []
    for key in entry_keys:
        value = payload.get(key)
        if isinstance(value, list):
            counts.append(len(value))

    if counts:
        return sum(counts)
    return 0


def _extract_traceability(
    rel_path: str,
    payload: Any,
    source: SourceSpec,
    overrides: dict[str, dict[str, str]],
) -> tuple[str, str]:
    if source.source_bead_id != "auto" and source.source_version != "auto":
        return source.source_bead_id, source.source_version

    override = overrides.get(rel_path)
    if override:
        bead = override.get("source_bead_id", "")
        version = override.get("source_version", "")
        if bead and version:
            return bead, version

    if isinstance(payload, dict):
        bead = (
            payload.get("bead_id")
            or payload.get("source_bead_id")
            or payload.get("bead")
            or ""
        )
        version = (
            payload.get("source_version")
            or payload.get("version")
            or payload.get("schema_version")
            or ""
        )
        bead_str = str(bead).strip()
        version_str = str(version).strip()
        if bead_str and version_str:
            return bead_str, version_str

    return "", ""


def _cross_runtime_summary(payload: Any, targets: tuple[str, ...]) -> dict[str, Any]:
    if not targets:
        return {
            "applicable": False,
            "status": "NOT_APPLICABLE",
            "targets": [],
            "observed_implementations": [],
            "detail": "No parity targets configured for source",
        }

    observed: set[str] = set()
    if isinstance(payload, dict):
        runtime_results = payload.get("runtime_results")
        if isinstance(runtime_results, dict):
            observed.update(str(k) for k in runtime_results.keys())

        for key in ("vectors", "test_vectors", "cases", "inclusion_cases", "prefix_cases"):
            rows = payload.get(key)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for impl_field in ("implementation", "runtime", "engine"):
                    value = row.get(impl_field)
                    if isinstance(value, str) and value.strip():
                        observed.add(value.strip())

    if not observed:
        return {
            "applicable": False,
            "status": "NOT_APPLICABLE",
            "targets": list(targets),
            "observed_implementations": [],
            "detail": "No runtime implementation metadata in vector payload",
        }

    missing_targets = sorted(set(targets) - observed)
    if missing_targets:
        return {
            "applicable": True,
            "status": "NOT_APPLICABLE",
            "targets": list(targets),
            "observed_implementations": sorted(observed),
            "detail": f"Observed runtime metadata but missing target(s): {', '.join(missing_targets)}",
        }

    return {
        "applicable": True,
        "status": "PASS",
        "targets": list(targets),
        "observed_implementations": sorted(observed),
        "detail": "Runtime metadata covers all parity targets",
    }


def _validate_json_target(
    target: Path,
    source: SourceSpec,
    root: Path,
    overrides: dict[str, dict[str, str]],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    rel_path = _relative(target, root)
    verified_at = _now_rfc3339()

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add_check("exists", target.is_file(), rel_path)
    payload: Any = None
    if target.is_file():
        try:
            payload = _load_json(target)
            add_check("json_parse", True, "Parsed JSON successfully")
        except json.JSONDecodeError as exc:
            add_check("json_parse", False, f"JSON parse failure: {exc}")
    else:
        add_check("json_parse", False, "Path is not a file")

    if payload is not None:
        for key in source.required_keys:
            add_check(f"required_key:{key}", isinstance(payload, dict) and key in payload, f"{key} present")

        entry_count = _entry_count(payload, source.entry_keys)
        add_check(
            "minimum_entries",
            entry_count >= source.minimum_entries,
            f"entries={entry_count} minimum={source.minimum_entries}",
        )
    else:
        entry_count = 0
        add_check("minimum_entries", False, "No payload available")

    bead_id, source_version = _extract_traceability(rel_path, payload, source, overrides)
    add_check(
        "traceability",
        bool(bead_id and source_version),
        f"source_bead_id={bead_id or '<missing>'} source_version={source_version or '<missing>'}",
    )

    cross_runtime = _cross_runtime_summary(payload, source.parity_targets) if payload is not None else {
        "applicable": False,
        "status": "NOT_APPLICABLE",
        "targets": list(source.parity_targets),
        "observed_implementations": [],
        "detail": "No payload available",
    }

    passed = all(check["passed"] for check in checks)
    return {
        "source_id": source.source_id,
        "source_section": source.section,
        "path": rel_path,
        "suite_kind": source.suite_kind,
        "status": "PASS" if passed else "FAIL",
        "required": source.required,
        "source_bead_id": bead_id,
        "source_version": source_version,
        "entry_count": entry_count,
        "verified_at": verified_at,
        "cross_runtime": cross_runtime,
        "checks": checks,
    }


def _validate_directory_target(target: Path, source: SourceSpec, root: Path) -> dict[str, Any]:
    rel_path = _relative(target, root)
    checks: list[dict[str, Any]] = []
    verified_at = _now_rfc3339()

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add_check("exists", target.exists(), rel_path)
    add_check("is_directory", target.is_dir(), rel_path)

    file_count = 0
    if target.is_dir():
        file_count = sum(1 for path in target.rglob("*") if path.is_file())
    add_check(
        "minimum_entries",
        file_count >= source.minimum_entries,
        f"files={file_count} minimum={source.minimum_entries}",
    )

    add_check(
        "traceability",
        bool(source.source_bead_id and source.source_version),
        f"source_bead_id={source.source_bead_id or '<missing>'} source_version={source.source_version or '<missing>'}",
    )

    passed = all(check["passed"] for check in checks)
    return {
        "source_id": source.source_id,
        "source_section": source.section,
        "path": rel_path,
        "suite_kind": source.suite_kind,
        "status": "PASS" if passed else "FAIL",
        "required": source.required,
        "source_bead_id": source.source_bead_id,
        "source_version": source.source_version,
        "entry_count": file_count,
        "verified_at": verified_at,
        "cross_runtime": {
            "applicable": False,
            "status": "NOT_APPLICABLE",
            "targets": [],
            "observed_implementations": [],
            "detail": "Directory corpus suite",
        },
        "checks": checks,
    }


def _validate_changelog(
    changelog_path: Path,
    manifest_version: str,
    discovered_paths: list[str],
    source_ids: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add_check("changelog_exists", changelog_path.is_file(), str(changelog_path))
    if not changelog_path.is_file():
        return checks

    text = _read_text(changelog_path)
    add_check(
        "changelog_has_manifest_version",
        manifest_version in text,
        f"version={manifest_version}",
    )

    for source_id in sorted(set(source_ids)):
        add_check(
            f"changelog_mentions_source:{source_id}",
            source_id in text,
            f"{source_id} present in changelog",
        )

    for rel_path in sorted(set(discovered_paths)):
        add_check(
            f"changelog_mentions_path:{rel_path}",
            rel_path in text,
            f"{rel_path} present in changelog",
        )

    return checks


def run_gate(
    manifest_path: Path = DEFAULT_MANIFEST,
    changelog_path: Path = DEFAULT_CHANGELOG,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add_check("manifest_exists", manifest_path.is_file(), str(manifest_path))
    if not manifest_path.is_file():
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "generated_at": _now_rfc3339(),
            "checks": checks,
            "sources": [],
            "vector_sets": [],
            "release_gate": {
                "verdict": "FAIL",
                "blocked_release": True,
                "blockers": ["ERR_CVG_MANIFEST_MISSING"],
            },
            "publication_gate": {
                "verdict": "FAIL",
                "blocked_publication": True,
                "reason": "Manifest missing",
            },
            "summary": {
                "sources_total": 0,
                "sources_passed": 0,
                "vector_sets_total": 0,
                "vector_sets_passed": 0,
                "checks_passed": sum(1 for c in checks if c["passed"]),
                "checks_total": len(checks),
            },
            "verdict": "FAIL",
            "checks_passed": sum(1 for c in checks if c["passed"]),
            "checks_total": len(checks),
        }

    try:
        manifest = _load_manifest(manifest_path)
        add_check("manifest_parse", True, "Parsed TOML manifest")
    except (OSError, tomllib.TOMLDecodeError) as exc:
        add_check("manifest_parse", False, f"TOML parse failure: {exc}")
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "generated_at": _now_rfc3339(),
            "checks": checks,
            "sources": [],
            "vector_sets": [],
            "release_gate": {
                "verdict": "FAIL",
                "blocked_release": True,
                "blockers": ["ERR_CVG_MANIFEST_INVALID"],
            },
            "publication_gate": {
                "verdict": "FAIL",
                "blocked_publication": True,
                "reason": "Manifest invalid",
            },
            "summary": {
                "sources_total": 0,
                "sources_passed": 0,
                "vector_sets_total": 0,
                "vector_sets_passed": 0,
                "checks_passed": sum(1 for c in checks if c["passed"]),
                "checks_total": len(checks),
            },
            "verdict": "FAIL",
            "checks_passed": sum(1 for c in checks if c["passed"]),
            "checks_total": len(checks),
        }

    parsed_sources = _parse_sources(manifest)
    add_check(
        "manifest_sources_present",
        len(parsed_sources) > 0,
        f"sources={len(parsed_sources)}",
    )
    overrides = _parse_overrides(manifest)

    source_results: list[dict[str, Any]] = []
    vector_sets: list[dict[str, Any]] = []
    discovered_paths: list[str] = []
    source_ids: list[str] = []

    for source in parsed_sources:
        source_ids.append(source.source_id)
        targets = _discover_targets(source, root)
        discovered_rel_paths = [_relative(path, root) for path in targets]
        discovered_paths.extend(discovered_rel_paths)

        source_checks: list[dict[str, Any]] = []

        def add_source_check(name: str, passed: bool, detail: str) -> None:
            source_checks.append({"check": name, "passed": passed, "detail": detail})

        add_source_check(
            "discovery_non_empty",
            len(targets) > 0,
            f"discovered={len(targets)}",
        )

        target_results: list[dict[str, Any]] = []
        for target in targets:
            if source.suite_kind == "directory_corpus":
                result = _validate_directory_target(target, source, root)
            else:
                result = _validate_json_target(target, source, root, overrides)
            target_results.append(result)
            vector_sets.append(result)

        passed_targets = sum(1 for item in target_results if item["status"] == "PASS")
        source_passed = bool(target_results) and passed_targets == len(target_results) and all(
            check["passed"] for check in source_checks
        )
        source_results.append(
            {
                "source_id": source.source_id,
                "section": source.section,
                "suite_kind": source.suite_kind,
                "required": source.required,
                "publication_tag": source.publication_tag,
                "status": "PASS" if source_passed else "FAIL",
                "verified_at": _now_rfc3339(),
                "discovered_count": len(target_results),
                "passed_count": passed_targets,
                "failed_count": len(target_results) - passed_targets,
                "checks": source_checks,
                "targets": target_results,
            }
        )

    changelog_checks = _validate_changelog(
        changelog_path=changelog_path,
        manifest_version=str(manifest.get("version", "")).strip(),
        discovered_paths=discovered_paths,
        source_ids=source_ids,
    )
    checks.extend(changelog_checks)

    failing_required_sources = [
        source["source_id"]
        for source in source_results
        if source["required"] and source["status"] != "PASS"
    ]
    changelog_failures = [check["check"] for check in changelog_checks if not check["passed"]]

    blockers = []
    blockers.extend(f"source:{item}" for item in failing_required_sources)
    blockers.extend(changelog_failures)

    release_pass = len(blockers) == 0
    release_gate = {
        "verdict": "PASS" if release_pass else "FAIL",
        "blocked_release": not release_pass,
        "blockers": blockers,
    }
    publication_gate = {
        "verdict": "PASS" if release_pass else "FAIL",
        "blocked_publication": not release_pass,
        "reason": (
            "All required canonical vector suites verified in current run"
            if release_pass
            else "Blocked by release gate failure"
        ),
    }

    checks_passed = sum(1 for check in checks if check["passed"])
    checks_total = len(checks)

    summary = {
        "sources_total": len(source_results),
        "sources_passed": sum(1 for source in source_results if source["status"] == "PASS"),
        "vector_sets_total": len(vector_sets),
        "vector_sets_passed": sum(1 for item in vector_sets if item["status"] == "PASS"),
        "checks_passed": checks_passed,
        "checks_total": checks_total,
    }

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "manifest": _relative(manifest_path.resolve(), root),
        "changelog": _relative(changelog_path.resolve(), root),
        "generated_at": _now_rfc3339(),
        "checks": checks,
        "sources": source_results,
        "vector_sets": vector_sets,
        "release_gate": release_gate,
        "publication_gate": publication_gate,
        "summary": summary,
        "checks_passed": checks_passed,
        "checks_total": checks_total,
        "verdict": "PASS" if release_pass else "FAIL",
    }


def self_test() -> bool:
    temp_dir = Path(tempfile.mkdtemp(prefix="canonical-vectors-self-test-"))
    try:
        (temp_dir / "vectors").mkdir(parents=True, exist_ok=True)
        manifest_path = temp_dir / "vectors" / "canonical_manifest.toml"
        changelog_path = temp_dir / "vectors" / "CHANGELOG.md"
        vector_path = temp_dir / "vectors" / "sample_vectors.json"

        vector_path.write_text(
            json.dumps(
                {
                    "bead_id": "bd-test",
                    "version": "1.0.0",
                    "vectors": [{"id": "v1", "implementation": "native"}],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        manifest_path.write_text(
            """
version = "1.0.0"

[[sources]]
source_id = "test-source"
section = "10.test"
source_bead_id = "auto"
source_version = "auto"
suite_kind = "json_vectors"
required = true
globs = ["vectors/*_vectors.json"]
entry_keys = ["vectors"]
required_keys = ["vectors"]
minimum_entries = 1
parity_targets = ["native"]
publication_tag = "test"
""".strip()
            + "\n",
            encoding="utf-8",
        )

        changelog_path.write_text(
            """
## [1.0.0] - 2026-02-22
- Source `test-source`: `vectors/sample_vectors.json`
""".strip()
            + "\n",
            encoding="utf-8",
        )

        result = run_gate(manifest_path, changelog_path, root=temp_dir)
        assert result["verdict"] == "PASS", "self-test pass fixture should pass"

        changelog_path.write_text("## [1.0.0] - 2026-02-22\n", encoding="utf-8")
        failing = run_gate(manifest_path, changelog_path, root=temp_dir)
        assert failing["verdict"] == "FAIL", "self-test changelog mutation should fail"
        return True
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    logger = configure_test_logging("check_canonical_vectors")
    parser = argparse.ArgumentParser(description="Verify canonical trust vector gate (bd-s6y)")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'}", file=sys.stderr)
        return 0 if ok else 1

    result = run_gate(args.manifest, args.changelog, root=args.root)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"{BEAD_ID} canonical vector gate: {result['verdict']} "
            f"({result['summary']['vector_sets_passed']}/{result['summary']['vector_sets_total']} vector sets)"
        )
        for source in result["sources"]:
            print(
                f"  [{source['status']}] {source['source_id']} "
                f"{source['passed_count']}/{source['discovered_count']}"
            )
        if result["release_gate"]["blocked_release"]:
            print("  blockers:")
            for blocker in result["release_gate"]["blockers"]:
                print(f"    - {blocker}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
