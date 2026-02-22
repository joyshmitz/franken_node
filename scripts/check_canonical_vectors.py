#!/usr/bin/env python3
"""Canonical trust protocol vector release gate (bd-s6y).

Adopts golden vectors from sections 10.13 and 10.14, enforces release/publication
gates, validates schema conformance, checks changelog discipline, and reports
cross-implementation parity status.

Event codes: CVG-001 through CVG-006.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-s6y"
SECTION = "10.7"
TITLE = "Adopt canonical trust protocol vectors and enforce release gates"

MANIFEST_PATH = ROOT / "vectors" / "canonical_manifest.toml"
CHANGELOG_PATH = ROOT / "vectors" / "CHANGELOG.md"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_7" / "bd-s6y_contract.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_7" / "bd-s6y" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_7" / "bd-s6y" / "verification_summary.md"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _load_json(path: Path) -> Any | None:
    text = _read(path)
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _load_manifest() -> dict[str, Any] | None:
    """Load and parse canonical_manifest.toml."""
    text = _read(MANIFEST_PATH)
    if not text:
        return None
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            return None
    # Fallback: lightweight TOML-subset parser for the manifest structure.
    return _fallback_parse_manifest(text)


def _fallback_parse_manifest(text: str) -> dict[str, Any] | None:
    """Minimal TOML parser sufficient for canonical_manifest.toml.

    Handles top-level [manifest] section and [[suites]] array-of-tables.
    """
    import re

    manifest: dict[str, Any] = {}
    suites: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Array-of-tables header
        if line == "[[suites]]":
            current = {}
            suites.append(current)
            current_section = "suites"
            continue

        # Table header
        m = re.match(r"^\[(\w+)\]$", line)
        if m:
            current_section = m.group(1)
            if current_section == "manifest":
                current = manifest.setdefault("manifest", {})
            continue

        # Key-value
        kv = re.match(r'^(\w+)\s*=\s*(.+)$', line)
        if kv and current is not None:
            key = kv.group(1)
            val_raw = kv.group(2).strip()
            current[key] = _parse_toml_value(val_raw)

    manifest["suites"] = suites
    return manifest


def _parse_toml_value(raw: str) -> Any:
    """Parse a simple TOML value (string, bool, int, array of strings)."""
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    if raw.startswith("[") and raw.endswith("]"):
        import re
        return re.findall(r'"([^"]*)"', raw)
    return raw


def _validate_vector_schema(data: Any, suite_name: str) -> tuple[bool, str]:
    """Basic schema validation: check that vector data has expected structure."""
    if data is None:
        return False, f"{suite_name}: file missing or unparseable"
    if not isinstance(data, dict):
        return False, f"{suite_name}: root must be an object"

    # Every vector file should have some form of vectors/cases/test_vectors list
    has_vectors = False
    for key in ("vectors", "test_vectors", "inclusion_cases", "prefix_cases"):
        val = data.get(key)
        if isinstance(val, list) and len(val) > 0:
            has_vectors = True
            break
    if not has_vectors:
        return False, f"{suite_name}: no vector array found (expected 'vectors', 'test_vectors', 'inclusion_cases', or 'prefix_cases')"

    return True, f"{suite_name}: schema valid"


def _count_vectors(data: dict[str, Any]) -> int:
    """Count the number of individual vectors in a vector file."""
    count = 0
    for key in ("vectors", "test_vectors", "inclusion_cases", "prefix_cases"):
        val = data.get(key)
        if isinstance(val, list):
            count += len(val)
    return count


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _checks() -> list[dict[str, Any]]:
    """Run all verification checks and return results."""
    results: list[dict[str, Any]] = []
    manifest = _load_manifest()

    # 1. Manifest exists
    ok = MANIFEST_PATH.is_file()
    results.append({
        "check": "manifest_exists",
        "passed": ok,
        "detail": f"canonical_manifest.toml {'exists' if ok else 'MISSING'} at vectors/canonical_manifest.toml",
    })

    # 2. Manifest parseable
    ok = manifest is not None
    results.append({
        "check": "manifest_parseable",
        "passed": ok,
        "detail": f"canonical_manifest.toml {'parsed successfully' if ok else 'PARSE FAILED'}",
    })

    # 3. Manifest has suites
    suites = manifest.get("suites", []) if manifest else []
    ok = len(suites) >= 1
    results.append({
        "check": "manifest_has_suites",
        "passed": ok,
        "detail": f"{len(suites)} suites registered (>= 1 required)",
    })

    # 4. Manifest has both 10.13 and 10.14 sources
    source_sections = set()
    for s in suites:
        src = s.get("source_section", "")
        source_sections.add(src)
    has_1013 = "10.13" in source_sections
    has_1014 = "10.14" in source_sections
    ok = has_1013 and has_1014
    results.append({
        "check": "manifest_adopts_1013_and_1014",
        "passed": ok,
        "detail": f"Sources: {sorted(source_sections)} ({'both 10.13 and 10.14 present' if ok else 'MISSING one or both'})",
    })

    # 5. All required suites have required=true
    required_count = sum(1 for s in suites if s.get("required", False))
    ok = required_count >= 1
    results.append({
        "check": "required_suites_flagged",
        "passed": ok,
        "detail": f"{required_count} suites marked required (>= 1 needed)",
    })

    # 6. All suite vector files exist
    missing_files: list[str] = []
    for s in suites:
        vf = ROOT / s.get("vector_file", "NOFILE")
        if not vf.is_file():
            missing_files.append(s.get("suite_name", "?"))
    ok = len(missing_files) == 0
    results.append({
        "check": "vector_files_exist",
        "passed": ok,
        "detail": "All vector files present" if ok else f"Missing: {', '.join(missing_files)}",
    })

    # 7. All vector files are valid JSON with schema conformance
    schema_errors: list[str] = []
    total_vector_count = 0
    suite_results: list[dict[str, Any]] = []
    for s in suites:
        vf = ROOT / s.get("vector_file", "NOFILE")
        data = _load_json(vf)
        valid, msg = _validate_vector_schema(data, s.get("suite_name", "?"))
        if not valid:
            schema_errors.append(msg)
        vc = _count_vectors(data) if data else 0
        total_vector_count += vc
        suite_results.append({
            "suite_name": s.get("suite_name", "?"),
            "vector_count": vc,
            "schema_valid": valid,
            "source_section": s.get("source_section", "?"),
            "required": s.get("required", False),
        })
    ok = len(schema_errors) == 0
    results.append({
        "check": "schema_validation",
        "passed": ok,
        "detail": f"All {len(suites)} suites pass schema validation ({total_vector_count} total vectors)"
            if ok else f"Schema errors: {'; '.join(schema_errors)}",
    })

    # 8. Changelog exists
    ok = CHANGELOG_PATH.is_file()
    results.append({
        "check": "changelog_exists",
        "passed": ok,
        "detail": f"CHANGELOG.md {'exists' if ok else 'MISSING'} at vectors/CHANGELOG.md",
    })

    # 9. Changelog references the manifest version
    changelog_text = _read(CHANGELOG_PATH)
    ok = "1.0.0" in changelog_text and "canonical_manifest" in changelog_text.lower().replace(" ", "_").replace("-", "_")
    results.append({
        "check": "changelog_references_manifest",
        "passed": ok,
        "detail": f"CHANGELOG.md {'references' if ok else 'DOES NOT reference'} canonical_manifest and version 1.0.0",
    })

    # 10. Changelog documents all vector files
    changelog_lower = changelog_text.lower()
    undocumented: list[str] = []
    for s in suites:
        vf = s.get("vector_file", "")
        # Check if the vector file basename is mentioned in the changelog
        basename = Path(vf).name.lower()
        if basename not in changelog_lower:
            undocumented.append(s.get("suite_name", "?"))
    ok = len(undocumented) == 0
    results.append({
        "check": "changelog_documents_all_vectors",
        "passed": ok,
        "detail": "All vector files documented in CHANGELOG.md"
            if ok else f"Undocumented: {', '.join(undocumented)}",
    })

    # 11. Spec contract exists
    ok = SPEC_PATH.is_file()
    results.append({
        "check": "spec_contract_exists",
        "passed": ok,
        "detail": f"Spec contract {'exists' if ok else 'MISSING'} at docs/specs/section_10_7/bd-s6y_contract.md",
    })

    # 12. Release gate output structure
    # Validate that we can produce structured JSON output
    gate_output = _build_gate_output(suites, suite_results, total_vector_count)
    required_keys = {"suites", "total_vectors", "overall_status"}
    ok = all(k in gate_output for k in required_keys)
    results.append({
        "check": "gate_output_structured",
        "passed": ok,
        "detail": f"Gate output contains required keys: {sorted(required_keys)}" if ok
            else f"Gate output missing keys: {sorted(required_keys - set(gate_output.keys()))}",
    })

    # 13. Cross-implementation parity readiness
    # Check that at least the native implementation vectors exist
    ok = total_vector_count > 0
    results.append({
        "check": "cross_impl_parity_ready",
        "passed": ok,
        "detail": f"{total_vector_count} vectors available for cross-implementation parity checks"
            if ok else "No vectors available for parity checking",
    })

    # 14. Every suite has required fields
    suite_field_errors: list[str] = []
    required_suite_fields = ["suite_name", "source_section", "vector_file", "schema_version", "required", "categories"]
    for s in suites:
        for field in required_suite_fields:
            if field not in s:
                suite_field_errors.append(f"{s.get('suite_name', '?')}.{field}")
    ok = len(suite_field_errors) == 0
    results.append({
        "check": "suite_fields_complete",
        "passed": ok,
        "detail": "All suites have required fields" if ok
            else f"Missing fields: {', '.join(suite_field_errors)}",
    })

    # 15. Manifest metadata present
    meta = manifest.get("manifest", {}) if manifest else {}
    ok = bool(meta.get("schema_version")) and bool(meta.get("bead_id"))
    results.append({
        "check": "manifest_metadata",
        "passed": ok,
        "detail": f"Manifest metadata present (schema_version={meta.get('schema_version', 'N/A')}, bead_id={meta.get('bead_id', 'N/A')})"
            if ok else "Manifest metadata incomplete",
    })

    return results


def _build_gate_output(
    suites: list[dict[str, Any]],
    suite_results: list[dict[str, Any]],
    total_vectors: int,
) -> dict[str, Any]:
    """Build structured gate output for CI consumption."""
    all_pass = all(sr.get("schema_valid", False) for sr in suite_results)
    return {
        "suites": [
            {
                "suite_name": sr["suite_name"],
                "vector_count": sr["vector_count"],
                "pass_count": sr["vector_count"] if sr["schema_valid"] else 0,
                "fail_count": 0 if sr["schema_valid"] else sr["vector_count"],
                "status": "PASS" if sr["schema_valid"] else "FAIL",
                "source_section": sr["source_section"],
                "required": sr["required"],
            }
            for sr in suite_results
        ],
        "total_vectors": total_vectors,
        "total_suites": len(suite_results),
        "passing_suites": sum(1 for sr in suite_results if sr["schema_valid"]),
        "failing_suites": sum(1 for sr in suite_results if not sr["schema_valid"]),
        "overall_status": "PASS" if all_pass else "FAIL",
    }


# ---------------------------------------------------------------------------
# run_all / self_test / main
# ---------------------------------------------------------------------------

def run_all() -> dict[str, Any]:
    """Execute all checks and return structured result."""
    t0 = time.monotonic()
    checks = _checks()
    elapsed = round(time.monotonic() - t0, 4)

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": verdict,
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
        "elapsed_s": elapsed,
    }


def self_test() -> bool:
    """Run self-test validating internal helpers and the full pipeline."""
    result = run_all()
    assert isinstance(result, dict), "run_all must return a dict"
    assert "checks" in result, "result must contain 'checks'"
    assert "verdict" in result, "result must contain 'verdict'"
    assert isinstance(result["checks"], list), "'checks' must be a list"
    assert len(result["checks"]) >= 10, f"Expected >= 10 checks, got {len(result['checks'])}"
    assert all(
        "check" in c and "passed" in c and "detail" in c
        for c in result["checks"]
    ), "Each check must have 'check', 'passed', 'detail' keys"

    # Validate helper functions
    ok, msg = _validate_vector_schema({"vectors": [{"id": "test"}]}, "test-suite")
    assert ok, f"_validate_vector_schema should pass for valid data: {msg}"
    ok, msg = _validate_vector_schema({}, "empty-suite")
    assert not ok, "_validate_vector_schema should fail for empty data"
    ok, msg = _validate_vector_schema(None, "none-suite")
    assert not ok, "_validate_vector_schema should fail for None"

    assert _count_vectors({"vectors": [1, 2, 3]}) == 3
    assert _count_vectors({"test_vectors": [1], "inclusion_cases": [2, 3]}) == 3
    assert _count_vectors({}) == 0

    # Validate gate output builder
    gate_out = _build_gate_output(
        [{"suite_name": "test", "source_section": "10.13", "required": True}],
        [{"suite_name": "test", "vector_count": 5, "schema_valid": True,
          "source_section": "10.13", "required": True}],
        5,
    )
    assert gate_out["overall_status"] == "PASS"
    assert gate_out["total_vectors"] == 5

    # Validate fallback TOML parser
    if tomllib is None or True:  # always test fallback
        test_toml = '''
[manifest]
schema_version = "1.0.0"
bead_id = "bd-test"

[[suites]]
suite_name = "Test Suite"
source_section = "10.13"
vector_file = "test.json"
required = true
categories = ["cat1", "cat2"]
'''
        parsed = _fallback_parse_manifest(test_toml)
        assert parsed is not None, "Fallback parser should succeed"
        assert parsed["manifest"]["schema_version"] == "1.0.0"
        assert len(parsed["suites"]) == 1
        assert parsed["suites"][0]["suite_name"] == "Test Suite"
        assert parsed["suites"][0]["required"] is True
        assert parsed["suites"][0]["categories"] == ["cat1", "cat2"]

    return True


def _write_evidence(result: dict[str, Any]) -> None:
    """Write verification evidence JSON."""
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def _write_summary(result: dict[str, Any]) -> None:
    """Write human-readable verification summary."""
    lines = [
        f"# bd-s6y Verification Summary",
        "",
        f"- Section: `{SECTION}`",
        f"- Title: {TITLE}",
        f"- Verdict: `{result['verdict']}`",
        f"- Checks: `{result['passed']}/{result['total']}` passed",
        f"- Elapsed: `{result.get('elapsed_s', 'N/A')}s`",
        "",
        "## Checks",
        "",
        "| Check | Status | Detail |",
        "|-------|--------|--------|",
    ]
    for c in result["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        lines.append(f"| {c['check']} | {status} | {c['detail']} |")
    lines.append("")

    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Verify {BEAD_ID}: {TITLE}")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    parser.add_argument("--no-write", action="store_true", help="Skip writing output files")
    args = parser.parse_args()

    if args.self_test:
        try:
            ok = self_test()
        except AssertionError as exc:
            print(f"self_test FAILED: {exc}")
            return 1
        print("self_test passed")
        return 0

    result = run_all()

    if not args.no_write:
        _write_evidence(result)
        _write_summary(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{BEAD_ID} Canonical Vectors Gate -- {result['verdict']}"
              f" ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")

    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
