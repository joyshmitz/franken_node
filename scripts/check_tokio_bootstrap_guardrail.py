#!/usr/bin/env python3
"""Detect unjustified Tokio bootstrap/runtime reintroduction in frankenengine-node.

Usage:
    python3 scripts/check_tokio_bootstrap_guardrail.py
    python3 scripts/check_tokio_bootstrap_guardrail.py --json
    python3 scripts/check_tokio_bootstrap_guardrail.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


BEAD_ID = "bd-1now.3.1"
TITLE = "Implement deterministic Tokio/bootstrap drift checker and explicit exception path"
SOURCE_ROOT = Path(
    os.environ.get(
        "TOKIO_BOOTSTRAP_GUARDRAIL_SOURCE_ROOT",
        str(ROOT / "crates" / "franken-node" / "src"),
    )
)
BLUEPRINT = Path(
    os.environ.get(
        "TOKIO_BOOTSTRAP_GUARDRAIL_BLUEPRINT",
        str(ROOT / "docs" / "architecture" / "blueprint.md"),
    )
)
BLUEPRINT_SECTION = "## 8.6 Selective Asupersync Leverage Decision Record"
EXCEPTION_SECTION = "### Runtime Guardrail Exception Path"
SCAN_EXCLUDED_DIRS = {"testing"}
APPROVED_EXCEPTION_FILES: dict[str, str] = {}

EXCEPTION_GUIDANCE = (
    "If a real async boundary now exists, update "
    "docs/architecture/blueprint.md (Selective Asupersync decision record + "
    "Runtime Guardrail Exception Path), then add an intentional exception entry "
    "to scripts/check_tokio_bootstrap_guardrail.py and land matching proof in "
    "bd-1now.3.2 or its successor."
)


class RuleSpec(NamedTuple):
    rule_id: str
    reason_code: str
    description: str
    pattern: re.Pattern[str]


DIRECT_RULES = (
    RuleSpec(
        "tokio-attr-main",
        "TKG-001",
        "tokio bootstrap attribute recreates an ambient executor shell",
        re.compile(r"#\s*\[\s*tokio\s*::\s*main\b"),
    ),
    RuleSpec(
        "tokio-runtime-direct",
        "TKG-002",
        "direct tokio runtime constructor recreates a hidden executor shell",
        re.compile(r"tokio\s*::\s*runtime\s*::\s*Runtime\s*::\s*new\s*\("),
    ),
    RuleSpec(
        "tokio-builder-direct-current-thread",
        "TKG-003",
        "direct tokio runtime builder recreates an ambient executor shell",
        re.compile(r"tokio\s*::\s*runtime\s*::\s*Builder\s*::\s*new_current_thread\s*\("),
    ),
    RuleSpec(
        "tokio-builder-direct-multi-thread",
        "TKG-004",
        "direct multi-thread tokio builder recreates an ambient executor shell",
        re.compile(r"tokio\s*::\s*runtime\s*::\s*Builder\s*::\s*new_multi_thread\s*\("),
    ),
)

USE_RUNTIME_RE = re.compile(r"\buse\s+tokio\s*::\s*runtime\s*::\s*(\{[^;]+\}|[^;]+);")


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "pass": bool(passed), "detail": detail}


def _normalize_rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _iter_source_files() -> list[Path]:
    files: list[Path] = []
    for path in sorted(SOURCE_ROOT.rglob("*.rs")):
        if any(part in SCAN_EXCLUDED_DIRS for part in path.relative_to(SOURCE_ROOT).parts):
            continue
        files.append(path)
    return files


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset)
    col = offset + 1 if line_start == -1 else offset - line_start
    return line, col


def _line_excerpt(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def _strip_rust_non_code(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    block_depth = 0
    in_line_comment = False
    in_string = False
    string_quote = '"'
    escape = False
    raw_hashes = 0

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        if block_depth:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.extend((" ", " "))
                i += 2
                continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                out.extend((" ", " "))
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if in_string:
            if raw_hashes:
                closing = '"' + ("#" * raw_hashes)
                if text.startswith(closing, i):
                    out.extend(" " * len(closing))
                    i += len(closing)
                    in_string = False
                    raw_hashes = 0
                    continue
                out.append("\n" if ch == "\n" else " ")
                i += 1
                continue

            if escape:
                out.append(" " if ch != "\n" else "\n")
                escape = False
                i += 1
                continue
            if ch == "\\":
                out.append(" ")
                escape = True
                i += 1
                continue
            out.append("\n" if ch == "\n" else " ")
            if ch == string_quote:
                in_string = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            out.extend((" ", " "))
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_depth = 1
            out.extend((" ", " "))
            i += 2
            continue
        if ch == '"':
            in_string = True
            string_quote = '"'
            out.append(" ")
            i += 1
            continue
        if ch == "r":
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                in_string = True
                raw_hashes = hashes
                out.extend(" " * (j - i + 1))
                i = j + 1
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def _parse_tokio_runtime_aliases(sanitized: str) -> tuple[set[str], set[str]]:
    builder_aliases: set[str] = set()
    runtime_aliases: set[str] = set()

    for match in USE_RUNTIME_RE.finditer(sanitized):
        imports = match.group(1).strip()
        entries: list[str]
        if imports.startswith("{") and imports.endswith("}"):
            entries = [part.strip() for part in imports[1:-1].split(",")]
        else:
            entries = [imports]

        for entry in entries:
            if not entry or entry == "self":
                continue
            if " as " in entry:
                base, alias = [part.strip() for part in entry.split(" as ", 1)]
            else:
                base, alias = entry.strip(), entry.strip()
            if base == "Builder":
                builder_aliases.add(alias)
            elif base == "Runtime":
                runtime_aliases.add(alias)

    return builder_aliases, runtime_aliases


def _collect_alias_rule_matches(
    sanitized: str,
    aliases: set[str],
    method: str,
    rule_id: str,
    reason_code: str,
    description: str,
) -> list[tuple[RuleSpec, re.Match[str]]]:
    matches: list[tuple[RuleSpec, re.Match[str]]] = []
    for alias in sorted(aliases):
        pattern = re.compile(rf"\b{re.escape(alias)}\s*::\s*{re.escape(method)}\s*\(")
        spec = RuleSpec(rule_id, reason_code, description, pattern)
        for match in pattern.finditer(sanitized):
            matches.append((spec, match))
    return matches


def _scan_source(raw: str, rel: str) -> list[dict[str, Any]]:
    sanitized = _strip_rust_non_code(raw)
    builder_aliases, runtime_aliases = _parse_tokio_runtime_aliases(sanitized)

    matches: list[tuple[RuleSpec, re.Match[str]]] = []
    for spec in DIRECT_RULES:
        matches.extend((spec, match) for match in spec.pattern.finditer(sanitized))

    matches.extend(
        _collect_alias_rule_matches(
            sanitized,
            runtime_aliases,
            "new",
            "tokio-runtime-aliased",
            "TKG-005",
            "aliased tokio Runtime::new recreates a hidden executor shell",
        )
    )
    matches.extend(
        _collect_alias_rule_matches(
            sanitized,
            builder_aliases,
            "new_current_thread",
            "tokio-builder-aliased-current-thread",
            "TKG-006",
            "aliased tokio Builder::new_current_thread recreates an ambient executor shell",
        )
    )
    matches.extend(
        _collect_alias_rule_matches(
            sanitized,
            builder_aliases,
            "new_multi_thread",
            "tokio-builder-aliased-multi-thread",
            "TKG-007",
            "aliased tokio Builder::new_multi_thread recreates an ambient executor shell",
        )
    )

    seen: set[tuple[str, int, int]] = set()
    violations: list[dict[str, Any]] = []
    for spec, match in matches:
        line, col = _line_col(raw, match.start())
        key = (spec.rule_id, line, col)
        if key in seen:
            continue
        seen.add(key)
        violations.append(
            {
                "path": rel,
                "line": line,
                "column": col,
                "rule_id": spec.rule_id,
                "reason_code": spec.reason_code,
                "description": spec.description,
                "excerpt": _line_excerpt(raw, line),
                "remediation": EXCEPTION_GUIDANCE,
                "approved_exception": rel in APPROVED_EXCEPTION_FILES,
            }
        )
    return violations


def _scan_file(path: Path) -> list[dict[str, Any]]:
    return _scan_source(path.read_text(encoding="utf-8"), _normalize_rel(path))


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    blueprint_text = BLUEPRINT.read_text(encoding="utf-8") if BLUEPRINT.is_file() else ""

    checks.append(
        _check(
            "source_root_exists",
            SOURCE_ROOT.is_dir(),
            f"path={_normalize_rel(SOURCE_ROOT)}",
        )
    )
    checks.append(
        _check(
            "blueprint_decision_record_present",
            BLUEPRINT_SECTION in blueprint_text,
            f"path={_normalize_rel(BLUEPRINT)} section={'present' if BLUEPRINT_SECTION in blueprint_text else 'missing'}",
        )
    )
    checks.append(
        _check(
            "blueprint_exception_path_present",
            EXCEPTION_SECTION in blueprint_text,
            f"path={_normalize_rel(BLUEPRINT)} section={'present' if EXCEPTION_SECTION in blueprint_text else 'missing'}",
        )
    )

    source_files = _iter_source_files()
    checks.append(
        _check(
            "source_scan_has_coverage",
            len(source_files) > 0,
            f"scanned_files={len(source_files)} excluded_dirs={sorted(SCAN_EXCLUDED_DIRS)}",
        )
    )

    bad_exceptions = [
        rel for rel, reason in APPROVED_EXCEPTION_FILES.items() if not reason.strip()
    ]
    missing_exception_paths = [
        rel for rel in APPROVED_EXCEPTION_FILES if not (ROOT / rel).is_file()
    ]
    checks.append(
        _check(
            "exception_registry_consistent",
            not bad_exceptions and not missing_exception_paths,
            f"blank_reasons={bad_exceptions} missing_paths={missing_exception_paths}",
        )
    )

    all_violations: list[dict[str, Any]] = []
    for path in source_files:
        all_violations.extend(_scan_file(path))

    unapproved = [item for item in all_violations if not item["approved_exception"]]
    approved = [item for item in all_violations if item["approved_exception"]]
    checks.append(
        _check(
            "no_unapproved_tokio_bootstrap_patterns",
            len(unapproved) == 0,
            f"unapproved_violations={len(unapproved)} approved_exception_hits={len(approved)}",
        )
    )

    checks.append(
        _check(
            "rule_catalog_present",
            len(DIRECT_RULES) >= 4,
            f"rules={[rule.rule_id for rule in DIRECT_RULES]}",
        )
    )

    passed = sum(1 for item in checks if item["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "checks": checks,
        "violations": unapproved + approved,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "overall_pass": failed == 0,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "metrics": {
            "scanned_files": len(source_files),
            "excluded_dirs": sorted(SCAN_EXCLUDED_DIRS),
            "rule_count": len(DIRECT_RULES) + 3,
            "unapproved_violation_count": len(unapproved),
            "approved_exception_count": len(approved),
            "registered_exceptions": len(APPROVED_EXCEPTION_FILES),
        },
        "exception_path": {
            "blueprint": _normalize_rel(BLUEPRINT),
            "section": EXCEPTION_SECTION,
            "guidance": EXCEPTION_GUIDANCE,
        },
    }


def self_test() -> bool:
    sample = """\
use tokio::runtime::{Builder as TokioBuilder, Runtime};
// #[tokio::main]
const MESSAGE: &str = "#[tokio::main]";
#[tokio::main]
async fn main() {}
fn build() {
    let _ = TokioBuilder::new_current_thread();
    let _ = Runtime::new();
}
"""
    sanitized = _strip_rust_non_code(sample)
    assert sanitized.count("#[tokio::main]") == 1
    assert "const MESSAGE" in sanitized
    builder_aliases, runtime_aliases = _parse_tokio_runtime_aliases(sanitized)
    assert builder_aliases == {"TokioBuilder"}
    assert runtime_aliases == {"Runtime"}
    sample_violations = _scan_source(sample, "sample.rs")
    assert [item["reason_code"] for item in sample_violations] == [
        "TKG-001",
        "TKG-005",
        "TKG-006",
    ]

    result = run_all()
    assert result["bead_id"] == BEAD_ID
    assert result["exception_path"]["section"] == EXCEPTION_SECTION
    assert isinstance(result["violations"], list)
    # The live tree should currently be clean after bd-1now.2.
    assert result["metrics"]["unapproved_violation_count"] == len(
        [item for item in result["violations"] if not item["approved_exception"]]
    )
    return True


def main() -> None:
    logger = configure_test_logging("check_tokio_bootstrap_guardrail")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run built-in self test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    logger.info(
        "running tokio bootstrap guardrail",
        extra={
            "bead_id": BEAD_ID,
            "source_root": _normalize_rel(SOURCE_ROOT),
            "exception_registry_size": len(APPROVED_EXCEPTION_FILES),
        },
    )

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")
        if result["violations"]:
            print("\nViolations:")
            for violation in result["violations"]:
                marker = "APPROVED-EXCEPTION" if violation["approved_exception"] else "FAIL"
                print(
                    f"- [{marker}] {violation['reason_code']} {violation['rule_id']} "
                    f"{violation['path']}:{violation['line']}:{violation['column']}"
                )
                print(f"  {violation['description']}")
                if violation["excerpt"]:
                    print(f"  excerpt: {violation['excerpt']}")
        print(f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}")
        if not result["overall_pass"]:
            print(f"Remediation: {EXCEPTION_GUIDANCE}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
