#!/usr/bin/env python3
"""
Repository Split Contract CI Enforcement.

Verifies that franken_node correctly consumes engine crates from
/dp/franken_engine and does not reintroduce local engine crate copies.

Usage:
    python3 scripts/check_split_contract.py [--json]

Exit codes:
    0 = PASS (all checks pass)
    1 = FAIL (one or more violations)
    2 = ERROR (script failure)
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Directories that must NOT exist (local engine crate reintroduction)
FORBIDDEN_DIRS = [
    ROOT / "crates" / "franken-engine",
    ROOT / "crates" / "franken-extension-host",
]

# Required governance documents
REQUIRED_DOCS = [
    ROOT / "docs" / "ENGINE_SPLIT_CONTRACT.md",
    ROOT / "docs" / "PRODUCT_CHARTER.md",
]

# Expected engine path prefix in Cargo.toml dependencies
ENGINE_PATH_PREFIX = "../../../franken_engine/crates/"

# Engine crate names to check
ENGINE_CRATE_NAMES = [
    "frankenengine-engine",
    "frankenengine-extension-host",
]

# Keywords that must appear in ENGINE_SPLIT_CONTRACT.md
SPLIT_CONTRACT_KEYWORDS = [
    "franken_engine",
    "MUST NOT",
    "path dependencies",
]


def check_no_local_engine_crates() -> dict:
    """Verify no local engine crate directories exist."""
    result = {"id": "SPLIT-NO-LOCAL", "status": "PASS", "details": {}}
    violations = []
    for d in FORBIDDEN_DIRS:
        if d.exists():
            violations.append(str(d.relative_to(ROOT)))
    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove local engine crate directories. Engine crates must "
            "come from /dp/franken_engine via path dependencies."
        )
    else:
        result["details"]["checked"] = [str(d.relative_to(ROOT)) for d in FORBIDDEN_DIRS]
    return result


def check_engine_path_deps() -> dict:
    """Verify engine dependencies use correct path references."""
    result = {"id": "SPLIT-PATH-DEPS", "status": "PASS", "details": {"cargo_files": []}}

    cargo_files = list(ROOT.rglob("Cargo.toml"))
    # Exclude target/ and .beads/
    cargo_files = [
        f for f in cargo_files
        if "target" not in f.parts and ".beads" not in f.parts
    ]

    for cargo_file in cargo_files:
        try:
            content = cargo_file.read_text()
        except Exception as e:
            result["status"] = "FAIL"
            result["details"]["error"] = f"Cannot read {cargo_file}: {e}"
            return result

        file_info = {"path": str(cargo_file.relative_to(ROOT)), "engine_deps": []}

        for crate_name in ENGINE_CRATE_NAMES:
            # Match patterns like: frankenengine-engine = { path = "..." }
            pattern = rf'{re.escape(crate_name)}\s*=\s*\{{[^}}]*path\s*=\s*"([^"]*)"'
            matches = re.findall(pattern, content)
            for match_path in matches:
                dep_info = {"crate": crate_name, "path": match_path}
                if ENGINE_PATH_PREFIX not in match_path and "franken_engine/crates/" not in match_path:
                    dep_info["valid"] = False
                    dep_info["remediation"] = (
                        f"Path should reference {ENGINE_PATH_PREFIX}{crate_name.replace('frankenengine-', 'franken-')}"
                    )
                    result["status"] = "FAIL"
                else:
                    dep_info["valid"] = True
                file_info["engine_deps"].append(dep_info)

        if file_info["engine_deps"]:
            result["details"]["cargo_files"].append(file_info)

    return result


def check_no_engine_internal_imports() -> dict:
    """Verify no Rust source files import engine-internal modules."""
    result = {"id": "SPLIT-NO-INTERNALS", "status": "PASS", "details": {"files_scanned": 0}}

    # Patterns that suggest direct engine-internal access
    internal_patterns = [
        r'use\s+frankenengine_engine::internal',
        r'use\s+frankenengine_extension_host::internal',
        r'mod\s+franken_engine',
        r'mod\s+franken_extension_host',
    ]

    violations = []
    rs_files = list((ROOT / "crates").rglob("*.rs")) if (ROOT / "crates").exists() else []
    # Also check src/ if it exists
    if (ROOT / "src").exists():
        rs_files.extend((ROOT / "src").rglob("*.rs"))

    result["details"]["files_scanned"] = len(rs_files)

    for rs_file in rs_files:
        try:
            content = rs_file.read_text()
        except Exception:
            continue
        for pattern in internal_patterns:
            if re.search(pattern, content):
                violations.append({
                    "file": str(rs_file.relative_to(ROOT)),
                    "pattern": pattern,
                })

    if violations:
        result["status"] = "FAIL"
        result["details"]["violations"] = violations
        result["details"]["remediation"] = (
            "Remove direct engine-internal imports. Use only the public API surface."
        )

    return result


def check_governance_docs() -> dict:
    """Verify required governance documents exist with expected content."""
    result = {"id": "SPLIT-GOVERNANCE", "status": "PASS", "details": {"docs": []}}

    for doc_path in REQUIRED_DOCS:
        doc_info = {"path": str(doc_path.relative_to(ROOT)), "exists": doc_path.exists()}
        if not doc_path.exists():
            result["status"] = "FAIL"
            doc_info["error"] = "File not found"
        result["details"]["docs"].append(doc_info)

    # Verify split contract has required keywords
    split_path = ROOT / "docs" / "ENGINE_SPLIT_CONTRACT.md"
    if split_path.exists():
        content = split_path.read_text()
        missing_keywords = []
        for kw in SPLIT_CONTRACT_KEYWORDS:
            if kw.lower() not in content.lower():
                missing_keywords.append(kw)
        if missing_keywords:
            result["status"] = "FAIL"
            result["details"]["missing_keywords"] = missing_keywords

    return result


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_no_local_engine_crates(),
        check_engine_path_deps(),
        check_no_engine_internal_imports(),
        check_governance_docs(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "split_contract_enforcement",
        "section": "10.1",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Repository Split Contract CI Enforcement ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "violations" in details:
                    for v in details["violations"][:5]:
                        print(f"       Violation: {v}")
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "remediation" in details:
                    print(f"       Fix: {details['remediation']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
