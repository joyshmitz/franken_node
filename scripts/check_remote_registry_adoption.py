#!/usr/bin/env python3
"""
Remote Registry Adoption Verification (bd-3014).

Validates that the canonical remote named-computation registry from bd-ac83
is properly integrated into the control-plane via adoption documentation,
adoption report artifact, and absence of divergent registries.

Usage:
    python3 scripts/check_remote_registry_adoption.py [--json] [--self-test]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# --- Constants ---

REGISTRY_SRC = ROOT / "crates" / "franken-node" / "src" / "remote" / "computation_registry.rs"
ADOPTION_DOC = ROOT / "docs" / "integration" / "control_remote_registry_adoption.md"
ADOPTION_REPORT = ROOT / "artifacts" / "10.15" / "remote_registry_adoption_report.json"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-3014_contract.md"
TEST_FILE = ROOT / "tests" / "test_check_remote_registry_adoption.py"

REQUIRED_COMPUTATION_NAMES = [
    "connector.health_probe.v1",
    "connector.rollout_notify.v1",
    "connector.fencing_acquire.v1",
    "connector.migration_step.v1",
    "federation.sync_delta.v1",
]

CONNECTOR_DIR = ROOT / "crates" / "franken-node" / "src" / "connector"
FEDERATION_DIR = ROOT / "crates" / "franken-node" / "src" / "federation"

# Patterns that indicate a divergent name-to-handler mapping.
# We scan for HashMap<String, ...Handler/Fn/Box...> patterns in connector/federation code.
DIVERGENT_PATTERNS = [
    "HashMap<String, Box<dyn",
    "HashMap<String, fn(",
    "HashMap<String, Handler",
    "HashMap<&str, Box<dyn",
    "HashMap<&str, fn(",
    "BTreeMap<String, Box<dyn",
    "BTreeMap<String, fn(",
]


def check_registry_source_exists() -> dict:
    """CRA-SRC: Computation registry source file exists."""
    exists = REGISTRY_SRC.exists()
    return {
        "id": "CRA-SRC",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(REGISTRY_SRC.relative_to(ROOT))},
    }


def check_adoption_doc_exists() -> dict:
    """CRA-DOC: Adoption document exists."""
    exists = ADOPTION_DOC.exists()
    return {
        "id": "CRA-DOC",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(ADOPTION_DOC.relative_to(ROOT))},
    }


def check_adoption_report_exists() -> dict:
    """CRA-REPORT: Adoption report artifact exists and is valid JSON."""
    if not ADOPTION_REPORT.exists():
        return {
            "id": "CRA-REPORT",
            "status": "FAIL",
            "details": {"error": "file not found"},
        }
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        has_bead = data.get("bead") == "bd-3014"
        has_computations = isinstance(data.get("registered_computations"), list)
        has_status = data.get("adoption_status") == "documented"
        ok = has_bead and has_computations and has_status
        return {
            "id": "CRA-REPORT",
            "status": "PASS" if ok else "FAIL",
            "details": {
                "has_bead": has_bead,
                "has_computations": has_computations,
                "has_status": has_status,
            },
        }
    except json.JSONDecodeError as e:
        return {
            "id": "CRA-REPORT",
            "status": "FAIL",
            "details": {"error": f"invalid JSON: {e}"},
        }


def check_computation_names_documented() -> dict:
    """CRA-NAMES: All required computation names appear in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {
            "id": "CRA-NAMES",
            "status": "FAIL",
            "details": {"error": "adoption doc not found"},
        }
    content = ADOPTION_DOC.read_text()
    missing = [n for n in REQUIRED_COMPUTATION_NAMES if n not in content]
    return {
        "id": "CRA-NAMES",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(REQUIRED_COMPUTATION_NAMES)},
    }


def check_error_code_in_registry() -> dict:
    """CRA-ERRCODE: ERR_UNKNOWN_COMPUTATION error code defined in registry source."""
    if not REGISTRY_SRC.exists():
        return {
            "id": "CRA-ERRCODE",
            "status": "FAIL",
            "details": {"error": "registry source not found"},
        }
    content = REGISTRY_SRC.read_text()
    has_code = "ERR_UNKNOWN_COMPUTATION" in content
    return {
        "id": "CRA-ERRCODE",
        "status": "PASS" if has_code else "FAIL",
        "details": {"found": has_code},
    }


def check_validate_method_exists() -> dict:
    """CRA-VALIDATE: validate_computation_name method exists in registry source."""
    if not REGISTRY_SRC.exists():
        return {
            "id": "CRA-VALIDATE",
            "status": "FAIL",
            "details": {"error": "registry source not found"},
        }
    content = REGISTRY_SRC.read_text()
    has_method = "validate_computation_name" in content
    return {
        "id": "CRA-VALIDATE",
        "status": "PASS" if has_method else "FAIL",
        "details": {"found": has_method},
    }


def check_no_divergent_registries() -> dict:
    """CRA-DIVERGENT: No divergent name-to-handler mappings in connector/federation."""
    violations = []
    dirs_to_scan = []
    if CONNECTOR_DIR.exists():
        dirs_to_scan.append(CONNECTOR_DIR)
    if FEDERATION_DIR.exists():
        dirs_to_scan.append(FEDERATION_DIR)

    for scan_dir in dirs_to_scan:
        for rs_file in sorted(scan_dir.glob("*.rs")):
            content = rs_file.read_text()
            for pattern in DIVERGENT_PATTERNS:
                if pattern in content:
                    violations.append({
                        "file": str(rs_file.relative_to(ROOT)),
                        "pattern": pattern,
                    })

    return {
        "id": "CRA-DIVERGENT",
        "status": "PASS" if not violations else "FAIL",
        "details": {"violations": violations},
    }


def check_spec_contract_exists() -> dict:
    """CRA-SPEC: Spec contract document exists."""
    exists = SPEC_CONTRACT.exists()
    return {
        "id": "CRA-SPEC",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))},
    }


def check_test_file_exists() -> dict:
    """CRA-TESTS: Unit test file exists."""
    exists = TEST_FILE.exists()
    return {
        "id": "CRA-TESTS",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(TEST_FILE.relative_to(ROOT))},
    }


def check_adoption_doc_content() -> dict:
    """CRA-CONTENT: Adoption doc contains key sections."""
    if not ADOPTION_DOC.exists():
        return {
            "id": "CRA-CONTENT",
            "status": "FAIL",
            "details": {"error": "adoption doc not found"},
        }
    content = ADOPTION_DOC.read_text()
    required_sections = [
        "Fail-Closed Contract",
        "Prohibition on Divergent Registries",
        "Error Handling",
        "Registered Computations",
        "Invariants",
    ]
    missing = [s for s in required_sections if s not in content]
    return {
        "id": "CRA-CONTENT",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_report_computation_count() -> dict:
    """CRA-COUNT: Adoption report lists all 5 computations."""
    if not ADOPTION_REPORT.exists():
        return {
            "id": "CRA-COUNT",
            "status": "FAIL",
            "details": {"error": "report not found"},
        }
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        computations = data.get("registered_computations", [])
        names = [c.get("name") for c in computations]
        missing = [n for n in REQUIRED_COMPUTATION_NAMES if n not in names]
        return {
            "id": "CRA-COUNT",
            "status": "PASS" if not missing else "FAIL",
            "details": {"count": len(computations), "missing": missing},
        }
    except json.JSONDecodeError as e:
        return {
            "id": "CRA-COUNT",
            "status": "FAIL",
            "details": {"error": str(e)},
        }


def check_canonical_naming_function() -> dict:
    """CRA-NAMING: is_canonical_computation_name function exists in registry."""
    if not REGISTRY_SRC.exists():
        return {
            "id": "CRA-NAMING",
            "status": "FAIL",
            "details": {"error": "registry source not found"},
        }
    content = REGISTRY_SRC.read_text()
    has_fn = "is_canonical_computation_name" in content
    return {
        "id": "CRA-NAMING",
        "status": "PASS" if has_fn else "FAIL",
        "details": {"found": has_fn},
    }


def self_test() -> dict:
    """Run all checks."""
    checks = [
        check_registry_source_exists(),
        check_adoption_doc_exists(),
        check_adoption_report_exists(),
        check_computation_names_documented(),
        check_error_code_in_registry(),
        check_validate_method_exists(),
        check_no_divergent_registries(),
        check_spec_contract_exists(),
        check_test_file_exists(),
        check_adoption_doc_content(),
        check_report_computation_count(),
        check_canonical_naming_function(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "remote_registry_adoption_verification",
        "bead": "bd-3014",
        "section": "10.15",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_remote_registry_adoption")
    json_output = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    if run_self_test:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)
    else:
        result = self_test()
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
            print(f"\nVerdict: {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
