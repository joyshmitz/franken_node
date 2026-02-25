#!/usr/bin/env python3
"""Validate frankentui integration contract coverage and checklist completeness (bd-34ll)."""

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

CONTRACT_PATH = ROOT / "docs" / "specs" / "frankentui_integration_contract.md"
CHECKLIST_PATH = ROOT / "artifacts" / "10.16" / "frankentui_contract_checklist.json"
MODULE_ROOT = ROOT / "crates" / "franken-node" / "src"

REQUIRED_CONTRACT_SECTIONS = [
    "## Component Boundaries",
    "## Styling and Token Strategy",
    "## Rendering + Event Loop Contract",
    "## Input Handling Contract",
    "## Error Rendering Contract",
    "## Testability Contract",
]

REQUIRED_EVENT_CODES = {
    "FRANKENTUI_CONTRACT_LOADED",
    "FRANKENTUI_COMPONENT_UNMAPPED",
    "FRANKENTUI_STYLING_VIOLATION",
}

REQUIRED_KEYS = {
    "franken_node_module",
    "frankentui_component",
    "boundary_type",
    "styling_strategy",
    "snapshot_hook",
}

ALLOWED_BOUNDARY_TYPES = {
    "surface_definition",
    "renderer",
    "diagnostic_renderer",
}

ALLOWED_STYLING_STRATEGIES = {
    "token_only",
}

ALLOWED_CHECKLIST_STATUS = {"defined", "pending", "waived"}

OUTPUT_PATTERNS = ("println!(", "eprintln!(", "print!(")
ANSI_PATTERNS = ("\x1b[", "\\x1b[", "\\u001b[", "\\u{1b}")


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path = ROOT) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def discover_output_modules(
    module_root: Path = MODULE_ROOT,
    project_root: Path = ROOT,
) -> list[str]:
    if not module_root.exists():
        raise FileNotFoundError(f"module root not found: {module_root}")

    modules: list[str] = []
    for file_path in sorted(module_root.rglob("*.rs")):
        content = file_path.read_text(encoding="utf-8")
        if any(pattern in content for pattern in OUTPUT_PATTERNS):
            modules.append(_rel(file_path, project_root))
    return modules


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate_contract(
    checklist: dict[str, Any],
    contract_text: str,
    output_modules: list[str],
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    trace = _trace_id(checklist)
    events.append(
        {
            "event_code": "FRANKENTUI_CONTRACT_LOADED",
            "severity": "info",
            "trace_correlation": trace,
            "message": "Loaded frankentui integration contract checklist.",
        }
    )

    for section in REQUIRED_CONTRACT_SECTIONS:
        if section not in contract_text:
            errors.append(f"contract missing section: {section}")

    components = checklist.get("components")
    if not isinstance(components, list) or not components:
        errors.append("components must be a non-empty list")
        components = []

    mapped_modules: set[str] = set()
    for idx, component in enumerate(components):
        if not isinstance(component, dict):
            errors.append(f"components[{idx}] must be an object")
            continue

        missing_keys = sorted(REQUIRED_KEYS - set(component.keys()))
        if missing_keys:
            errors.append(f"components[{idx}] missing keys: {', '.join(missing_keys)}")
            continue

        module_path = component["franken_node_module"]
        if not isinstance(module_path, str) or not module_path:
            errors.append(f"components[{idx}].franken_node_module must be a non-empty string")
            continue
        mapped_modules.add(module_path)

        boundary_type = component["boundary_type"]
        if boundary_type not in ALLOWED_BOUNDARY_TYPES:
            errors.append(f"{module_path}: invalid boundary_type `{boundary_type}`")

        styling_strategy = component["styling_strategy"]
        if styling_strategy not in ALLOWED_STYLING_STRATEGIES:
            errors.append(f"{module_path}: invalid styling_strategy `{styling_strategy}`")

    for module_path in output_modules:
        if module_path not in mapped_modules:
            message = f"output module not mapped in contract checklist: {module_path}"
            events.append(
                {
                    "event_code": "FRANKENTUI_COMPONENT_UNMAPPED",
                    "severity": "error",
                    "trace_correlation": trace,
                    "module": module_path,
                    "message": message,
                }
            )
            errors.append(message)

    if "crates/franken-node/src/cli.rs" not in mapped_modules:
        errors.append(
            "required cli surface missing from component boundaries: "
            "crates/franken-node/src/cli.rs"
        )

    event_codes = set(checklist.get("event_codes", []))
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - event_codes)
    if missing_event_codes:
        errors.append(f"missing required event codes: {', '.join(missing_event_codes)}")

    event_loop_contract = checklist.get("event_loop_contract", {})
    if not isinstance(event_loop_contract, dict):
        errors.append("event_loop_contract must be an object")
    else:
        owner = event_loop_contract.get("owner")
        tick_rate = event_loop_contract.get("tick_rate_ms")
        propagation = event_loop_contract.get("state_propagation_pattern")
        if not isinstance(owner, str) or not owner.strip():
            errors.append("event_loop_contract.owner must be a non-empty string")
        if not isinstance(tick_rate, int) or tick_rate <= 0:
            errors.append("event_loop_contract.tick_rate_ms must be a positive integer")
        if not isinstance(propagation, str) or not propagation.strip():
            errors.append(
                "event_loop_contract.state_propagation_pattern must be a non-empty string"
            )

    styling_policy = checklist.get("styling_policy", {})
    if not isinstance(styling_policy, dict):
        errors.append("styling_policy must be an object")
    else:
        if styling_policy.get("ansi_escape_sequences_forbidden") is not True:
            errors.append("styling_policy.ansi_escape_sequences_forbidden must be true")
        token_source = styling_policy.get("required_token_source")
        if not isinstance(token_source, str) or "frankentui" not in token_source:
            errors.append(
                "styling_policy.required_token_source must reference frankentui token source"
            )

    checklist_items = checklist.get("checklist")
    if not isinstance(checklist_items, list) or not checklist_items:
        errors.append("checklist must be a non-empty list")
    else:
        pending = []
        for idx, item in enumerate(checklist_items):
            if not isinstance(item, dict):
                errors.append(f"checklist[{idx}] must be an object")
                continue
            status = item.get("status")
            if status not in ALLOWED_CHECKLIST_STATUS:
                errors.append(f"checklist[{idx}] has invalid status `{status}`")
                continue
            if status == "pending":
                pending.append(item.get("requirement", f"item_{idx}"))
        if pending:
            errors.append(f"pending checklist requirements: {', '.join(pending)}")

    # Enforce no raw ANSI escapes in mapped source modules.
    for module_path in sorted(mapped_modules):
        abs_path = ROOT / module_path
        if not abs_path.is_file() or abs_path.suffix != ".rs":
            continue
        content = abs_path.read_text(encoding="utf-8")
        if any(pattern in content for pattern in ANSI_PATTERNS):
            message = f"raw ANSI escape usage detected in mapped module: {module_path}"
            events.append(
                {
                    "event_code": "FRANKENTUI_STYLING_VIOLATION",
                    "severity": "error",
                    "trace_correlation": trace,
                    "module": module_path,
                    "message": message,
                }
            )
            errors.append(message)

    success = len(errors) == 0
    report = {
        "ok": success,
        "trace_correlation": trace,
        "mapped_component_count": len(mapped_modules),
        "discovered_output_module_count": len(output_modules),
        "unmapped_output_modules": sorted(set(output_modules) - mapped_modules),
        "errors": errors,
        "warnings": warnings,
        "events": events,
    }
    return success, report


def run_checks(
    checklist_path: Path = CHECKLIST_PATH,
    contract_path: Path = CONTRACT_PATH,
    module_root: Path = MODULE_ROOT,
) -> tuple[bool, dict[str, Any]]:
    if not checklist_path.is_file():
        raise FileNotFoundError(f"missing checklist artifact: {checklist_path}")
    if not contract_path.is_file():
        raise FileNotFoundError(f"missing contract doc: {contract_path}")

    checklist = json.loads(checklist_path.read_text(encoding="utf-8"))
    contract_text = contract_path.read_text(encoding="utf-8")
    output_modules = discover_output_modules(module_root, ROOT)

    ok, report = evaluate_contract(checklist, contract_text, output_modules)
    result = {
        "bead_id": "bd-34ll",
        "contract": _rel(contract_path),
        "checklist": _rel(checklist_path),
        "module_root": _rel(module_root),
        **report,
    }
    return ok, result


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="frankentui-contract-selftest-") as tmp:
        root = Path(tmp)
        src_root = root / "crates" / "franken-node" / "src"
        src_root.mkdir(parents=True, exist_ok=True)
        (src_root / "main.rs").write_text('fn main() { println!("ok"); }\n', encoding="utf-8")
        (src_root / "cli.rs").write_text("pub struct Cli;\n", encoding="utf-8")

        contract = root / "contract.md"
        contract.write_text("\n".join(REQUIRED_CONTRACT_SECTIONS), encoding="utf-8")

        checklist = {
            "components": [
                {
                    "franken_node_module": "crates/franken-node/src/main.rs",
                    "frankentui_component": "Panel",
                    "boundary_type": "renderer",
                    "styling_strategy": "token_only",
                    "snapshot_hook": "tests/snap/main.snap",
                },
                {
                    "franken_node_module": "crates/franken-node/src/cli.rs",
                    "frankentui_component": "CommandSurface",
                    "boundary_type": "surface_definition",
                    "styling_strategy": "token_only",
                    "snapshot_hook": "tests/snap/cli.snap",
                },
            ],
            "event_loop_contract": {
                "owner": "runtime",
                "tick_rate_ms": 16,
                "state_propagation_pattern": "bus",
            },
            "styling_policy": {
                "ansi_escape_sequences_forbidden": True,
                "required_token_source": "frankentui::tokens",
            },
            "event_codes": sorted(REQUIRED_EVENT_CODES),
            "checklist": [{"requirement": "complete", "status": "defined"}],
        }

        ok, report = evaluate_contract(
            checklist,
            contract.read_text(encoding="utf-8"),
            discover_output_modules(src_root, root),
        )
        assert ok, f"self_test expected pass but got errors: {report['errors']}"

        checklist_bad = dict(checklist)
        checklist_bad["components"] = checklist["components"][1:]
        ok_bad, report_bad = evaluate_contract(
            checklist_bad,
            contract.read_text(encoding="utf-8"),
            discover_output_modules(src_root, root),
        )
        assert not ok_bad, "self_test expected failure for unmapped output module"
        assert report_bad["unmapped_output_modules"], "expected unmapped module report"

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_frankentui_contract")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checklist", default=str(CHECKLIST_PATH), help="Checklist JSON path.")
    parser.add_argument("--contract", default=str(CONTRACT_PATH), help="Contract markdown path.")
    parser.add_argument("--module-root", default=str(MODULE_ROOT), help="Source module root path.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
    args = parser.parse_args()

    if args.self_test:
        ok, payload = self_test()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("self_test: passed" if ok else "self_test: failed")
        return 0 if ok else 1

    ok, report = run_checks(
        checklist_path=Path(args.checklist),
        contract_path=Path(args.contract),
        module_root=Path(args.module_root),
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for event in report["events"]:
            level = event["severity"].upper()
            print(f"[{level}] {event['event_code']}: {event['message']}")
        if report["errors"]:
            print("\nErrors:")
            for err in report["errors"]:
                print(f"- {err}")
        print(
            f"\nResult: {'PASS' if ok else 'FAIL'} "
            f"({report['mapped_component_count']} mapped components, "
            f"{report['discovered_output_module_count']} output modules discovered)"
        )

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
