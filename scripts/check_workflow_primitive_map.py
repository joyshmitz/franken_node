#!/usr/bin/env python3
"""bd-2177 verifier: workflow-to-primitive planning gate."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_CONTRACT = ROOT / "docs" / "architecture" / "tri_kernel_ownership_contract.md"
DEFAULT_MATRIX = ROOT / "artifacts" / "10.15" / "workflow_primitive_matrix.json"

BEAD = "bd-2177"
SECTION = "10.15"

REQUIRED_WORKFLOW_ALIASES = {
    "connector_lifecycle": {"connector_lifecycle"},
    "rollout_state_transitions": {"rollout_state_transitions", "rollout_transition"},
    "health_gate_evaluation": {"health_gate_evaluation"},
    "publish_flow": {"publish_flow"},
    "revoke_flow": {"revoke_flow"},
    "quarantine_promotion": {"quarantine_promotion"},
    "migration_orchestration": {"migration_orchestration"},
    "fencing_token_acquisition_release": {
        "fencing_token_acquisition_release",
        "fencing_token_ops",
    },
}

REQUIRED_WORKFLOWS = set(REQUIRED_WORKFLOW_ALIASES.keys())

REQUIRED_PRIMITIVES = [
    "cx_propagation",
    "region_ownership_scope",
    "cancellation_protocol",
    "obligation_tracking",
    "remote_computation_registry",
    "epoch_validity_window",
    "evidence_ledger_emission",
]


@dataclass
class GateResult:
    checks: list[dict[str, Any]]
    events: list[dict[str, Any]]
    workflow_counts: dict[str, int]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _extract_frontmatter(doc_text: str) -> str:
    match = re.match(r"^---\n(.*?)\n---\n", doc_text, flags=re.DOTALL)
    return "" if not match else match.group(1)


def parse_canonical_primitives(contract_text: str) -> list[str]:
    frontmatter = _extract_frontmatter(contract_text)
    if not frontmatter:
        return []

    lines = frontmatter.splitlines()
    values: list[str] = []
    in_block = False

    for line in lines:
        if line.startswith("canonical_asupersync_primitives:"):
            in_block = True
            continue
        if not in_block:
            continue

        if line.startswith("  - "):
            value = line[4:].strip()
            if value:
                values.append(value)
            continue

        if line and not line.startswith(" "):
            break

    return values


def _parse_timestamp(value: str) -> datetime | None:
    normalized = value.strip().replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone(UTC)


def _exception_is_approved(exc: Any, now_utc: datetime) -> tuple[bool, str]:
    if not isinstance(exc, dict):
        return False, "missing exception object"
    if exc.get("approved") is not True:
        return False, "exception.approved is not true"
    missing = [k for k in ("waiver_id", "reason", "expires_at") if not exc.get(k)]
    if missing:
        return False, f"missing exception fields: {', '.join(missing)}"

    expiry = _parse_timestamp(str(exc["expires_at"]))
    if expiry is None:
        return False, "exception.expires_at is not RFC3339"
    if expiry <= now_utc:
        return False, f"exception expired at {expiry.isoformat()}"
    return True, "approved exception"


def _is_required_workflow_id(workflow_id: str) -> bool:
    for aliases in REQUIRED_WORKFLOW_ALIASES.values():
        if workflow_id in aliases:
            return True
    return False


def _evaluate_matrix(
    matrix: dict[str, Any], canonical_primitives: list[str], trace_id: str
) -> GateResult:
    checks: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    now_utc = datetime.now(UTC)

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    workflows_raw = matrix.get("workflows", [])
    add_check("workflows_is_list", isinstance(workflows_raw, list), f"type={type(workflows_raw).__name__}")
    if not isinstance(workflows_raw, list):
        return GateResult(checks=checks, events=events, workflow_counts={"total": 0, "mapped": 0, "partial": 0, "unmapped": 0})

    workflows: list[dict[str, Any]] = [w for w in workflows_raw if isinstance(w, dict)]
    add_check(
        "workflow_entry_shapes",
        len(workflows) == len(workflows_raw),
        f"dict_entries={len(workflows)}/{len(workflows_raw)}",
    )

    workflow_ids = {str(w.get("workflow_id", "")) for w in workflows}
    missing_workflows = sorted(
        canonical_name
        for canonical_name, aliases in REQUIRED_WORKFLOW_ALIASES.items()
        if workflow_ids.isdisjoint(aliases)
    )
    add_check(
        "required_workflows_present",
        not missing_workflows,
        "all required workflows present"
        if not missing_workflows
        else f"missing: {', '.join(missing_workflows)}",
    )

    canonical_set = set(canonical_primitives)
    unknown_primitive_refs: list[str] = []
    primitive_coverage_gaps: list[str] = []
    unmapped_failures: list[str] = []

    mapped = 0
    partial = 0
    unmapped = 0

    for wf in workflows:
        wf_id = str(wf.get("workflow_id", "<missing-workflow-id>"))
        wf_name = str(wf.get("workflow_name", "<missing-workflow-name>"))
        primitives_raw = wf.get("required_primitives", [])
        primitives = list(primitives_raw) if isinstance(primitives_raw, list) else []

        missing_fields = [
            field
            for field in ("workflow_id", "workflow_name", "required_primitives", "mapped")
            if field not in wf
        ]
        if missing_fields:
            unmapped_failures.append(wf_id)
            events.append(
                {
                    "event_code": "WFM-003",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "fail",
                    "detail": f"missing fields: {', '.join(missing_fields)}",
                }
            )
            continue

        if _is_required_workflow_id(wf_id):
            missing_prims = [p for p in REQUIRED_PRIMITIVES if p not in primitives]
            if missing_prims:
                primitive_coverage_gaps.append(f"{wf_id}: missing {', '.join(missing_prims)}")

        unknown = sorted({str(p) for p in primitives if str(p) not in canonical_set})
        if unknown:
            unknown_primitive_refs.append(f"{wf_id}: {', '.join(unknown)}")
            events.append(
                {
                    "event_code": "WFM-004",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "fail",
                    "detail": f"unknown primitive(s): {', '.join(unknown)}",
                }
            )
        else:
            events.append(
                {
                    "event_code": "WFM-004",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "pass",
                    "detail": f"{len(primitives)} primitive reference(s) valid",
                }
            )

        is_mapped = bool(wf.get("mapped"))
        if is_mapped:
            mapped += 1
            events.append(
                {
                    "event_code": "WFM-001",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "pass",
                    "detail": f"{wf_name} mapped",
                }
            )
            continue

        approved, reason = _exception_is_approved(wf.get("exception"), now_utc)
        if approved:
            partial += 1
            events.append(
                {
                    "event_code": "WFM-002",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "pass",
                    "detail": reason,
                }
            )
        else:
            unmapped += 1
            unmapped_failures.append(wf_id)
            events.append(
                {
                    "event_code": "WFM-003",
                    "trace_id": trace_id,
                    "workflow_id": wf_id,
                    "status": "fail",
                    "detail": reason,
                }
            )

    add_check(
        "critical_workflow_primitive_coverage",
        not primitive_coverage_gaps,
        "all critical workflows include full primitive set"
        if not primitive_coverage_gaps
        else "; ".join(primitive_coverage_gaps),
    )

    add_check(
        "primitive_references_known",
        not unknown_primitive_refs,
        "all primitive references are canonical"
        if not unknown_primitive_refs
        else "; ".join(unknown_primitive_refs),
    )

    add_check(
        "critical_workflows_mapped_or_exceptioned",
        not unmapped_failures,
        "all critical workflows mapped or exception-approved"
        if not unmapped_failures
        else f"unmapped without approved exception: {', '.join(sorted(set(unmapped_failures)))}",
    )

    summary = matrix.get("summary", {})
    summary_ok = (
        isinstance(summary, dict)
        and summary.get("total_workflows") == len(workflows)
        and summary.get("fully_mapped") == mapped
        and summary.get("partially_mapped") == partial
        and summary.get("unmapped") == unmapped
    )
    add_check(
        "summary_counts_consistent",
        summary_ok,
        (
            f"expected total={len(workflows)} mapped={mapped} partial={partial} unmapped={unmapped}"
            if not summary_ok
            else "summary counts match workflow entries"
        ),
    )

    return GateResult(
        checks=checks,
        events=events,
        workflow_counts={
            "total": len(workflows),
            "mapped": mapped,
            "partial": partial,
            "unmapped": unmapped,
        },
    )


def run_gate(contract_path: Path, matrix_path: Path, trace_id: str) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add_check("contract_exists", contract_path.is_file(), str(contract_path))
    add_check("matrix_exists", matrix_path.is_file(), str(matrix_path))

    workflow_counts = {"total": 0, "mapped": 0, "partial": 0, "unmapped": 0}

    if contract_path.is_file() and matrix_path.is_file():
        try:
            contract_text = _read_text(contract_path)
            matrix = _load_json(matrix_path)
        except (OSError, json.JSONDecodeError) as exc:
            add_check("io_and_parse", False, str(exc))
            matrix = {}
            canonical = []
        else:
            add_check("io_and_parse", True, "contract and matrix loaded")
            canonical = parse_canonical_primitives(contract_text)
            add_check(
                "canonical_primitives_loaded",
                len(canonical) >= len(REQUIRED_PRIMITIVES),
                f"loaded={len(canonical)}",
            )

            gate_result = _evaluate_matrix(matrix, canonical, trace_id)
            checks.extend(gate_result.checks)
            events.extend(gate_result.events)
            workflow_counts = gate_result.workflow_counts

            canonical_alignment = sorted(set(REQUIRED_PRIMITIVES) - set(canonical))
            add_check(
                "canonical_vocab_alignment",
                not canonical_alignment,
                "required primitive vocabulary present in contract"
                if not canonical_alignment
                else f"missing from contract: {', '.join(canonical_alignment)}",
            )

    verdict = "PASS" if checks and all(c["passed"] for c in checks) else "FAIL"
    passed = sum(1 for c in checks if c["passed"])

    return {
        "bead_id": BEAD,
        "section": SECTION,
        "gate_script": Path(__file__).name,
        "trace_id": trace_id,
        "verdict": verdict,
        "checks_passed": passed,
        "checks_total": len(checks),
        "workflow_counts": workflow_counts,
        "checks": checks,
        "events": events,
        "contract_path": str(contract_path),
        "matrix_path": str(matrix_path),
    }


def self_test() -> bool:
    sample_contract = """---
canonical_asupersync_primitives:
  - cx_propagation
  - region_ownership_scope
  - cancellation_protocol
  - obligation_tracking
  - remote_computation_registry
  - epoch_validity_window
  - evidence_ledger_emission
---
"""

    canonical = parse_canonical_primitives(sample_contract)
    assert canonical == REQUIRED_PRIMITIVES, canonical

    valid_matrix = {
        "workflows": [
            {
                "workflow_id": wf_id,
                "workflow_name": wf_id,
                "required_primitives": REQUIRED_PRIMITIVES,
                "mapped": True,
            }
            for wf_id in sorted(REQUIRED_WORKFLOWS)
        ],
        "summary": {
            "total_workflows": len(REQUIRED_WORKFLOWS),
            "fully_mapped": len(REQUIRED_WORKFLOWS),
            "partially_mapped": 0,
            "unmapped": 0,
        },
    }
    ok_result = _evaluate_matrix(valid_matrix, canonical, trace_id=f"{BEAD}-self-test")
    assert all(c["passed"] for c in ok_result.checks), ok_result.checks

    broken_matrix = dict(valid_matrix)
    broken_workflows = [dict(w) for w in valid_matrix["workflows"]]
    broken_workflows[0]["mapped"] = False
    broken_matrix["workflows"] = broken_workflows
    broken_matrix["summary"] = {
        "total_workflows": len(REQUIRED_WORKFLOWS),
        "fully_mapped": len(REQUIRED_WORKFLOWS) - 1,
        "partially_mapped": 0,
        "unmapped": 1,
    }
    fail_result = _evaluate_matrix(broken_matrix, canonical, trace_id=f"{BEAD}-self-test")
    critical = {
        c["check"]: c for c in fail_result.checks
    }.get("critical_workflows_mapped_or_exceptioned")
    assert critical is not None and not critical["passed"]

    print(f"self_test: {len(ok_result.checks)} checks validated", file=sys.stderr)
    return True


def main() -> int:
    logger = configure_test_logging("check_workflow_primitive_map")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--self-test", action="store_true", dest="self_test_mode")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--trace-id", default=os.environ.get("TRACE_ID", f"{BEAD}-trace"))
    args = parser.parse_args()

    if args.self_test_mode:
        self_test()
        return 0

    payload = run_gate(contract_path=args.contract, matrix_path=args.matrix, trace_id=args.trace_id)

    if args.json_output:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{BEAD}: {payload['verdict']} "
            f"({payload['checks_passed']}/{payload['checks_total']})"
        )
        for check in payload["checks"]:
            mark = "PASS" if check["passed"] else "FAIL"
            print(f"  [{mark}] {check['check']}: {check['detail']}")

    return 0 if payload["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
