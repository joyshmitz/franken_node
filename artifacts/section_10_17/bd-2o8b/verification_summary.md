# bd-2o8b Verification Summary

## Result
PASS

## Delivered
- `crates/franken-node/src/runtime/hardware_planner.rs`
- `crates/franken-node/src/runtime/mod.rs` (wired hardware_planner module)
- `docs/specs/section_10_17/bd-2o8b_contract.md`
- `scripts/check_hardware_planner.py`
- `tests/test_check_hardware_planner.py`
- `artifacts/section_10_17/bd-2o8b/verification_evidence.json`
- `artifacts/section_10_17/bd-2o8b/verification_summary.md`

## Invariants

| ID | Status |
|----|--------|
| INV-HWP-DETERMINISTIC | Enforced -- BTreeMap/BTreeSet throughout, stable selection criteria |
| INV-HWP-CAPABILITY-MATCH | Enforced -- workload placed only on hardware with superset capabilities |
| INV-HWP-RISK-BOUND | Enforced -- placement rejected if risk exceeds tolerance |
| INV-HWP-EVIDENCE-COMPLETE | Enforced -- every decision carries PolicyEvidence with reasoning chain |
| INV-HWP-FALLBACK-PATH | Enforced -- contention triggers fallback with risk relaxation option |
| INV-HWP-DISPATCH-GATED | Enforced -- dispatch only through approved_interfaces set |
| INV-HWP-SCHEMA-VERSIONED | Enforced -- hwp-v1.0 on all serialized outputs |
| INV-HWP-AUDIT-COMPLETE | Enforced -- all decisions recorded with stable event codes |

## Event Codes

| Code | Description | Status |
|------|-------------|--------|
| HWP-001 | Hardware profile registered | Implemented |
| HWP-002 | Placement policy registered | Implemented |
| HWP-003 | Placement requested | Implemented |
| HWP-004 | Placement succeeded | Implemented |
| HWP-005 | Placement rejected (capability mismatch) | Implemented |
| HWP-006 | Placement rejected (risk exceeded) | Implemented |
| HWP-007 | Placement rejected (capacity exhausted) | Implemented |
| HWP-008 | Fallback path attempted | Implemented |
| HWP-009 | Fallback path succeeded | Implemented |
| HWP-010 | Fallback path exhausted | Implemented |
| HWP-011 | Dispatch executed through approved interface | Implemented |
| HWP-012 | Policy evidence recorded | Implemented |

## Error Codes

| Code | Description | Status |
|------|-------------|--------|
| ERR_HWP_NO_CAPABLE_TARGET | No capable hardware for workload | Implemented |
| ERR_HWP_RISK_EXCEEDED | All capable hardware exceeds risk tolerance | Implemented |
| ERR_HWP_CAPACITY_EXHAUSTED | All capable hardware at capacity | Implemented |
| ERR_HWP_DUPLICATE_PROFILE | Profile already registered | Implemented |
| ERR_HWP_DUPLICATE_POLICY | Policy already registered | Implemented |
| ERR_HWP_UNKNOWN_PROFILE | Referenced profile does not exist | Implemented |
| ERR_HWP_EMPTY_CAPABILITIES | Workload declares zero capabilities | Implemented |
| ERR_HWP_DISPATCH_UNGATED | Dispatch without approved interface | Implemented |
| ERR_HWP_INVALID_RISK_LEVEL | Risk level outside [0, 100] | Implemented |
| ERR_HWP_FALLBACK_EXHAUSTED | All fallback paths exhausted | Implemented |

## Gate Results
- `python3 scripts/check_hardware_planner.py --json` -> PASS
- `python3 scripts/check_hardware_planner.py --self-test` -> PASS
- `python3 -m pytest tests/test_check_hardware_planner.py -v` -> PASS
