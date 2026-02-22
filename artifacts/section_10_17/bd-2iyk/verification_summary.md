# bd-2iyk Verification Summary

- Status: **PASS**
- Checker: `92/92` PASS
- Checker self-test: PASS
- Unit tests (Python): all PASS
- Unit tests (Rust): 34 inline tests

## Delivered Surface

- `docs/specs/section_10_17/bd-2iyk_contract.md`
- `crates/franken-node/src/security/lineage_tracker.rs`
- `scripts/check_info_flow_lineage.py`
- `tests/test_check_info_flow_lineage.py`
- `artifacts/section_10_17/bd-2iyk/verification_evidence.json`
- `artifacts/section_10_17/bd-2iyk/verification_summary.md`

## Acceptance Coverage

- Taint labels are assigned to data payloads and persist across all flows (INV-IFL-LABEL-PERSIST).
- Flow edges are append-only, recording source, sink, operation, taint set, and timestamp (INV-IFL-EDGE-APPEND-ONLY).
- Exfiltration sentinel evaluates edges against taint boundaries and raises alerts on violation (INV-IFL-BOUNDARY-ENFORCED).
- Auto-containment quarantines offending flows, producing a ContainmentReceipt for each (INV-IFL-QUARANTINE-RECEIPT).
- Evaluation is deterministic given same graph state and config (INV-IFL-DETERMINISTIC).
- Lineage snapshots faithfully capture graph state (INV-IFL-SNAPSHOT-FAITHFUL).
- BTreeMap/BTreeSet used throughout for deterministic ordering.

## Implementation Details

- **12 types**: TaintLabel, TaintSet, FlowEdge, LineageGraph, ExfiltrationSentinel, ExfiltrationAlert, ContainmentReceipt, TaintBoundary, SentinelConfig, FlowVerdict, LineageQuery, LineageSnapshot
- **12 event codes**: FN-IFL-001 through FN-IFL-012
- **10 error codes**: ERR_IFL_LABEL_NOT_FOUND through ERR_IFL_TIMEOUT
- **6 invariants**: label persistence, append-only edges, quarantine receipts, boundary enforcement, determinism, snapshot faithfulness
- **Invariants module**: dedicated `invariants` sub-module with verification functions

## Blocker Note

Bead bd-2iyk is blocked by bd-3l2p (intent-aware remote effects firewall). Implementation is complete and verified independently; `br close` will succeed once the blocker is resolved.
