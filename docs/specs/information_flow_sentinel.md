# [10.17] Information-Flow Lineage and Exfiltration Sentinel

**Bead**: bd-2iyk
**Section**: 10.17
**Status**: Implemented

## Overview

This specification defines the information-flow lineage tracker and exfiltration
sentinel subsystem for franken_node. The module tracks taint labels across
execution flows, detects boundary violations that indicate data exfiltration,
and auto-contains detected threats via deterministic quarantine with receipts.

## Goals

1. **Taint label persistence**: Sensitive lineage tags, once attached to a
   datum, must persist across all supported execution flows (propagation, merge,
   snapshot). Labels are never silently stripped.
2. **Exfiltration detection**: The sentinel continuously evaluates flow edges
   against configured taint boundaries. Flows that cross a denied boundary
   raise structured alerts.
3. **Auto-containment**: Detected exfiltrations are quarantined automatically
   without manual intervention, producing a deterministic containment receipt.
4. **Recall and precision thresholds**: The sentinel must meet configurable
   recall (default >= 95%) and precision (default >= 90%) targets when
   evaluated against simulated covert exfiltration scenarios.
5. **Covert channel detection**: Heuristic scanning identifies patterns such
   as rapid sequential low-taint flows to external sinks.

## Event Codes

| Code | Description |
|------|-------------|
| LINEAGE_TAG_ATTACHED | A taint label was attached to a datum |
| LINEAGE_FLOW_TRACKED | A flow edge was tracked with sentinel evaluation |
| SENTINEL_SCAN_START | A sentinel graph scan was initiated |
| SENTINEL_EXFIL_DETECTED | An exfiltration was detected during scan |
| SENTINEL_CONTAINMENT_TRIGGERED | Auto-containment quarantine was applied |
| FN-IFL-001 | Internal taint assignment event |
| FN-IFL-002 | Internal edge append event |
| FN-IFL-003 | Internal taint propagation event |
| FN-IFL-004 | Internal boundary crossing event |
| FN-IFL-005 | Internal exfiltration alert event |
| FN-IFL-006 | Internal flow quarantine event |
| FN-IFL-007 | Internal containment receipt event |
| FN-IFL-008 | Internal snapshot export event |
| FN-IFL-009 | Internal config reload event |
| FN-IFL-010 | Internal depth limit event |
| FN-IFL-011 | Internal taint merge event |
| FN-IFL-012 | Internal health check event |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_LINEAGE_TAG_MISSING | Referenced taint label is not registered |
| ERR_LINEAGE_FLOW_BROKEN | Flow edge lost after propagation |
| ERR_SENTINEL_RECALL_BELOW_THRESHOLD | Recall dropped below configured threshold |
| ERR_SENTINEL_PRECISION_BELOW_THRESHOLD | Precision dropped below configured threshold |
| ERR_SENTINEL_CONTAINMENT_FAILED | Containment action could not be applied |
| ERR_SENTINEL_COVERT_CHANNEL | Covert channel pattern detected |
| ERR_IFL_LABEL_NOT_FOUND | Label lookup failed |
| ERR_IFL_DUPLICATE_EDGE | Edge with same ID already exists |
| ERR_IFL_GRAPH_FULL | Graph capacity limit reached |
| ERR_IFL_BOUNDARY_INVALID | Boundary rule is malformed |
| ERR_IFL_CONTAINMENT_FAILED | Containment action failed |
| ERR_IFL_SNAPSHOT_FAILED | Snapshot export failed |
| ERR_IFL_QUERY_INVALID | Query parameters are invalid |
| ERR_IFL_CONFIG_REJECTED | Configuration rejected |
| ERR_IFL_ALREADY_QUARANTINED | Edge already quarantined |
| ERR_IFL_TIMEOUT | Operation timed out |

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-LINEAGE-TAG-PERSISTENCE | Sensitive lineage tags persist across all supported execution flows |
| INV-SENTINEL-RECALL-THRESHOLD | Sentinel recall >= configured threshold (default 95%) |
| INV-SENTINEL-PRECISION-THRESHOLD | Sentinel precision >= configured threshold (default 90%) |
| INV-SENTINEL-AUTO-CONTAIN | Detected exfiltrations are auto-contained |
| INV-IFL-LABEL-PERSIST | Once assigned, a taint label is never removed |
| INV-IFL-EDGE-APPEND-ONLY | Flow edges are append-only |
| INV-IFL-QUARANTINE-RECEIPT | Every quarantine produces a receipt |
| INV-IFL-BOUNDARY-ENFORCED | No violating flow proceeds without alert |
| INV-IFL-DETERMINISTIC | Same input yields same verdict |
| INV-IFL-SNAPSHOT-FAITHFUL | Snapshot faithfully represents graph |

## Architecture

### Core Types

- `TaintLabel`: Immutable sensitivity classification tag with id, description, severity.
- `TaintSet`: Ordered set of active taint labels on a datum.
- `FlowEdge`: Directed edge recording (source, sink, operation, taint_set, timestamp).
- `TaintBoundary`: Policy rule defining allowed/denied taint crossings between zones.
- `FlowVerdict`: Per-edge decision (Pass, Quarantine, Alert).
- `ExfiltrationAlert`: Structured alert on boundary violation.
- `ContainmentReceipt`: Proof that a flow was quarantined.
- `SentinelConfig`: Tuning knobs for graph limits and recall/precision thresholds.
- `SentinelScanResult`: Result of a full graph scan.
- `SentinelMetrics`: Recall and precision evaluation result.
- `CovertChannelDetection`: Covert channel heuristic detection result.

### LineageGraph

Append-only DAG of `FlowEdge` records. Supports:
- Label registration and assignment (`register_label`, `assign_taint`)
- Edge append with capacity check (`append_edge`)
- Taint propagation with merge (`propagate_taint`)
- Subgraph query (`query`)
- Snapshot export (`snapshot`)

### ExfiltrationSentinel

Policy engine evaluating flow edges against taint boundaries. Supports:
- Boundary registration (`add_boundary`)
- Edge evaluation with auto-quarantine (`evaluate_edge`)
- Full graph scan (`scan_graph`)
- Lineage tag attachment (`attach_lineage_tag`)
- Flow tracking with sentinel evaluation (`track_flow`)
- Recall/precision metrics (`evaluate_metrics`)
- Covert channel detection (`detect_covert_channels`)
- Health check and config reload

## Configuration

```rust
SentinelConfig {
    max_graph_edges: 100_000,
    max_graph_depth: 256,
    alert_cooldown_ms: 1_000,
    recall_threshold_pct: 95,
    precision_threshold_pct: 90,
    schema_version: "ifl-v1.0",
}
```

## Acceptance Criteria

1. Sensitive lineage tags persist across supported execution flows.
2. Simulated covert exfiltration scenarios are detected and auto-contained
   above defined recall/precision thresholds.
3. All event codes, error codes, and invariants are present in implementation
   and referenced in tests.
