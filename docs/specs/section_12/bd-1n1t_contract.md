# bd-1n1t Contract: Topology Blind Spots

## Section
12 — Risk Register Countermeasure Program

## Bead ID
bd-1n1t

## Risk Statement
Dependency topology blind spots create hidden attack surfaces and unbounded
blast-radius pathways. Unknown or untracked transitive dependencies reduce
operator ability to evaluate compromise paths and cascading failure modes.

## Impact

| Dimension | Rating | Detail |
|---|---|---|
| Security | Critical | Supply-chain compromise can propagate via unobserved transitive edges. |
| Reliability | High | Choke-point dependency failures can cascade system-wide. |
| Operability | High | Missing topology visibility blocks accurate blast-radius analysis. |
| Recovery | Medium | Remediation speed depends on topology completeness and drift alerts. |

## Countermeasures

### (a) Mandatory Graph Ingestion

Every build must ingest the complete dependency graph (direct + transitive)
into a queryable structure derived from canonical metadata (`cargo metadata`
or equivalent).

Invariant:
- INV-TBS-GRAPH-INGEST: Graph generated on every build and includes all
  transitive dependencies.

### (b) Topology Metric Baselines

Baseline and monitor:
- maximum depth
- average fan-out
- betweenness centrality (top 10 nodes)

Drift from baseline above threshold requires explicit review.

Invariants:
- INV-TBS-METRICS-BASELINE: Baselines exist for all required metrics.
- INV-TBS-DRIFT-REVIEW: Metric drift > 20% triggers review alert.

### (c) Choke-Point Alerts

Dependencies present in > 50% of dependency paths are choke-points and must
be flagged for heightened review.

Invariant:
- INV-TBS-CHOKEPOINT: Choke-point detector flags dependencies used by >50%
  of paths.

### Cycle Handling

Graph ingestion must gracefully handle cyclic dependencies via explicit cycle
detection and reporting.

Invariant:
- INV-TBS-CYCLE-HANDLING: Cycles are detected, reported, and do not crash
  topology ingestion.

## Verification Requirements

1. Graph generation runs on every build and includes all transitive dependencies.
2. Metrics computed: max depth, average fan-out, betweenness centrality top-10.
3. Baselines exist; drift >20% emits review alert.
4. Choke-point detection correctly identifies dependencies used by >50% of paths.

## Scenario Matrix

- Scenario A: Add deep transitive dependency; ingestion captures it and
  depth increases.
- Scenario B: Introduce >50% path-share dependency; choke-point alert fires.
- Scenario C: Remove choke-point dependency; metrics improve and alert clears.
- Scenario D: Cyclic dependency input; cycles are detected/reported gracefully.

## Event Codes

| Code | Description |
|---|---|
| `TBS-101` | Topology graph ingestion completed for current build. |
| `TBS-102` | Topology metric drift exceeded threshold and review is required. |
| `TBS-103` | Choke-point dependency detected (>50% path share). |
| `TBS-104` | Choke-point alert cleared after topology improvement. |
| `TBS-105` | Cycle detected and reported during graph ingestion. |

## Acceptance Criteria

1. Full dependency graph ingestion is mandatory and queryable per build.
2. Baseline metrics exist for max depth, average fan-out, and top-10 centrality.
3. Drift >20% from baseline triggers deterministic review alert.
4. Choke-point dependencies (>50% path share) are detected and escalated.
5. Scenario A-D validations pass and are reflected in machine-readable artifacts.
