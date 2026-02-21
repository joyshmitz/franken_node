# Policy: Deterministic Incident Containment and Explanation

**Bead:** bd-pga7 | **Section:** 13 (Program Success Criteria)
**Effective:** 2026-02-20
**Owner:** Trust Plane (PP-03)

## Risk Description

Non-deterministic incident response creates ambiguity in post-incident
review, undermines auditor confidence, and prevents formal verification
of containment logic. If the same incident can produce different containment
actions depending on hidden state (timing jitter, thread scheduling, random
seeds), then the containment system cannot be trusted to behave predictably
in production.

### Impact

- **Audit failure:** Regulators and external auditors cannot reproduce
  containment decisions, blocking compliance certification.
- **Operator confusion:** Different containment actions from the same
  incident make runbooks unreliable.
- **Escalation cascade:** Non-deterministic containment may over-isolate
  or under-isolate, amplifying blast radius.
- **Trust erosion:** Users lose confidence in the system's incident
  response guarantees.

### Likelihood

Medium. Non-determinism can enter through:
- Wall-clock timestamps used in decision logic
- Unordered iteration over hash maps in telemetry processing
- Race conditions in concurrent containment action dispatch
- Floating-point rounding differences across platforms

## Containment Contract

### Blast Radius Bound

- **Maximum affected components:** 3 (configurable via policy)
- **Enforcement:** Containment engine refuses to propagate isolation beyond
  the configured bound. If the incident requires isolating more components,
  the engine emits DIC-002 and escalates to human operator.
- **Measurement:** Count of distinct component IDs in the containment action
  set for a single incident.

### Time Bounds

- **Detection to containment:** <= 60 seconds wall-clock
- **Measurement:** Delta between the first DIC-001 event timestamp and the
  incident detection timestamp in the telemetry stream.
- **Violation response:** If containment exceeds 60 seconds, the engine emits
  a timeout alert and logs the partial containment state for review.

### Automated Actions

All automated containment actions are deterministic pure functions of their
inputs:

| Action | Input | Output |
|--------|-------|--------|
| `isolate_component` | fault signature, component graph | set of component IDs to isolate |
| `shed_load` | load profile, threshold config | percentage to shed per component |
| `revoke_credentials` | compromise signal, credential inventory | set of credential IDs to revoke |
| `disable_extension` | misbehavior pattern, extension registry | set of extension IDs to disable |
| `snapshot_state` | trigger event, state dimensions config | state snapshot artifact |
| `emit_alert` | action set, alert template config | alert payload |

No action may consult wall-clock time, random number generators, or
process-local state that is not part of the input bundle.

## Explanation Contract

### Evidence Capture

- **Completeness target:** >= 95% of relevant telemetry dimensions
- **Relevant dimensions** include: incident detection event, all telemetry
  from affected components within the containment window, policy configuration
  at time of incident, component dependency graph, and containment action log.
- **Measurement:** Ratio of captured dimensions to the total set defined by
  the incident type's telemetry schema.

### Reproducibility

- **Target:** 100% bit-identical explanations from the same evidence bundle
- **Enforcement:** The explanation engine is a pure function. All intermediate
  state is derived from the evidence bundle. No external lookups, no
  timestamps, no random seeds.
- **Events:** Every successful explanation emits DIC-003. If a subsequent
  replay produces a different explanation, DIC-004 is emitted.
- **Verification:** Replay the evidence bundle twice and compare SHA-256
  hashes of the explanation output.

### Latency

- **Maximum explanation time:** 120 seconds from evidence bundle submission
- **Measurement:** Wall-clock delta from evidence bundle ingestion to
  explanation output emission.

## Monitoring and Dashboards

### Velocity Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `dic_containment_time_p99` | 99th percentile containment time | > 45 seconds |
| `dic_blast_radius_max` | Maximum blast radius in last 24 hours | > 2 components |
| `dic_explanation_time_p99` | 99th percentile explanation time | > 90 seconds |
| `dic_evidence_completeness_min` | Minimum evidence completeness in last 24 hours | < 96% |
| `dic_containment_divergence_count` | Count of DIC-002 events in last 24 hours | > 0 |
| `dic_explanation_divergence_count` | Count of DIC-004 events in last 24 hours | > 0 |

### Dashboard Panels

1. **Containment Latency Heatmap:** Time-to-contain distribution over last 7 days
2. **Blast Radius Distribution:** Histogram of affected component counts
3. **Evidence Completeness Trend:** Line chart of evidence completeness over time
4. **Divergence Events:** Timeline of DIC-002 and DIC-004 events
5. **Explanation Latency Trend:** P50/P95/P99 explanation times

## Escalation Procedures

### Containment Divergence (DIC-002)

1. Immediately page on-call incident commander.
2. Freeze the containment engine (switch to manual-only mode).
3. Capture both divergent action sets and the input telemetry.
4. Root-cause the divergence source (likely non-deterministic input).
5. File a priority-1 bead for the fix.
6. Unfreeze only after replay test confirms determinism is restored.

### Explanation Divergence (DIC-004)

1. Alert the trust plane owner.
2. Quarantine the divergent evidence bundle.
3. Replay the bundle in an isolated environment with verbose logging.
4. Identify the non-deterministic step in the explanation pipeline.
5. File a priority-1 bead for the fix.
6. Re-run all recent explanations to check for historical divergence.

### Blast Radius Exceeded

1. Page on-call incident commander and trust plane owner.
2. Assess whether the excess isolation was necessary or a false positive.
3. If false positive, roll back excess containment actions.
4. Update blast radius bound if the incident legitimately requires it (requires RFC).

### Evidence Completeness Below Threshold

1. Alert the telemetry team.
2. Identify missing telemetry dimensions.
3. Determine if the gap is due to collection failure or schema mismatch.
4. Fix collection or update the schema within 24 hours.

## Evidence Requirements for Review

For each incident review, the following evidence must be present:

1. **Incident telemetry bundle:** Complete telemetry from detection through containment
2. **Containment action log:** Ordered list of actions taken with timestamps
3. **Evidence bundle:** All inputs to the explanation engine
4. **Explanation output:** Root-cause analysis document
5. **Replay receipt:** Proof that replaying the telemetry produces identical actions
6. **Replay explanation receipt:** Proof that replaying evidence produces identical explanation
7. **Metrics snapshot:** Dashboard metrics at the time of the incident

All evidence must be content-addressed (SHA-256 hashed) and stored in the
artifacts directory with a retention period of at least 90 days.
