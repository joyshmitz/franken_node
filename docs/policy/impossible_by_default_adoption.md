# Policy: Impossible-by-Default Adoption

**Bead:** bd-1xao | **Section:** 13 (Program Success Criteria Instrumentation)
**Effective:** 2026-02-20
**Owner:** Trust Plane (PP-03)

## Risk Description

If dangerous operations are not architecturally gated by default, the
impossible-by-default posture becomes a marketing claim rather than a measured
reality. Without instrumentation to track adoption coverage, bypass attempts,
and authorization audit completeness, the project cannot objectively prove its
security posture.

### Impact

- **Security gap:** Ungated dangerous operations create exploitable attack
  surfaces that undermine the entire trust model.
- **Compliance failure:** Auditors require measurable evidence that dangerous
  operations are controlled. Without adoption metrics, certification is blocked.
- **Operator risk:** Operators who bypass gates without detection may cause
  cascading failures in production.
- **Trust erosion:** Users and stakeholders lose confidence if the project
  cannot demonstrate measured adoption of its security posture.

### Likelihood

High. Without active instrumentation, coverage gaps accumulate silently as
new dangerous operations are added to the codebase without corresponding gates.

## Capability States

All dangerous capabilities are tracked through a strict state machine:

| State | Description | Default |
|-------|-------------|---------|
| BLOCKED | Architecturally prevented. No code path can invoke the capability. | Yes (all capabilities start here) |
| AUTHORIZED | Explicit authorization granted via approval workflow. | No |
| ACTIVE | In active use under granted authorization. | No |
| REVOKED | Authorization revoked. Returns to BLOCKED behavior. | No |

### State Transition Rules

- BLOCKED to AUTHORIZED requires approval workflow completion and emits IBD-002
- AUTHORIZED to ACTIVE requires operator activation and emits IBD-002
- ACTIVE to REVOKED requires revocation trigger and emits IBD-002
- REVOKED to AUTHORIZED requires re-approval and emits IBD-002
- Direct BLOCKED to ACTIVE is forbidden (bypass attempt, emits IBD-003)
- Direct REVOKED to ACTIVE is forbidden (bypass attempt, emits IBD-003)

## Adoption Tiers

| Tier | Coverage | Release Gate Status |
|------|----------|-------------------|
| A0 | < 50% | Not release-ready. Immediate remediation required. |
| A1 | 50% - 74% | Not release-ready. Remediation plan required within 7 days. |
| A2 | 75% - 89% | Not release-ready. Remediation plan required within 14 days. |
| A3 | 90% - 94% | Minimum acceptable for release gate. Continuous improvement required. |
| A4 | >= 95% | Full adoption. Release gate passes unconditionally. |

### Tier Calculation

Coverage percentage is computed as:

```
coverage = (gated_dangerous_operations / total_identified_dangerous_operations) * 100
```

Where:
- `gated_dangerous_operations` = count of operations with enforced state machine
- `total_identified_dangerous_operations` = count from the dangerous operations catalog

## Event Codes

| Code | Trigger | Severity | Response |
|------|---------|----------|----------|
| IBD-001 | Capability blocked by default (gate enforcement verified) | Info | Log and increment coverage metric |
| IBD-002 | Capability authorization state transition | Info | Log with full audit record |
| IBD-003 | Bypass attempt detected | Critical | Alert on-call, block attempt, increment bypass counter |
| IBD-004 | Adoption metric computed | Info | Update dashboard, evaluate release gate |

## Invariants

| ID | Statement | Enforcement |
|----|-----------|-------------|
| INV-IBD-DEFAULT | All identified dangerous operations are blocked by default | Compile-time gates and runtime checks |
| INV-IBD-AUTH | Authorization required for activation | State machine rejects BLOCKED-to-ACTIVE transitions |
| INV-IBD-AUDIT | All state transitions recorded | Audit log middleware on every transition |
| INV-IBD-COVERAGE | Coverage >= 95% for A4, >= 90% for release | Periodic metric computation with gate check |

## Monitoring and Dashboards

### Velocity Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `ibd_capability_coverage_pct` | Current adoption coverage percentage | < 90% |
| `ibd_bypass_attempts_count` | Count of IBD-003 events in last 24 hours | > 0 |
| `ibd_authorization_audit_completeness` | Percentage of transitions with full audit records | < 100% |
| `ibd_active_authorizations_count` | Count of currently ACTIVE capabilities | monitoring only |
| `ibd_mean_time_to_authorize_hours` | Average authorization decision latency | > 24 hours |
| `ibd_revocation_latency_minutes` | Time from revocation trigger to blocked state | > 60 minutes |

### Dashboard Panels

1. **Adoption Coverage Trend:** Line chart of coverage percentage over time
2. **Bypass Attempt Timeline:** Timeline of IBD-003 events with source attribution
3. **Authorization Audit Heatmap:** Completeness of audit records per capability category
4. **Tier Distribution:** Current tier with historical tier progression
5. **Active Authorization Inventory:** Table of all currently ACTIVE capabilities
6. **Revocation Latency Distribution:** Histogram of revocation response times

## Escalation Procedures

### Bypass Attempt Detected (IBD-003)

1. Immediately page on-call security engineer.
2. Block the bypass attempt at the gate.
3. Capture the full call stack and actor identity.
4. Determine if the bypass was accidental (code bug) or intentional (attack).
5. If intentional: escalate to incident commander and initiate security review.
6. If accidental: file a priority-1 bead to fix the missing gate.
7. Verify the fix prevents the same bypass path.

### Coverage Below Release Gate (< 90%)

1. Alert the trust plane owner and release manager.
2. Generate a gap report listing all ungated dangerous operations.
3. Prioritize gaps by risk severity and exploitability.
4. Assign beads for each gap with target completion dates.
5. Block release until coverage returns to A3 or higher.

### Authorization Audit Incomplete

1. Alert the audit team.
2. Identify state transitions missing audit records.
3. Determine root cause (logging failure, middleware bypass, race condition).
4. Backfill missing records where possible from secondary sources.
5. Fix the audit middleware within 24 hours.

### Revocation Latency Exceeded

1. Alert the security team.
2. Verify the capability is actually blocked (even if the metric shows delay).
3. If not blocked: manually force-block immediately.
4. Root-cause the latency (queue backlog, handler failure, network partition).
5. Fix within the current on-call rotation.

## Evidence Requirements

For each adoption review, the following evidence must be present:

1. **Coverage report:** Current coverage percentage with per-category breakdown
2. **Bypass attempt log:** All IBD-003 events since last review
3. **Authorization audit report:** Completeness percentage with any gaps identified
4. **Tier assessment:** Current tier with justification and trend
5. **Gap remediation plan:** For any coverage below A4, a plan to reach A4
6. **Active authorization inventory:** All currently ACTIVE capabilities with justifications
7. **Revocation log:** All revocations since last review with response times

All evidence must be content-addressed (SHA-256 hashed) and stored in the
artifacts directory with a retention period of at least 90 days.
