# Risk Policy: Topology Blind Spots

**Bead:** bd-1n1t
**Section:** 12 — Risk Register Countermeasure Program
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Risk Description

The **Topology Blind Spots** risk arises when regions of the trust graph,
control plane, or monitoring infrastructure lack sufficient visibility for
operators and automated systems to detect anomalies, failures, or malicious
activity. Blind spots allow trust decisions to be made without audit trail,
control actions to propagate without observability, and failures to go
undetected until they cause downstream damage.

Root causes of topology blind spots:

- Trust decision nodes added to the architecture without monitoring hooks.
- Control plane actions that bypass the structured event emission pipeline.
- Subsystems deployed without telemetry instrumentation or with stale
  instrumentation that no longer covers the current topology.
- Implicit trust delegation chains with no explicit visibility contract.
- Configuration drift causing monitoring gaps after topology changes.
- Intentionally silent subsystems that are not documented in the allowlist.

## 2. Impact

| Dimension | Rating | Detail |
|-----------|--------|--------|
| Security | Critical | Unmonitored trust decisions may silently grant or deny without audit trail, enabling undetected compromise. |
| Operability | High | Operators cannot detect or diagnose failures in blind-spot regions until downstream effects are visible. |
| Availability | High | Dead zones mask cascading failures, delaying incident detection and response beyond acceptable windows. |
| Remediation | Medium | Once identified, blind spots can be instrumented within the 72-hour SLA using standard monitoring templates. |

## 3. Likelihood

| Factor | Assessment |
|--------|------------|
| Trust graph growth rate | High — new decision points are added as features ship. |
| Control plane expansion | Medium — new control actions introduced with each release cycle. |
| Telemetry coverage gaps | Medium — subsystems may ship without instrumentation if not gated. |
| Configuration drift | Medium — topology changes may invalidate existing monitoring rules. |
| Overall likelihood | **High** |

## 4. Countermeasure Details

### 4.1 Trust Graph Coverage Audit

A weekly automated audit enumerates all trust decision points in the
architecture and verifies that each has at least one active monitoring hook.

1. **Enumeration**: Crawl the trust graph registry to produce the full set
   of decision points (nodes).
2. **Coverage check**: For each node, verify at least one monitoring hook
   is registered and has emitted events within the last 7 days.
3. **Coverage calculation**: `monitored_nodes / total_nodes * 100`.
4. **Threshold enforcement**: Coverage must be >= 95% (INV-TBS-COVERAGE).
5. **Event emission**: TBS-001 emitted on completion with coverage
   percentage and per-node status.
6. **Failure action**: If coverage < 95%, generate blind spot tickets for
   unmonitored nodes and trigger escalation.

### 4.2 Control Plane Observability Contract

Every control action must emit a structured event within 5 seconds:

| Parameter | Value | Configurable |
|-----------|-------|-------------|
| Event latency bound | 5 seconds | Yes |
| Enforcement point | Control plane middleware | No |
| Blind spot event | TBS-002 | No |
| Monitoring | Real-time latency tracking | No |

Control actions that fail to emit events within the window:
- Are flagged with TBS-002.
- Generate a blind spot entry in the remediation register.
- Trigger the 72-hour remediation SLA.

### 4.3 Dead Zone Detection

Hourly automated scans detect subsystems with no telemetry in a rolling
24-hour window:

1. **Scan**: Query telemetry pipeline for last-seen timestamp per subsystem.
2. **Threshold**: Subsystems with no events in 24 hours are flagged.
3. **Allowlist**: Intentionally silent subsystems (e.g., cold standby) may
   be allowlisted with documented justification.
4. **Event**: TBS-003 emitted for each dead zone detected.
5. **Tracking**: Dead zones entered into the remediation register.

### 4.4 Blind Spot Remediation SLA

| Parameter | Value | Configurable |
|-----------|-------|-------------|
| Remediation deadline | 72 hours from discovery | Yes |
| Tracking | Remediation register | No |
| Completion event | TBS-004 | No |
| Escalation on breach | Automatic | No |

Remediation workflow:
1. Blind spot discovered (via audit, detection, or manual report).
2. Entry created in remediation register with timestamp.
3. Monitoring instrumentation added to the affected subsystem.
4. TBS-004 emitted on completion.
5. If 72-hour SLA breached, escalation triggered.

## 5. Escalation Procedures

When topology blind spots are detected:

1. **Immediate** (within 5 minutes):
   - Blind spot owner notified via dashboard alert.
   - TBS-002 or TBS-003 event emitted.
   - Entry created in remediation register.

2. **24-hour check-in**:
   - If remediation has not started, secondary notification sent.
   - Status update required in remediation register.

3. **72-hour SLA breach**:
   - Engineering lead notified.
   - Blind spot escalated to risk review board.
   - Mandatory review meeting scheduled within 4 hours.

4. **Coverage threshold breach** (< 95%):
   - All unmonitored nodes flagged for immediate remediation.
   - New feature deployments gated until coverage restored.
   - Weekly audit frequency increased to daily until threshold met.

## 6. Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires:

1. **Trust graph coverage report** — Weekly audit results showing coverage
   percentage and per-node monitoring status.
2. **Control plane event latency log** — Distribution of event emission
   latencies with any threshold violations flagged.
3. **Dead zone detection log** — Each dead zone detection with subsystem
   identity, last-seen timestamp, and remediation status.
4. **Remediation register** — All blind spots with discovery time,
   remediation time, and SLA compliance status.
5. **Invariant status** — Confirmation that INV-TBS-COVERAGE,
   INV-TBS-OBSERVE, INV-TBS-DETECT, and INV-TBS-REMEDIATE are satisfied.
6. **Escalation log** — Record of any SLA breaches and escalation actions.

Reviews are conducted monthly or after any coverage threshold breach,
whichever comes first.
