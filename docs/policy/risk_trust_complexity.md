# Risk Policy: Trust-System Complexity

**Bead:** bd-kiqr
**Section:** 12 — Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Risk Description

The **Trust-System Complexity** risk arises when the layered trust
architecture of franken_node becomes too complex for operators to reason
about, configure, and debug. The system employs multiple trust mechanisms:
capability tokens (RemoteCap), epoch-scoped keys, fencing tokens, mTLS
certificates, API keys, bearer tokens, and challenge flows. When these
interact without clear precedence rules and deterministic behaviour,
operators cannot predict or reproduce trust decisions.

Root causes of trust-system complexity:
- Multiple overlapping trust mechanisms without clear interaction rules.
- Trust decisions depending on non-local state (epoch clocks, quorum).
- Degraded-mode behaviour differing from normal-mode without documentation.
- Non-deterministic trust-chain validation due to timing or ordering.
- Absence of complexity budgets allowing unbounded decision chains.

## 2. Impact

| Dimension | Rating | Detail |
|-----------|--------|--------|
| Security | Critical | Non-deterministic trust decisions may silently bypass controls. |
| Operability | High | Operators cannot debug trust failures without replay capability. |
| Availability | High | Degraded-mode without explicit contracts causes unpredictable behaviour. |
| Remediation | Medium | Replay and audit mechanisms enable post-incident analysis. |

## 3. Likelihood

| Factor | Assessment |
|--------|------------|
| Trust mechanism count | High — 6+ distinct trust mechanisms across the system. |
| Cross-subsystem deps | High — trust decisions depend on epoch, quorum, certificate services. |
| Degraded-mode frequency | Medium — network partitions and service restarts trigger degraded mode. |
| Overall likelihood | **High** |

## 4. Countermeasure Details

### 4.1 Trust Decision Replay

Every trust decision is recorded with sufficient context to replay
deterministically:

1. Input capture: token type, token value hash, epoch, capability set,
   clock value, caller identity.
2. Decision recording: outcome (grant/deny/escalate/degraded), decision
   path (ordered list of checks), latency.
3. Replay verification: recorded inputs fed to the same decision function
   produce the identical outcome.
4. Event emission: **RTC-001** on successful replay, **RTC-002** on
   divergence.
5. Storage: decision contexts retained for 30 days minimum.

### 4.2 Degraded-Mode Trust Contract

When trust subsystems are unavailable:

| Parameter | Default | Configurable |
|-----------|---------|-------------|
| Max degraded duration | 300s | Yes |
| Permitted operations | Cached capability set only | Yes |
| Auto safe-mode transition | After max duration | Yes |
| Degraded-mode logging | All decisions logged with RTC-003 | No |

Degraded-mode activates when:
- Epoch service is unreachable for > 5s.
- Quorum service returns timeout or error.
- Certificate validation service is unavailable.

Exit criteria:
- Trust subsystem recovers and passes health check.
- Operator explicitly exits degraded mode with verification.

### 4.3 Trust Complexity Budget

Per-decision-path depth limits:

| Parameter | Default | Configurable |
|-----------|---------|-------------|
| Max decision depth | 5 checks | Yes |
| Warning threshold | 4 checks | Yes |
| Hard reject threshold | 6 checks | Yes |

When decision depth reaches:
- **4 checks**: Warning logged, decision proceeds.
- **5 checks**: Decision proceeds, **RTC-004** emitted.
- **6+ checks**: Decision rejected, **RTC-004** emitted.

### 4.4 Monitoring

Trust decision health is monitored via:

- **Trust decision dashboard**: Real-time display of decision counts by
  outcome, average path depth, replay verification rate.
- **Replay verification metrics**: Rolling success rate with target of 100%.
- **Degraded-mode tracker**: Activation count, duration, and cached
  capability set utilization.
- **Complexity budget utilization**: Per-group decision depth distribution.
- **Velocity metrics**: Decision rate trends by endpoint group.

## 5. Escalation Procedures

When trust-system anomalies are detected:

1. **Immediate** (within 1 minute):
   - Trust-system owner notified via dashboard alert.
   - Affected endpoint blocked if replay divergence detected.
   - Event **RTC-002** or **RTC-004** emitted.

2. **5-minute escalation**:
   - If degraded mode has been active > 300s, auto safe-mode transition.
   - Operator receives safe-mode notification with recovery steps.

3. **1-hour escalation**:
   - Multiple degraded-mode activations trigger engineering lead notification.
   - Trust-system review meeting scheduled within 4 hours.

4. **Replay divergence resolution**:
   - Divergence receipt generated with full decision context.
   - Root cause analysis required before endpoint unblocked.
   - Fix must include regression test verifying determinism.

## 6. Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires:
1. **Replay verification log** — All trust decision replays with pass/fail.
2. **Degraded-mode activation log** — Each activation with duration, cached
   capabilities used, and recovery outcome.
3. **Complexity budget utilization** — Decision depth distribution per group.
4. **Trust decision audit** — Counts by outcome across all endpoint groups.
5. **Invariant status** — Confirmation that INV-RTC-REPLAY, INV-RTC-DEGRADED,
   INV-RTC-BUDGET, and INV-RTC-AUDIT are satisfied.
6. **Escalation log** — Record of any escalations since last review.

Reviews are conducted monthly or after any replay divergence, whichever
comes first.
