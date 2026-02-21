# bd-kiqr: Risk Control — Trust-System Complexity

**Bead:** bd-kiqr
**Section:** 12 — Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## Scope

The Trust-System Complexity risk arises when the layered trust architecture
(capability tokens, epoch-scoped keys, fencing, challenge flows, certificate
chains) becomes too complex for operators to reason about. Misconfiguration,
silent trust-path failures, and non-deterministic trust decisions erode
safety guarantees.

This contract defines countermeasures, invariants, and event codes that
govern trust-system complexity detection and enforcement.

## Risk Description

Trust-system complexity grows when:
- Multiple overlapping trust mechanisms (capability tokens, mTLS, API keys,
  epoch keys) interact without clear precedence rules.
- Trust decisions depend on non-local state (remote quorum, epoch clocks)
  that may be unavailable or stale.
- Degraded-mode behaviour differs from normal-mode in ways that are not
  documented or tested.
- Trust-chain validation paths are not deterministically replayable.

Left unchecked, trust-system complexity leads to misconfiguration, silent
security bypasses, non-reproducible trust failures, and operator confusion.

## Countermeasures

### 1. Trust Decision Replay

Every trust decision (grant, deny, escalate) must be deterministically
replayable from a recorded decision context. The replay mechanism:
- Captures all inputs (token, epoch, capability set, clock value).
- Produces an identical decision when replayed with the same inputs.
- Emits **RTC-001** on successful replay verification.
- Emits **RTC-002** on replay divergence (non-determinism detected).

### 2. Degraded-Mode Trust Contract

When trust subsystems are unavailable (epoch service down, quorum
unreachable), the system enters degraded mode with explicit contracts:
- Only pre-authorized operations permitted (cached capability set).
- All degraded-mode decisions are logged with **RTC-003**.
- Degraded mode has a maximum duration (configurable, default 300s).
- Exceeding the duration triggers automatic safe-mode transition.

### 3. Trust Complexity Budget

Each trust decision path has a maximum depth (number of trust checks
in the chain). The default maximum is 5 checks per decision.
- Decisions exceeding the complexity budget emit **RTC-004** and are
  rejected.
- The budget is configurable per endpoint group.

### 4. Trust Decision Audit Dashboard

A dashboard tracks:
- Trust decision counts by outcome (grant/deny/escalate/degraded).
- Average decision path depth across endpoint groups.
- Replay verification success rate (target: 100%).
- Degraded-mode activation frequency and duration.

## Event Codes

| Code | Trigger |
|------|---------|
| RTC-001 | Trust decision replay verified — deterministic |
| RTC-002 | Trust decision replay diverged — non-determinism detected |
| RTC-003 | Degraded-mode trust decision — subsystem unavailable |
| RTC-004 | Trust complexity budget exceeded — decision chain too deep |

## Invariants

| ID | Statement |
|----|-----------|
| INV-RTC-REPLAY | Every trust decision is deterministically replayable from recorded context |
| INV-RTC-DEGRADED | Degraded-mode trust has an explicit contract with maximum duration and cached-only operations |
| INV-RTC-BUDGET | Trust decision chain depth does not exceed configured complexity budget |
| INV-RTC-AUDIT | Trust decision outcomes are tracked with dashboard visibility |

## Threshold Enforcement

| Level | Condition | Action |
|-------|-----------|--------|
| Green | Replay rate 100%, no degraded-mode activations | No action |
| Warning | Replay rate < 100% or degraded-mode activated | Alert trust-system owner |
| Critical | Replay divergence detected or complexity budget exceeded | Block deployment; escalation |

The **hard threshold** is replay divergence count = 0 in production.

## Alert Pipeline

```
Trust Decision
  |
  v
Record decision context
  |
  v
Replay verification
  |
  +-- Deterministic --> log RTC-001, continue
  |
  +-- Divergence --> log RTC-002, fire CRITICAL alert
                     block affected endpoint
```

## Escalation Procedures

| Trigger | Escalation |
|---------|------------|
| Replay divergence detected | Trust-system owner notified; endpoint blocked |
| Degraded mode > 300s | Auto-transition to safe mode; operator alert |
| Complexity budget exceeded | Decision rejected; endpoint owner notified |
| Multiple degraded-mode activations in 1h | Engineering lead escalation |

## Evidence Requirements for Risk Mitigation Review

1. **Replay verification log** — All trust decision replays with pass/fail.
2. **Degraded-mode activation log** — Duration, cached capabilities used.
3. **Complexity budget utilization** — Decision depth distribution.
4. **Trust decision audit** — Counts by outcome across all endpoint groups.
5. **Invariant status** — Confirmation of all four invariants.
6. **Escalation log** — Record of any escalations since last review.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_12/bd-kiqr_contract.md` |
| Risk policy | `docs/policy/risk_trust_complexity.md` |
| Verification script | `scripts/check_trust_complexity.py` |
| Python unit tests | `tests/test_check_trust_complexity.py` |
| Verification evidence | `artifacts/section_12/bd-kiqr/verification_evidence.json` |
| Verification summary | `artifacts/section_12/bd-kiqr/verification_summary.md` |
