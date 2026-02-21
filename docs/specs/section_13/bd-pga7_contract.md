# bd-pga7: Deterministic Incident Containment and Explanation

## Scope

Ensure that incident containment and root-cause explanation are deterministic
and reproducible. Given identical incident telemetry, the system must take
identical containment actions. Given identical evidence bundles, the system
must produce identical root-cause explanations.

**Section:** 13 (Program Success Criteria)
**Predecessor:** bd-2a4l (Externally Verifiable Trust/Security Claims)

## Purpose

franken_node's incident response must be fully deterministic. When an incident
occurs, operators and auditors must be able to replay the same telemetry and
observe the same containment decisions and the same explanation output. This
eliminates ambiguity in post-incident review and ensures that containment
logic can be formally verified.

## Containment Dimensions

| Dimension | Description | Target |
|-----------|-------------|--------|
| `blast_radius_bound` | Maximum number of components affected by a single incident before containment activates | <= 3 components |
| `time_to_contain` | Maximum wall-clock seconds from incident detection to containment completion | <= 60 seconds |
| `automated_actions` | Deterministic actions taken in response to incident telemetry | See table below |

### Automated Containment Actions

| Action | Trigger Condition | Determinism Guarantee |
|--------|-------------------|----------------------|
| `isolate_component` | Component fault detected in telemetry | Same fault signature always isolates same component set |
| `shed_load` | Throughput exceeds safe threshold | Same load profile always sheds same percentage |
| `revoke_credentials` | Credential compromise signal in telemetry | Same signal always revokes same credential set |
| `disable_extension` | Extension misbehavior detected | Same misbehavior pattern always disables same extension |
| `snapshot_state` | Pre-containment state capture | Same trigger always captures same state dimensions |
| `emit_alert` | Any containment action taken | Same action set always produces same alert payload |

## Explanation Dimensions

| Dimension | Description | Target |
|-----------|-------------|--------|
| `evidence_completeness` | Percentage of relevant telemetry captured in the evidence bundle | >= 95% |
| `root_cause_reproducibility` | Replay of evidence bundle produces the same root-cause explanation | 100% (bit-identical) |
| `explanation_latency` | Maximum wall-clock seconds to produce a root-cause explanation from evidence | <= 120 seconds |

## Event Codes

| Code | Trigger |
|------|---------|
| DIC-001 | Incident contained deterministically (containment actions match expected for telemetry) |
| DIC-002 | Containment divergence detected (different containment actions from same telemetry) |
| DIC-003 | Root-cause explanation produced from evidence bundle |
| DIC-004 | Explanation divergence detected (different explanation from same evidence bundle) |

## Invariants

| ID | Statement |
|----|-----------|
| INV-DIC-CONTAIN | Containment is deterministic: same incident telemetry always produces same containment actions |
| INV-DIC-EXPLAIN | Explanation is reproducible: same evidence bundle always produces same root-cause explanation |
| INV-DIC-BOUND | Blast radius does not exceed the configured bound (default: 3 components) |
| INV-DIC-COMPLETE | Evidence bundle captures >= 95% of relevant telemetry for the incident |

## Quantitative Targets

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| blast_radius | <= 3 components | Count of components affected before containment completes |
| time_to_contain | <= 60 seconds | Wall-clock delta from detection to containment-complete event |
| evidence_completeness | >= 95% | Ratio of captured telemetry dimensions to total relevant dimensions |
| explanation_reproducibility | 100% | Bit-identical comparison of explanations from replayed evidence |

## Determinism Contract

### Containment Determinism

The containment engine is a pure function of incident telemetry:

```
containment_actions = f(incident_telemetry, policy_config)
```

All inputs are captured in the evidence bundle. No external state (wall-clock
time, random seeds, process IDs) may influence the containment decision.
Timestamps in telemetry are part of the input; the current wall-clock time
is not.

### Explanation Determinism

The explanation engine is a pure function of the evidence bundle:

```
explanation = g(evidence_bundle, analysis_config)
```

The explanation includes: identified root cause, causal chain, affected
components, timeline reconstruction, and recommended remediation. All of
these are deterministic from the same evidence bundle.

## Acceptance Criteria

1. Spec contract exists at `docs/specs/section_13/bd-pga7_contract.md` with all dimensions documented
2. Policy document exists at `docs/policy/deterministic_incident_containment.md` with risk, impact, and escalation
3. All four event codes (DIC-001 through DIC-004) are defined and documented
4. All four invariants (INV-DIC-CONTAIN, INV-DIC-EXPLAIN, INV-DIC-BOUND, INV-DIC-COMPLETE) are defined
5. Quantitative targets are specified: blast_radius <= 3, time_to_contain <= 60s, evidence_completeness >= 95%, explanation_reproducibility = 100%
6. Containment determinism contract is documented with pure-function semantics
7. Explanation determinism contract is documented with pure-function semantics
8. Verification script passes all checks
9. Evidence artifact and summary produced with PASS verdict

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_13/bd-pga7_contract.md` |
| Policy document | `docs/policy/deterministic_incident_containment.md` |
| Verification script | `scripts/check_incident_containment.py` |
| Python unit tests | `tests/test_check_incident_containment.py` |
| Verification evidence | `artifacts/section_13/bd-pga7/verification_evidence.json` |
| Verification summary | `artifacts/section_13/bd-pga7/verification_summary.md` |
