# Claim-Language Policy: Asupersync-Backed Invariant Evidence Requirements

**Section:** 10.15 | **Bead:** bd-33kj | **Status:** Active

## Purpose

This policy defines the formal requirements for tying trust, replay, and safety
claims made in franken_node documentation, APIs, and release materials to
asupersync-backed invariant evidence. Every public claim must be grounded in a
specific, verifiable invariant enforced by the asupersync correctness kernel, with
a machine-readable evidence reference that can be independently validated.

No claim may exist in documentation without an approved template and a verified
evidence anchor. This prevents aspirational, vague, or unsubstantiated language
from entering the project's public surface.

---

## 1. Claim Taxonomy

### 1.1 Trust Claims

**Definition:** Assertions about the integrity, authenticity, or provenance
guarantees that franken_node provides for data, operations, or artifacts.

Trust claims assert that a specific trust property holds under defined conditions,
backed by asupersync epoch-scoped invariants.

**Examples:**
- Epoch-scoped key binding for artifact provenance
- Fail-closed behavior on epoch unavailability
- Split-brain detection via bounded-lag guards

**Required evidence references:**
- At least one `INV-EP-*` invariant identifier
- An evidence artifact path under `artifacts/` with `"verdict": "PASS"`
- The conformance test that validates the invariant (test file path or test name)

### 1.2 Replay Claims

**Definition:** Assertions about the deterministic reproducibility of operations,
state transitions, or execution traces within the franken_node system.

Replay claims assert that a given operation or sequence can be faithfully replayed
from recorded evidence, producing identical results.

**Examples:**
- Deterministic replay of trust-native executions
- Epoch-transition replay with drain-barrier enforcement
- Incident bundle replay for forensic reconstruction

**Required evidence references:**
- At least one `INV-EP-*` or `INV-RP-*` invariant identifier
- An evidence artifact path under `artifacts/` with `"verdict": "PASS"`
- A replay conformance test or replay bundle artifact

### 1.3 Safety Claims

**Definition:** Assertions about the system's behavior under failure, attack,
or degraded conditions -- guaranteeing that unsafe states are prevented or
contained.

Safety claims assert that franken_node prevents or mitigates specific failure
modes through structural invariants.

**Examples:**
- Compromise reduction via evidence-by-default audit trails
- Immutable creation epochs preventing retroactive tampering
- Fail-closed error surfaces on component unavailability

**Required evidence references:**
- At least one `INV-EP-*`, `INV-SF-*`, or `INV-CR-*` invariant identifier
- An evidence artifact path under `artifacts/` with `"verdict": "PASS"`
- A security or safety conformance test

---

## 2. Approved Claim Templates

Each approved template embeds an evidence reference pattern. Claims in
documentation MUST follow one of these templates or be registered as a new
template through the process in Section 4.

### Template T-TRUST-01: Epoch-Scoped Trust Binding

> Trust-native execution with epoch-scoped keys ensures artifact provenance
> is cryptographically bound to the issuing epoch.
> [verified by epoch_key_derivation conformance test, INV-EP-FAIL-CLOSED]

### Template T-TRUST-02: Fail-Closed Epoch Availability

> Epoch unavailability triggers fail-closed behavior: operations return a
> structured error rather than proceeding with stale epoch data.
> [verified by epoch_transition_barrier conformance test, INV-EP-FAIL-CLOSED]

### Template T-REPLAY-01: Deterministic Execution Replay

> Cancellation follows the request-drain-finalize protocol, ensuring
> deterministic replay of trust-native executions.
> [verified by cancel_drain_finalize conformance test, INV-EP-MONOTONIC, INV-EP-DRAIN-BARRIER]

### Template T-REPLAY-02: Incident Bundle Reconstruction

> Incident bundles capture sufficient state for forensic replay, with all
> non-determinism sources pinned at recording time.
> [verified by incident_bundle_retention conformance test, INV-RP-DETERMINISTIC]

### Template T-SAFETY-01: Compromise Reduction via Evidence-by-Default

> Compromise reduction is achieved through evidence-by-default audit trails
> that record all epoch transitions with full metadata.
> [verified by control_evidence_replay conformance test, INV-EP-AUDIT-HISTORY, INV-CR-EVIDENCE-DEFAULT]

### Template T-SAFETY-02: Immutable Creation Epoch

> Artifact creation epochs are set once at creation time and are structurally
> prevented from mutation, ensuring retroactive tampering is detectable.
> [verified by epoch_key_derivation conformance test, INV-EP-IMMUTABLE-CREATION-EPOCH]

---

## 3. Prohibited Phrasings

The following phrasings are prohibited in all documentation, API descriptions,
release notes, and marketing materials. These represent vague or unsubstantiated
language that cannot be tied to invariant evidence.

| Prohibited Phrasing | Reason |
|---------------------|--------|
| "military-grade security" | Undefined standard; no corresponding invariant |
| "guaranteed uptime" | Availability is not an asupersync-backed invariant |
| "incredibly reliable" | Subjective qualifier without measurable criterion |
| "enterprise-grade" | Marketing term without technical definition |
| "unbreakable" | Absolute claim that no evidence can substantiate |

### Additional Prohibited Patterns

- Unqualified superlatives: "best-in-class", "world-class", "state-of-the-art"
  (unless citing a specific benchmark with evidence)
- Aspirational language without evidence: "designed to", "aims to", "will provide"
  (future claims must be clearly marked as roadmap items, not capabilities)
- Bare assertions without evidence anchors: any claim-like sentence in a
  capability section that lacks a `[verified by ...]` reference or an
  `<!-- claim:... artifact:... -->` annotation

---

## 4. Adding New Approved Templates

To register a new approved claim template:

1. **Identify the backing invariant(s).** The claim must map to one or more
   `INV-*` identifiers enforced by asupersync. If no invariant exists, the
   invariant must be defined and implemented first.

2. **Create or identify the conformance test.** The invariant must be validated
   by a conformance test under `tests/conformance/` that produces a PASS/FAIL
   result.

3. **Create the evidence artifact.** The test must produce or reference an
   evidence artifact under `artifacts/` with a `"verdict"` field.

4. **Draft the template.** Write the claim text with an embedded evidence
   reference following the pattern:
   ```
   > [Claim statement].
   > [verified by <test_name> conformance test, <INV-ID-1>, <INV-ID-2>]
   ```

5. **Submit for review.** Add the template to Section 2 of this document via
   pull request. The PR must include:
   - The template text
   - The invariant ID(s)
   - The conformance test path
   - The evidence artifact path

6. **Gate validation.** The claim language gate (`tests/conformance/claim_language_gate.rs`)
   must pass after the template is added. The gate validates that all claims
   in documentation match approved templates or carry evidence references.

---

## 5. Enforcement: Claim Language Gate

### Gate Operation

The claim language gate scans all markdown files under `docs/` for claim-like
language and validates each detected claim against the approved templates and
evidence reference requirements.

### Scan Targets

- `docs/**/*.md` -- all policy, spec, and integration documents
- `README.md` -- project root readme
- `CHANGELOG.md` -- release notes

### Detection Patterns

The gate detects claim-like language by matching sentences that contain:
- Trust-related keywords: "trust", "provenance", "authenticity", "integrity"
- Replay-related keywords: "replay", "deterministic", "reproducible"
- Safety-related keywords: "safety", "compromise", "immutable", "fail-closed"

### Validation Rules

1. **Evidence anchor required.** Detected claims must contain either:
   - A `[verified by ...]` inline reference, or
   - An `<!-- claim:... artifact:... -->` HTML comment annotation

2. **Template match.** Claims should match an approved template from Section 2.
   Novel claims without a template trigger a warning (not a hard failure) to
   allow for template registration.

3. **Prohibited phrasing rejection.** Any prohibited phrasing from Section 3
   triggers a hard FAIL regardless of evidence anchors.

4. **Broken reference detection.** Evidence references that point to
   non-existent artifact files trigger a hard FAIL.

### Gate Invocation

```bash
cargo test --test claim_language_gate
```

### Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| CLG-001 | info | Claim detected and validated against approved template |
| CLG-002 | error | Claim detected without evidence anchor |
| CLG-003 | error | Prohibited phrasing detected |
| CLG-004 | error | Evidence reference points to non-existent artifact |
| CLG-005 | info | Gate scan completed |
| CLG-006 | warn | Novel claim detected without matching template |

---

## 6. Claim-Invariant Mapping Reference

| Claim Type | Required Invariant Prefix | Minimum Invariants |
|------------|--------------------------|-------------------|
| Trust | `INV-EP-*` | 1 |
| Replay | `INV-EP-*` or `INV-RP-*` | 1 |
| Safety | `INV-EP-*`, `INV-SF-*`, or `INV-CR-*` | 1 |

### Invariant Registry

| Invariant ID | Statement | Claim Types |
|-------------|-----------|-------------|
| INV-EP-MONOTONIC | Epoch transitions are strictly monotonically increasing | trust, replay |
| INV-EP-DRAIN-BARRIER | All in-flight operations drain before epoch advance | replay |
| INV-EP-FAIL-CLOSED | Unavailable epoch source returns error, never stale data | trust, safety |
| INV-EP-SPLIT-BRAIN-GUARD | Bounded lag guard prevents split-brain across replicas | trust |
| INV-EP-IMMUTABLE-CREATION-EPOCH | Artifact creation epoch is set once and never mutated | safety |
| INV-EP-AUDIT-HISTORY | All epoch transitions are recorded with full metadata | safety |
| INV-RP-DETERMINISTIC | Replay produces identical results from recorded state | replay |
| INV-CR-EVIDENCE-DEFAULT | Evidence is recorded by default for all state transitions | safety |

---

## 7. Verification

Run the claim language gate:

```bash
cargo test --test claim_language_gate -- --nocapture
```

Gate report artifact:

```
artifacts/10.15/claim_language_gate_report.json
```
