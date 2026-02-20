# bd-1mj: Claim-Language Policy Requiring Verifier Artifacts

## Decision Rationale

The canonical plan (Section 10.1, line 1012) requires a policy that all external product claims ship with reproducible, independently verifiable artifacts. The product charter states: "Claims without evidence are not claims." This bead codifies that principle into an enforceable policy with CI-gatable checks.

## Scope

**External claims** are statements about franken_node's capabilities published in:
- Release notes and changelogs
- README and product documentation
- Public benchmarks and scorecards
- Security advisories and audit reports
- Marketing and announcement materials

## Claim Categories

| Category | Example | Required Evidence |
|----------|---------|-------------------|
| **Compatibility** | ">=95% Node.js test corpus pass rate" | Test report artifact with pass/fail counts |
| **Security** | ">=10x reduction in host compromise" | Adversarial test results, audit report |
| **Performance** | "Cold-start <50ms" | Benchmark artifact with signed provenance |
| **Resilience** | "Fleet convergence in <30s" | E2E test evidence with replay capsule |
| **Migration** | ">=3x migration throughput" | Benchmark comparison artifact |

## Policy Rules

### Rule 1: No Unverified Claims
Every external claim MUST map to at least one verification artifact in `artifacts/`. Claims without artifacts are policy violations.

### Rule 2: Evidence Freshness
Evidence artifacts MUST include timestamps. Stale evidence (>90 days without refresh) triggers a warning. Release-blocking claims require evidence from the current release cycle.

### Rule 3: Reproducibility
All claim-backing artifacts MUST include a reproducibility pack (env.json + manifest.json + repro.lock) so any external party can independently reproduce the evidence.

### Rule 4: Claim Registry
All external claims MUST be registered in `docs/CLAIMS_REGISTRY.md` with:
- Claim text (exact wording)
- Category
- Evidence artifact path(s)
- Verification command
- Last verified timestamp

### Rule 5: CI Enforcement
A CI check scans the claims registry and verifies that:
- Every registered claim has at least one linked artifact
- Linked artifacts exist on disk
- Artifact evidence files are valid JSON with a `verdict` field
- No claim references a missing or broken artifact path

## Invariants

1. `docs/CLAIMS_REGISTRY.md` exists and is well-formed.
2. Every claim entry has non-empty `evidence_artifacts` paths.
3. All referenced artifact paths resolve to existing files.
4. All referenced evidence JSON files contain a `verdict` field.
5. No external-facing document contains unregistered claims.

## Interface Boundaries

- **Input**: `docs/CLAIMS_REGISTRY.md` (claim definitions)
- **Input**: `artifacts/` directory (evidence files)
- **Output**: PASS/FAIL verdict with per-claim status

## Failure Semantics

- Missing registry file: FAIL with instruction to create it
- Claim with no artifacts: FAIL per-claim
- Artifact path not found: FAIL per-claim
- Invalid evidence JSON: FAIL per-claim
- All claims verified: PASS
