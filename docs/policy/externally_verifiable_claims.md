# Externally Verifiable Trust/Security Claims

**Bead:** bd-2a4l | **Section:** 13

## Principle

franken_node makes zero trust/security claims that cannot be independently
verified. Every claim is backed by a reproducible evidence bundle that an
external party can audit using only public tools and public inputs.

## Claim Registry

All public trust and security claims are enumerated in a machine-readable
claim registry. Each entry contains:

- **Claim ID**: Unique identifier (e.g., `CLAIM-COMPAT-001`)
- **Statement**: The exact claim text
- **Category**: One of `compatibility`, `security`, `trust`, `performance`, `migration`
- **Evidence path**: Content-addressed path to the evidence bundle
- **Evidence hash**: SHA-256 of the evidence bundle
- **Last verified**: ISO 8601 timestamp of most recent verification
- **Staleness threshold**: Maximum age before the claim is considered stale (default: 30 days)

## Evidence Bundle Format

Each evidence bundle is a self-contained directory or archive containing:

```
bundle/
  claim.json          # Claim statement and metadata
  procedure.md        # Step-by-step verification procedure
  inputs/             # All input data needed for reproduction
  expected_output/    # Expected verification results
  actual_output/      # Actual results from the latest run
  manifest.json       # SHA-256 hashes of all files in the bundle
```

### Content Addressing

The bundle's top-level hash is the SHA-256 of `manifest.json`. This hash
appears in the claim registry and in release notes. Any modification to
any file in the bundle changes the manifest hash, making tampering
detectable.

## Reproduction Protocol

### Prerequisites for External Verifiers

External parties need only:
- A POSIX-compatible system (Linux/macOS)
- Rust toolchain (stable or nightly as specified in `rust-toolchain.toml`)
- Python 3.11+ (for verification scripts)
- No proprietary dependencies, internal APIs, or privileged network access

### Reproduction Steps

1. Clone the public repository at the tagged release commit.
2. Locate the evidence bundle for the claim under `artifacts/`.
3. Follow `procedure.md` in the bundle.
4. Compare outputs against `expected_output/`.
5. Verify `manifest.json` hashes match actual file contents.

### Determinism Guarantees

Verification procedures strip or pin all sources of non-determinism:
- Timestamps are replaced with epoch zero or stripped entirely
- Process IDs are masked with placeholder values
- Random seeds are pinned in procedure configuration
- File paths are canonicalized relative to repository root

## Adversarial Resilience

The verification system is tested against adversarial perturbations:

| Perturbation | Expected behavior |
|-------------|-------------------|
| Corrupted input file | Verification fails with clear error, EVC-004 emitted |
| Truncated evidence bundle | Manifest hash mismatch detected, bundle rejected |
| Tampered hash in manifest | Integrity check fails, EVC-004 emitted |
| Replayed old bundle with new claim | Staleness check fails, EVC-003 then EVC-002 emitted |
| Missing evidence for a claim | CI gate blocks release, EVC-002 emitted |

## CI Integration

### Release Gate

The CI pipeline runs a claim-coverage check before every release:
1. Parse the claim registry.
2. For each claim, verify the evidence bundle exists and passes integrity.
3. Check evidence freshness (< 30 days at release time).
4. Run reproduction procedure for a random sample (>= 20%) of claims.
5. Block release if any claim is orphaned, stale, or fails verification.

### Freshness Monitoring

A nightly job checks all evidence bundles for approaching staleness
(within 7 days of threshold). EVC-003 warnings are emitted and routed
to the owning track's on-call.

## Claim Categories

### Compatibility Claims

Backed by lockstep oracle evidence bundles from bd-1w78 continuous
validation. Include: API compatibility scores, divergence receipts,
mode transition records.

### Security Claims

Backed by security doctrine evidence from bd-ud5h. Include: adversary
model coverage, trust surface enumeration, safety target measurements.

### Trust Claims

Backed by EV score and trust card evidence. Include: tier assignments,
verification dimension scores, audit trail records.

### Performance Claims

Backed by benchmark evidence from performance doctrine bd-2vl5. Include:
cold-start measurements, overhead ratios, throughput benchmarks.

### Migration Claims

Backed by migration pathway evidence from bd-2f43. Include: success
rates, rollback times, risk scores for reference archetypes.

## Governance

- Claim registry is maintained by the trust plane (PP-03) owner.
- New claims require evidence bundles before merge.
- Claim removal requires deprecation notice in release notes.
- Weight/threshold changes to the verification system require RFC.
