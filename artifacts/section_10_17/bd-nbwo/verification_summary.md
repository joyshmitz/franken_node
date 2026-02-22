# bd-nbwo: Universal Verifier SDK and Replay Capsule Format

**Section:** 10.17 -- Radical Expansion Execution Track
**Verdict:** PASS

## Summary

This bead publishes a universal verifier SDK and replay capsule format that
enables external verifiers to replay signed capsules and reproduce claim
verdicts without privileged internal access. The capsule schema (`vsdk-v1.0`)
and verification APIs are stable and versioned.

## Implementation

**Module:** `crates/franken-node/src/connector/universal_verifier_sdk.rs`

### Types (9)

- `CapsuleVerdict` -- Enum: Pass, Fail, Inconclusive
- `CapsuleManifest` -- Describes capsule contents, schema version, expected outputs
- `ReplayCapsule` -- Signed, self-contained replay unit with deterministic inputs/outputs
- `ReplayResult` -- Outcome of replaying a capsule
- `SessionStep` -- Single step in a multi-step verification session
- `VerificationSession` -- Stateful session for multi-step verification workflows
- `VerifierSdk` -- Top-level facade for external verifiers
- `VsdkEvent` -- Structured audit event for telemetry
- `VsdkError` -- Error type with 7 ERR_VSDK_* codes

### Core Operations (8)

- `validate_manifest` -- Validate capsule manifest completeness and schema version
- `verify_capsule_signature` -- Verify capsule signature covers full payload
- `sign_capsule` -- Compute and set capsule signature
- `replay_capsule` -- Replay capsule and produce verdict
- `create_session` -- Create new verification session
- `record_session_step` -- Append replay result to session
- `seal_session` -- Seal session and compute final verdict
- `create_verifier_sdk` -- Create SDK facade instance

### Invariants (5)

| ID | Description |
|----|-------------|
| INV-VSDK-CAPSULE-DETERMINISTIC | Same capsule always produces same verdict |
| INV-VSDK-NO-PRIVILEGE | No privileged internal access required |
| INV-VSDK-SCHEMA-VERSIONED | Every capsule carries schema version |
| INV-VSDK-SESSION-MONOTONIC | Session steps are append-only |
| INV-VSDK-SIGNATURE-BOUND | Signature covers manifest + payload + inputs |

### Event Codes (7)

VSDK_001 through VSDK_007 covering capsule replay start, completion (pass/fail),
session creation, step recording, signature verification, and manifest validation.

### Error Codes (7)

ERR_VSDK_CAPSULE_INVALID, ERR_VSDK_SIGNATURE_MISMATCH, ERR_VSDK_SCHEMA_UNSUPPORTED,
ERR_VSDK_REPLAY_DIVERGED, ERR_VSDK_SESSION_SEALED, ERR_VSDK_MANIFEST_INCOMPLETE,
ERR_VSDK_EMPTY_PAYLOAD.

## Verification

- Check script: `scripts/check_universal_verifier_sdk.py`
- Test suite: `tests/test_check_universal_verifier_sdk.py`
- Rust unit tests: 47+ inline `#[cfg(test)]` tests
- All types are Send + Sync, serde-serializable, BTreeMap for determinism

## Relationship to Existing Code

This module extends the verifier-economy SDK (`connector::verifier_sdk`, bd-3c2,
Section 10.12) with universally accessible capsule replay. Where bd-3c2 provides
claim/evidence/bundle verification primitives, bd-nbwo adds signed replay
capsules, verification sessions, and a stable external API surface.
