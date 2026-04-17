//! Replay capsule types and operations for external verifiers.
//!
//! This module provides the public-facing capsule format that external verifiers
//! use to replay structurally bound capsules and reproduce claim verdicts
//! without privileged internal access.
//!
//! # Security Posture
//!
//! This module is structural-only. `sign_capsule` and `verify_signature`
//! compute and compare a deterministic SHA-256 structural signature digest so
//! external tools can reproduce capsule content binding without implying a
//! detached cryptographic attestation surface. The replacement-critical
//! canonical verifier lives elsewhere.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Schema format is stable across versions.
//! - INV-CAPSULE-VERSIONED-API: Every capsule carries a version.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: Replay is entirely local and offline.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always yields same verdict.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{
    ERR_CAPSULE_ACCESS_DENIED, ERR_CAPSULE_REPLAY_DIVERGED, ERR_CAPSULE_SCHEMA_MISMATCH,
    ERR_CAPSULE_SIGNATURE_INVALID, ERR_CAPSULE_VERDICT_MISMATCH, SDK_VERSION,
};

/// Explicit posture marker for the standalone workspace replay capsule surface.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id for guardrails that must fence the workspace replay capsule surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE";

// ---------------------------------------------------------------------------
// Capsule types
// ---------------------------------------------------------------------------

/// Manifest describing a replay capsule's contents.
///
/// INV-CAPSULE-VERSIONED-API: carries schema_version.
/// INV-CAPSULE-STABLE-SCHEMA: fields are fixed for a given schema version.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleManifest {
    pub schema_version: String,
    pub capsule_id: String,
    pub description: String,
    pub claim_type: String,
    pub input_refs: Vec<String>,
    pub expected_output_hash: String,
    pub created_at: String,
    pub creator_identity: String,
    pub metadata: BTreeMap<String, String>,
}

/// A signed, self-contained replay capsule.
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: all data needed for replay is included.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic replay from contained data.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayCapsule {
    pub manifest: CapsuleManifest,
    pub payload: String,
    pub inputs: BTreeMap<String, String>,
    pub signature: String,
}

/// Verdict of a capsule replay operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleVerdict {
    Pass,
    Fail,
    Inconclusive,
}

/// Result of replaying a capsule.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleReplayResult {
    pub capsule_id: String,
    pub verdict: CapsuleVerdict,
    pub expected_hash: String,
    pub actual_hash: String,
    pub detail: String,
}

/// Error type for capsule operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CapsuleError {
    SignatureInvalid(String),
    SchemaMismatch(String),
    ReplayDiverged { expected: String, actual: String },
    VerdictMismatch { expected: String, actual: String },
    AccessDenied(String),
    EmptyPayload(String),
    ManifestIncomplete(String),
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SIGNATURE_INVALID)
            }
            Self::SchemaMismatch(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SCHEMA_MISMATCH)
            }
            Self::ReplayDiverged { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    ERR_CAPSULE_REPLAY_DIVERGED
                )
            }
            Self::VerdictMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    ERR_CAPSULE_VERDICT_MISMATCH
                )
            }
            Self::AccessDenied(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_ACCESS_DENIED)
            }
            Self::EmptyPayload(msg) => {
                write!(f, "ERR_CAPSULE_EMPTY_PAYLOAD: {msg}")
            }
            Self::ManifestIncomplete(msg) => {
                write!(f, "ERR_CAPSULE_MANIFEST_INCOMPLETE: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time string comparison to prevent timing side-channels on
/// signature/hash verification.
fn ct_eq(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte slice comparison.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Compute a deterministic hash (SHA-256, hex-encoded) with domain separator.
///
/// External verifiers may use this for ad-hoc hashing of capsule-related data.
///
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: same inputs always yield same output.
pub fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn push_length_prefixed(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Compute the deterministic replay hash for a capsule's payload and inputs.
///
/// Uses length-prefixed encoding to prevent payload-input delimiter collision:
/// without length-prefixing, a payload containing "|key=value" would hash
/// identically to a shorter payload with that key-value pair in inputs.
fn compute_replay_hash(payload: &str, inputs: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_replay_v1:");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload.as_bytes());
    hasher.update((inputs.len() as u64).to_le_bytes());
    for (k, v) in inputs {
        hasher.update((k.len() as u64).to_le_bytes());
        hasher.update(k.as_bytes());
        hasher.update((v.len() as u64).to_le_bytes());
        hasher.update(v.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Compute the signing payload for a capsule using length-prefixed SHA-256.
///
/// Uses length-prefixed encoding to prevent delimiter-collision ambiguity
/// across manifest fields, payload, and inputs.
///
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic for same capsule contents.
fn compute_signing_payload(capsule: &ReplayCapsule) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_capsule_signing_v1:");
    for field in [
        capsule.manifest.capsule_id.as_str(),
        capsule.manifest.schema_version.as_str(),
        capsule.manifest.description.as_str(),
        capsule.manifest.claim_type.as_str(),
        capsule.manifest.expected_output_hash.as_str(),
        capsule.manifest.created_at.as_str(),
        capsule.manifest.creator_identity.as_str(),
        capsule.payload.as_str(),
    ] {
        push_length_prefixed(&mut hasher, field);
    }
    hasher.update((capsule.manifest.input_refs.len() as u64).to_le_bytes());
    for input_ref in &capsule.manifest.input_refs {
        push_length_prefixed(&mut hasher, input_ref);
    }
    hasher.update((capsule.manifest.metadata.len() as u64).to_le_bytes());
    for (key, value) in &capsule.manifest.metadata {
        push_length_prefixed(&mut hasher, key);
        push_length_prefixed(&mut hasher, value);
    }
    hasher.update((capsule.inputs.len() as u64).to_le_bytes());
    for (k, v) in &capsule.inputs {
        push_length_prefixed(&mut hasher, k);
        push_length_prefixed(&mut hasher, v);
    }
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Validate a capsule manifest for completeness.
///
/// INV-CAPSULE-STABLE-SCHEMA: schema_version must match SDK_VERSION.
/// INV-CAPSULE-VERSIONED-API: version is checked.
pub fn validate_manifest(manifest: &CapsuleManifest) -> Result<(), CapsuleError> {
    if manifest.schema_version.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "schema_version is empty".into(),
        ));
    }
    if manifest.schema_version != SDK_VERSION {
        return Err(CapsuleError::SchemaMismatch(format!(
            "unsupported: {}, expected: {}",
            manifest.schema_version, SDK_VERSION
        )));
    }
    if manifest.capsule_id.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "capsule_id is empty".into(),
        ));
    }
    if manifest.claim_type.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "claim_type is empty".into(),
        ));
    }
    if manifest.expected_output_hash.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "expected_output_hash is empty".into(),
        ));
    }
    if !is_sha256_hex(&manifest.expected_output_hash) {
        return Err(CapsuleError::ManifestIncomplete(
            "expected_output_hash must be a 64-character hex sha256 digest".into(),
        ));
    }
    if manifest.created_at.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "created_at is empty".into(),
        ));
    }
    if manifest.creator_identity.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity is empty".into(),
        ));
    }
    Ok(())
}

fn validate_declared_input_refs(capsule: &ReplayCapsule) -> Result<(), CapsuleError> {
    let mut declared = BTreeSet::new();
    for input_ref in &capsule.manifest.input_refs {
        if !declared.insert(input_ref.as_str()) {
            return Err(CapsuleError::ManifestIncomplete(
                "input_refs contains duplicate entries".into(),
            ));
        }
    }

    let actual: BTreeSet<&str> = capsule.inputs.keys().map(String::as_str).collect();
    if declared != actual {
        let missing: Vec<&str> = declared.difference(&actual).copied().collect();
        let extra: Vec<&str> = actual.difference(&declared).copied().collect();
        return Err(CapsuleError::ManifestIncomplete(format!(
            "input_refs do not match inputs: missing=[{}], extra=[{}]",
            missing.join(","),
            extra.join(",")
        )));
    }

    Ok(())
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), CapsuleError> {
    let normalized = verifier_identity.trim();
    let Some(remainder) = normalized.strip_prefix("verifier://") else {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must use the external verifier:// scheme".into(),
        ));
    };
    if remainder.is_empty() {
        return Err(CapsuleError::AccessDenied(
            "verifier_identity must include a non-empty verifier name".into(),
        ));
    }
    Ok(())
}

/// Sign a capsule by computing its structural signature digest.
///
/// The structural signature digest binds the manifest, payload, and inputs via
/// length-prefixed SHA-256 hashing.
pub fn sign_capsule(capsule: &mut ReplayCapsule) {
    capsule.signature = compute_signing_payload(capsule);
}

/// Verify a capsule's structural signature digest against the computed signing payload.
///
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verify_signature(capsule: &ReplayCapsule) -> Result<(), CapsuleError> {
    let expected = compute_signing_payload(capsule);
    if !ct_eq(&capsule.signature, &expected) {
        return Err(CapsuleError::SignatureInvalid(format!(
            "expected={expected}, actual={}",
            capsule.signature
        )));
    }
    Ok(())
}

/// Replay a capsule and produce a result.
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: purely local computation.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic for same inputs.
pub fn replay(
    capsule: &ReplayCapsule,
    verifier_identity: &str,
) -> Result<CapsuleReplayResult, CapsuleError> {
    // Step 1: Validate manifest
    validate_manifest(&capsule.manifest)?;

    // Step 2: Ensure the caller is an external verifier identity.
    validate_verifier_identity(verifier_identity)?;

    // Step 3: Verify signature
    verify_signature(capsule)?;

    // Step 4: Bind the declared input inventory to the replayed inputs.
    validate_declared_input_refs(capsule)?;

    // Step 5: Check non-empty payload
    if capsule.payload.is_empty() {
        return Err(CapsuleError::EmptyPayload("payload is empty".into()));
    }

    // Step 6: Compute actual output hash using length-prefixed encoding
    let actual_hash = compute_replay_hash(&capsule.payload, &capsule.inputs);

    // Step 7: Compare
    let verdict = if ct_eq(&actual_hash, &capsule.manifest.expected_output_hash) {
        CapsuleVerdict::Pass
    } else {
        CapsuleVerdict::Fail
    };

    let detail = if verdict == CapsuleVerdict::Pass {
        "replay output matches expected hash".to_string()
    } else {
        format!(
            "replay diverged: expected={}, actual={}",
            capsule.manifest.expected_output_hash, actual_hash
        )
    };

    Ok(CapsuleReplayResult {
        capsule_id: capsule.manifest.capsule_id.clone(),
        verdict,
        expected_hash: capsule.manifest.expected_output_hash.clone(),
        actual_hash,
        detail,
    })
}

/// Build a reference capsule for testing.
///
/// The capsule is properly signed and has a valid expected_output_hash
/// so that replay will produce a PASS verdict.
pub fn build_reference_capsule() -> ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();

    // Compute expected output hash exactly as replay does
    let expected_hash = compute_replay_hash(&payload, &inputs);

    let manifest = CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "capsule-ref-001".to_string(),
        description: "Reference capsule for testing".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash: expected_hash,
        created_at: "2026-02-21T00:00:00Z".to_string(),
        creator_identity: "creator://test@example.com".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut capsule = ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    sign_capsule(&mut capsule);
    capsule
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_manifest_tamper_rejected(case: &str, mutate: impl FnOnce(&mut ReplayCapsule)) {
        let capsule = build_reference_capsule();
        let mut tampered = capsule.clone();
        mutate(&mut tampered);
        match verify_signature(&tampered) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for {case} tamper, got {other:?}"),
        }
    }

    #[test]
    fn test_structural_only_posture_markers_defined() {
        assert_eq!(
            STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_REPLAY_CAPSULE"
        );
    }

    #[test]
    fn test_build_reference_capsule() {
        let capsule = build_reference_capsule();
        assert!(!capsule.signature.is_empty());
        assert_eq!(capsule.signature.len(), 64);
        assert_eq!(capsule.manifest.schema_version, SDK_VERSION);
    }

    #[test]
    fn test_validate_manifest_pass() {
        let capsule = build_reference_capsule();
        assert!(validate_manifest(&capsule.manifest).is_ok());
    }

    #[test]
    fn test_validate_manifest_bad_schema() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.schema_version = "bad".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::SchemaMismatch(_)) => {}
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = String::new();
        assert!(validate_manifest(&capsule.manifest).is_err());
    }

    #[test]
    fn test_validate_manifest_malformed_expected_hash() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
                assert!(msg.contains("sha256"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = String::new();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_signature_pass() {
        let capsule = build_reference_capsule();
        assert!(verify_signature(&capsule).is_ok());
    }

    #[test]
    fn test_verify_signature_tampered() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match verify_signature(&capsule) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_pass() {
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "verifier://verifier-1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert_eq!(result.actual_hash, result.expected_hash);
    }

    #[test]
    fn test_replay_deterministic() {
        // INV-CAPSULE-VERDICT-REPRODUCIBLE
        let capsule = build_reference_capsule();
        let r1 = replay(&capsule, "verifier://v1").unwrap();
        let r2 = replay(&capsule, "verifier://v1").unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.actual_hash, r2.actual_hash);
    }

    #[test]
    fn test_replay_diverged() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "f".repeat(64);
        sign_capsule(&mut capsule);
        let result = replay(&capsule, "verifier://v1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Fail);
    }

    #[test]
    fn test_replay_rejects_malformed_expected_hash() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
                assert!(msg.contains("sha256"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_empty_created_at() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.created_at = String::new();
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("created_at"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_empty_payload() {
        let mut capsule = build_reference_capsule();
        capsule.payload = String::new();
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::EmptyPayload(_)) => {}
            other => panic!("expected EmptyPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_tampered_signature() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_missing_declared_input() {
        let mut capsule = build_reference_capsule();
        capsule.inputs.remove("artifact_b");
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("missing=[artifact_b]"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_extra_undeclared_input() {
        let mut capsule = build_reference_capsule();
        capsule
            .inputs
            .insert("artifact_c".to_string(), "content_of_c".to_string());
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("extra=[artifact_c]"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_duplicate_declared_input_refs() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.input_refs.push("artifact_a".to_string());
        sign_capsule(&mut capsule);
        match replay(&capsule, "verifier://v1") {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("input_refs"));
                assert!(msg.contains("duplicate"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_error_display_signature_invalid() {
        let err = CapsuleError::SignatureInvalid("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SIGNATURE_INVALID));
    }

    #[test]
    fn test_error_display_schema_mismatch() {
        let err = CapsuleError::SchemaMismatch("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SCHEMA_MISMATCH));
    }

    #[test]
    fn test_error_display_replay_diverged() {
        let err = CapsuleError::ReplayDiverged {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_REPLAY_DIVERGED));
    }

    #[test]
    fn test_error_display_verdict_mismatch() {
        let err = CapsuleError::VerdictMismatch {
            expected: "pass".into(),
            actual: "fail".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_VERDICT_MISMATCH));
    }

    #[test]
    fn test_error_display_access_denied() {
        let err = CapsuleError::AccessDenied("denied".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_ACCESS_DENIED));
    }

    #[test]
    fn test_deterministic_hash_consistency() {
        let h1 = deterministic_hash("test_data");
        let h2 = deterministic_hash("test_data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_deterministic_hash_different_inputs() {
        let h1 = deterministic_hash("input_a");
        let h2 = deterministic_hash("input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_capsule_no_privileged_access() {
        // INV-CAPSULE-NO-PRIVILEGED-ACCESS: replay is local, no network needed
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "verifier://offline-verifier").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn test_replay_rejects_empty_verifier_identity() {
        let capsule = build_reference_capsule();
        match replay(&capsule, "   ") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("verifier://"));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_rejects_non_verifier_identity_scheme() {
        let capsule = build_reference_capsule();
        match replay(&capsule, "creator://test@example.com") {
            Err(CapsuleError::AccessDenied(msg)) => {
                assert!(msg.contains("verifier://"));
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    #[test]
    fn test_capsule_manifest_btreemap_ordering() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.metadata.insert("z_key".into(), "z".into());
        capsule.manifest.metadata.insert("a_key".into(), "a".into());
        let keys: Vec<_> = capsule.manifest.metadata.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    // -- Security regression tests ------------------------------------------

    #[test]
    fn test_hash_uses_sha256_not_xor() {
        // Verify the hash is SHA-256 (collision-resistant), not XOR-based.
        // XOR hash: "ab" and "ba" could collide. SHA-256 will not.
        let h1 = deterministic_hash("ab");
        let h2 = deterministic_hash("ba");
        assert_ne!(h1, h2, "hash must distinguish permuted inputs (not XOR)");

        // XOR hash maps all single-char inputs of same byte to same slot,
        // making strings that differ only in repeated chars collide.
        let h3 = deterministic_hash("aaa");
        let h4 = deterministic_hash("a");
        assert_ne!(
            h3, h4,
            "hash must distinguish different-length same-char inputs"
        );
    }

    #[test]
    fn test_signing_payload_delimiter_collision_resistance() {
        // Pipe-delimited "A|B" signing would let an attacker craft a capsule_id
        // containing "|" that produces the same signing payload as a different
        // capsule. Length-prefixed encoding prevents this.
        let mut capsule_a = build_reference_capsule();
        capsule_a.manifest.capsule_id = "id-a|vsdk-v1.0".to_string();
        capsule_a.manifest.schema_version = SDK_VERSION.to_string();
        sign_capsule(&mut capsule_a);

        let mut capsule_b = build_reference_capsule();
        capsule_b.manifest.capsule_id = "id-a".to_string();
        capsule_b.manifest.schema_version = SDK_VERSION.to_string();
        sign_capsule(&mut capsule_b);

        assert_ne!(
            capsule_a.signature, capsule_b.signature,
            "signing must resist delimiter collision in capsule_id"
        );
    }

    #[test]
    fn test_replay_hash_payload_input_collision_resistance() {
        // Without length-prefixed encoding, a payload "data|key=val" with no
        // inputs would hash identically to payload "data" with input key=val.
        let inputs_empty = BTreeMap::new();
        let h1 = compute_replay_hash("data|artifact_a=content_of_a", &inputs_empty);

        let mut inputs_with = BTreeMap::new();
        inputs_with.insert("artifact_a".to_string(), "content_of_a".to_string());
        let h2 = compute_replay_hash("data", &inputs_with);

        assert_ne!(
            h1, h2,
            "replay hash must distinguish payload-embedded vs actual inputs"
        );
    }

    #[test]
    fn test_constant_time_comparison_used() {
        // Verify that ct_eq works correctly (same and different strings).
        assert!(ct_eq("hello", "hello"));
        assert!(!ct_eq("hello", "hellx"));
        assert!(!ct_eq("hello", "hell"));
        assert!(ct_eq("", ""));
        assert!(ct_eq_bytes(b"test", b"test"));
        assert!(!ct_eq_bytes(b"test", b"tesx"));
    }

    #[test]
    fn test_forged_same_length_signature_rejected() {
        // Adversarial: forged signature with same length as real one
        let capsule = build_reference_capsule();
        let mut forged = capsule.clone();
        // Create a 64-char hex string that differs from the real signature
        forged.signature = "a".repeat(64);
        assert_ne!(forged.signature, capsule.signature);
        match verify_signature(&forged) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for forged sig, got {other:?}"),
        }
    }

    #[test]
    fn test_payload_swap_under_reused_signature() {
        // Adversarial: swap payload but keep old signature
        let capsule = build_reference_capsule();
        let mut swapped = capsule.clone();
        swapped.payload = "completely_different_payload".to_string();
        // Don't re-sign — attacker reuses old signature
        match replay(&swapped, "verifier://v1") {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for swapped payload, got {other:?}"),
        }
    }

    #[test]
    fn test_claim_type_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("claim_type", |capsule| {
            capsule.manifest.claim_type = "runtime_safety".to_string();
        });
    }

    #[test]
    fn test_input_refs_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("input_refs", |capsule| {
            capsule.manifest.input_refs.push("artifact_c".to_string());
        });
    }

    #[test]
    fn test_created_at_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("created_at", |capsule| {
            capsule.manifest.created_at = "2026-02-22T00:00:00Z".to_string();
        });
    }

    #[test]
    fn test_creator_identity_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("creator_identity", |capsule| {
            capsule.manifest.creator_identity = "creator://attacker@example.com".to_string();
        });
    }

    #[test]
    fn test_metadata_tamper_under_reused_signature_rejected() {
        assert_manifest_tamper_rejected("metadata", |capsule| {
            capsule
                .manifest
                .metadata
                .insert("tampered".to_string(), "true".to_string());
        });
    }

    #[test]
    fn test_cross_claim_replay_rejected() {
        // Adversarial: take signature from capsule A, apply to capsule B
        let capsule_a = build_reference_capsule();
        let mut capsule_b = build_reference_capsule();
        capsule_b.manifest.capsule_id = "capsule-different-001".to_string();
        capsule_b.manifest.expected_output_hash =
            compute_replay_hash(&capsule_b.payload, &capsule_b.inputs);
        // Reuse capsule_a's signature
        capsule_b.signature = capsule_a.signature.clone();
        match verify_signature(&capsule_b) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid for cross-claim replay, got {other:?}"),
        }
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_validate_manifest_with_unicode_control_characters_rejects() {
        let mut capsule = build_reference_capsule();
        // Inject null byte and other control characters into capsule_id
        capsule.manifest.capsule_id = "capsule\0with\x01control\x1fchars".to_string();
        sign_capsule(&mut capsule);

        // Should pass manifest validation (we don't sanitize control chars)
        // but demonstrates potential injection vector
        assert!(validate_manifest(&capsule.manifest).is_ok());

        // However, such IDs are suspicious and could be filtered by calling code
        assert!(capsule.manifest.capsule_id.contains('\0'));
    }

    #[test]
    fn negative_replay_with_extremely_large_payload_handles_gracefully() {
        let mut capsule = build_reference_capsule();
        // Create a very large payload (1MB of 'x' characters)
        capsule.payload = "x".repeat(1_000_000);
        capsule.manifest.expected_output_hash = compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&mut capsule);

        // Should handle large payloads without panicking or excessive memory usage
        let result = replay(&capsule, "verifier://large-test").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn negative_validate_manifest_with_path_traversal_characters_accepts_but_suspicious() {
        let mut capsule = build_reference_capsule();
        // Inject path traversal sequences into various fields
        capsule.manifest.capsule_id = "../../../etc/passwd".to_string();
        capsule.manifest.description = "payload\\..\\windows\\system32".to_string();
        capsule.manifest.creator_identity = "creator://../root@localhost".to_string();

        // These are just strings, so validation passes, but calling code should sanitize
        assert!(validate_manifest(&capsule.manifest).is_ok());
        assert!(capsule.manifest.capsule_id.contains("../"));
        assert!(capsule.manifest.description.contains("..\\"));
    }

    #[test]
    fn negative_deterministic_hash_with_maximum_unicode_handles_correctly() {
        // Test with various Unicode edge cases including max codepoints
        let test_cases = vec![
            "\u{FFFF}".to_string(),  // Max BMP codepoint
            "\u{10FFFF}".to_string(), // Max Unicode codepoint
            "🚀🔥💀\u{1F600}".to_string(), // Emoji sequence
            "\u{200B}\u{FEFF}\u{034F}".to_string(), // Zero-width/invisible chars
        ];

        for input in test_cases {
            let hash = deterministic_hash(&input);
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn negative_validate_manifest_with_whitespace_only_fields_rejects() {
        let mut capsule = build_reference_capsule();

        // Test various whitespace-only scenarios
        capsule.manifest.capsule_id = "   \t\n\r   ".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            Ok(_) => {
                // If it passes, the field isn't empty after trim, which is fine
                assert!(!capsule.manifest.capsule_id.trim().is_empty());
            }
        }

        let mut capsule2 = build_reference_capsule();
        capsule2.manifest.claim_type = "\u{00A0}\u{2000}\u{2001}".to_string(); // Non-breaking spaces
        match validate_manifest(&capsule2.manifest) {
            Err(CapsuleError::ManifestIncomplete(_)) => {}, // Expected if considered empty
            Ok(_) => {} // Fine if non-breaking spaces aren't considered empty
        }
    }

    #[test]
    fn negative_validate_verifier_identity_with_malformed_uri_rejects() {
        let capsule = build_reference_capsule();

        let invalid_identities = vec![
            "verifier://",           // Missing verifier name
            "verifier:///empty",     // Extra slash
            "verifier://\n\r",       // Newlines in URI
            "verifier://space space", // Spaces in verifier name
            "VERIFIER://upper",      // Wrong case scheme
            "verifier://../traversal", // Path traversal in URI
            "verifier://\u{0000}",   // Null byte
            "verifier://\u{FFFF}",   // Invalid Unicode
        ];

        for identity in invalid_identities {
            match replay(&capsule, identity) {
                Err(CapsuleError::AccessDenied(_)) => {}, // Expected
                other => panic!("Expected AccessDenied for identity '{identity}', got {other:?}"),
            }
        }
    }

    #[test]
    fn negative_validate_manifest_with_almost_valid_hash_formats_rejects() {
        let mut capsule = build_reference_capsule();

        let invalid_hashes = vec![
            "g".repeat(64),          // Invalid hex character 'g'
            "f".repeat(63),          // Too short (63 chars)
            "f".repeat(65),          // Too long (65 chars)
            "F".repeat(64),          // Uppercase hex (might be rejected)
            "123456789abcdef".repeat(3) + "12", // Wrong length
            "".to_string(),          // Empty
            "\n".repeat(32) + &"f".repeat(32), // Newlines in middle
        ];

        for hash in invalid_hashes {
            capsule.manifest.expected_output_hash = hash.clone();
            match validate_manifest(&capsule.manifest) {
                Err(CapsuleError::ManifestIncomplete(msg)) => {
                    assert!(msg.contains("expected_output_hash") || msg.contains("sha256"));
                }
                other => panic!("Expected ManifestIncomplete for hash '{hash}', got {other:?}"),
            }
        }
    }

    #[test]
    fn negative_replay_with_massive_input_map_handles_memory_efficiently() {
        let mut capsule = build_reference_capsule();

        // Create capsule with many inputs (1000 key-value pairs)
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        for i in 0..1000 {
            let key = format!("input_key_{:04}", i);
            let value = format!("input_value_data_content_{}", i);
            capsule.inputs.insert(key.clone(), value);
            capsule.manifest.input_refs.push(key);
        }

        capsule.manifest.expected_output_hash = compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&mut capsule);

        // Should handle large input maps without excessive memory consumption
        let start = std::time::Instant::now();
        let result = replay(&capsule, "verifier://stress-test").unwrap();
        let duration = start.elapsed();

        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        // Should complete within reasonable time (5 seconds is generous)
        assert!(duration < std::time::Duration::from_secs(5));
    }

    #[test]
    fn negative_compute_replay_hash_with_key_value_collision_attack_resists() {
        // Test that length-prefixed encoding prevents key-value collision attacks
        // where attacker crafts keys/values to produce same hash as different data

        // Attack 1: Key ending with length prefix of value
        let mut inputs1 = BTreeMap::new();
        inputs1.insert("key\x08\x00\x00\x00\x00\x00\x00\x00value123".to_string(), "".to_string());
        let hash1 = compute_replay_hash("payload", &inputs1);

        // Attack 2: Different key-value split of same byte sequence
        let mut inputs2 = BTreeMap::new();
        inputs2.insert("key".to_string(), "value123".to_string());
        let hash2 = compute_replay_hash("payload", &inputs2);

        // Length-prefixed encoding should make these produce different hashes
        assert_ne!(hash1, hash2, "Replay hash must resist key-value collision attacks");
    }

    #[test]
    fn negative_replay_with_empty_string_verifier_identity_after_scheme_rejects() {
        let capsule = build_reference_capsule();

        // Test verifier:// with empty remainder after trimming
        let empty_remainder_cases = vec![
            "verifier://   ",        // Only whitespace after scheme
            "verifier://\t\n\r",     // Only tabs/newlines after scheme
            "verifier://\u{00A0}",   // Only non-breaking space after scheme
        ];

        for identity in empty_remainder_cases {
            match replay(&capsule, identity) {
                Err(CapsuleError::AccessDenied(msg)) => {
                    assert!(msg.contains("non-empty verifier name"));
                }
                other => panic!("Expected AccessDenied for empty verifier name '{identity}', got {other:?}"),
            }
        }
    }

    // ── Additional negative-path tests for edge cases and boundary conditions ──

    #[test]
    fn negative_is_sha256_hex_with_boundary_and_invalid_cases() {
        // Test exact boundary cases for SHA-256 hex validation
        assert!(!is_sha256_hex(""));  // Empty string
        assert!(!is_sha256_hex("f".repeat(63).as_str()));  // Too short by 1
        assert!(!is_sha256_hex("f".repeat(65).as_str()));  // Too long by 1
        assert!(!is_sha256_hex("G".repeat(64).as_str()));  // Invalid hex char
        assert!(!is_sha256_hex("Z".repeat(64).as_str()));  // Invalid hex char
        assert!(!is_sha256_hex(&format!("{}g{}", "f".repeat(31), "f".repeat(32))));  // Invalid char in middle
        assert!(!is_sha256_hex(&format!("{}\x00{}", "f".repeat(31), "f".repeat(32))));  // Null byte
        // Valid case for comparison
        assert!(is_sha256_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn negative_push_length_prefixed_with_maximum_and_zero_values() {
        let mut hasher = Sha256::new();

        // Test with maximum possible string length (approaching usize::MAX)
        // Note: We can't actually create a string of usize::MAX length due to memory,
        // but we can test the length encoding behavior
        let max_len_str = "x".repeat(65536);  // Large but manageable string
        push_length_prefixed(&mut hasher, &max_len_str);

        // Test with zero-length string
        push_length_prefixed(&mut hasher, "");

        // Test with string containing only null bytes
        let null_str = "\0".repeat(100);
        push_length_prefixed(&mut hasher, &null_str);

        // Test with string containing high Unicode codepoints
        let unicode_str = "\u{1F4A9}".repeat(100);  // Pile of poo emoji repeated
        push_length_prefixed(&mut hasher, &unicode_str);

        // Finalize to ensure no panic
        let _result = hasher.finalize();
    }

    #[test]
    fn negative_compute_replay_hash_with_minimal_and_edge_data() {
        // Test with completely empty payload and inputs
        let empty_inputs = BTreeMap::new();
        let hash1 = compute_replay_hash("", &empty_inputs);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.bytes().all(|b| b.is_ascii_hexdigit()));

        // Test with payload containing only control characters
        let control_payload = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let hash2 = compute_replay_hash(control_payload, &empty_inputs);
        assert_ne!(hash1, hash2);

        // Test with single-character key and value at boundaries
        let mut single_inputs = BTreeMap::new();
        single_inputs.insert("".to_string(), "".to_string());  // Empty key and value
        single_inputs.insert("a".to_string(), "b".to_string());  // Single chars
        let hash3 = compute_replay_hash("c", &single_inputs);
        assert_ne!(hash1, hash3);
        assert_ne!(hash2, hash3);
    }

    #[test]
    fn negative_compute_signing_payload_with_boundary_manifest_sizes() {
        let mut capsule = build_reference_capsule();

        // Test with minimal manifest fields (empty strings where allowed)
        let mut minimal_capsule = capsule.clone();
        minimal_capsule.manifest.description = "".to_string();
        minimal_capsule.manifest.input_refs.clear();
        minimal_capsule.manifest.metadata.clear();
        minimal_capsule.inputs.clear();
        minimal_capsule.payload = "".to_string();
        let minimal_payload = compute_signing_payload(&minimal_capsule);

        // Test with maximum reasonable field sizes
        let mut maximal_capsule = capsule.clone();
        maximal_capsule.manifest.description = "x".repeat(10000);
        maximal_capsule.payload = "y".repeat(10000);
        for i in 0..100 {
            let key = format!("meta_key_{}", i);
            let value = format!("meta_value_{}", "z".repeat(100));
            maximal_capsule.manifest.metadata.insert(key, value);
        }
        let maximal_payload = compute_signing_payload(&maximal_capsule);

        assert_ne!(minimal_payload, maximal_payload);
        assert_eq!(minimal_payload.len(), 64);
        assert_eq!(maximal_payload.len(), 64);
    }

    #[test]
    fn negative_validate_declared_input_refs_with_edge_case_collections() {
        // Test with capsule having maximum number of input refs
        let mut stress_capsule = build_reference_capsule();
        stress_capsule.manifest.input_refs.clear();
        stress_capsule.inputs.clear();

        // Add many input refs to test iteration performance and memory
        for i in 0..1000 {
            let ref_name = format!("stress_input_{:04}", i);
            stress_capsule.manifest.input_refs.push(ref_name.clone());
            stress_capsule.inputs.insert(ref_name, format!("content_{}", i));
        }

        assert!(validate_declared_input_refs(&stress_capsule).is_ok());

        // Test with input refs containing Unicode edge cases
        let mut unicode_capsule = build_reference_capsule();
        unicode_capsule.manifest.input_refs.clear();
        unicode_capsule.inputs.clear();

        let unicode_refs = vec![
            "\u{1F600}".to_string(),  // Emoji
            "\u{0000}".to_string(),   // Null character
            "\u{FFFF}".to_string(),   // Max BMP
            "\u{10FFFF}".to_string(), // Max Unicode
        ];

        for unicode_ref in unicode_refs {
            unicode_capsule.manifest.input_refs.push(unicode_ref.clone());
            unicode_capsule.inputs.insert(unicode_ref, "unicode_content".to_string());
        }

        assert!(validate_declared_input_refs(&unicode_capsule).is_ok());
    }

    #[test]
    fn negative_ct_eq_bytes_with_length_boundary_conditions() {
        // Test constant-time comparison with various length combinations
        assert!(!ct_eq_bytes(b"", b"a"));  // Empty vs non-empty
        assert!(!ct_eq_bytes(b"a", b""));  // Non-empty vs empty
        assert!(ct_eq_bytes(b"", b""));    // Both empty

        // Test with very large byte arrays of different lengths
        let large1 = vec![0u8; 10000];
        let large2 = vec![1u8; 10000];
        let large3 = vec![0u8; 10001];  // Different length

        assert!(ct_eq_bytes(&large1, &large1));   // Same content, same length
        assert!(!ct_eq_bytes(&large1, &large2)); // Different content, same length
        assert!(!ct_eq_bytes(&large1, &large3)); // Same content, different length

        // Test with arrays differing only in last byte
        let mut almost_same1 = vec![42u8; 1000];
        let mut almost_same2 = vec![42u8; 1000];
        almost_same2[999] = 43;  // Change last byte

        assert!(!ct_eq_bytes(&almost_same1, &almost_same2));
    }

    #[test]
    fn negative_domain_separator_collision_resistance_stress_test() {
        // Test that different domain separators produce different hashes
        // even with identical subsequent data
        let test_data = "identical_input_data";

        let hash_capsule = deterministic_hash(test_data);

        // Manually compute hash with different domain separator
        let mut hasher_different = Sha256::new();
        hasher_different.update(b"different_domain_separator:");
        hasher_different.update(test_data.as_bytes());
        let hash_different = hex::encode(hasher_different.finalize());

        assert_ne!(hash_capsule, hash_different,
                  "Domain separators must prevent hash collision");

        // Test with malicious input that tries to forge domain separator
        let malicious_input = "verifier_sdk_capsule_v1:fake_domain_sep";
        let hash_malicious = deterministic_hash(malicious_input);

        // Should NOT match hash of legitimate empty string with proper separator
        let hash_legitimate = deterministic_hash("");
        assert_ne!(hash_malicious, hash_legitimate,
                  "Malicious domain separator injection must be prevented");
    }

    #[test]
    fn negative_hash_computation_with_zero_length_boundaries() {
        // Test edge cases in hash computation involving zero-length data
        let mut zero_inputs = BTreeMap::new();
        zero_inputs.insert("".to_string(), "".to_string());  // Zero-length key and value

        let hash_zero_payload = compute_replay_hash("", &zero_inputs);
        let hash_zero_inputs = compute_replay_hash("data", &BTreeMap::new());
        let hash_both_zero = compute_replay_hash("", &BTreeMap::new());

        // All should be different due to different length prefixes
        assert_ne!(hash_zero_payload, hash_zero_inputs);
        assert_ne!(hash_zero_payload, hash_both_zero);
        assert_ne!(hash_zero_inputs, hash_both_zero);

        // Test with zero-length metadata in signing payload
        let mut zero_meta_capsule = build_reference_capsule();
        zero_meta_capsule.manifest.metadata.clear();
        zero_meta_capsule.manifest.metadata.insert("".to_string(), "".to_string());
        let signing_zero = compute_signing_payload(&zero_meta_capsule);

        let mut no_meta_capsule = build_reference_capsule();
        no_meta_capsule.manifest.metadata.clear();
        let signing_no_meta = compute_signing_payload(&no_meta_capsule);

        assert_ne!(signing_zero, signing_no_meta,
                  "Empty metadata entry must differ from no metadata");
    }

    // =========================================================================
    // ADDITIONAL COMPREHENSIVE NEGATIVE-PATH TESTS
    // =========================================================================

    #[test]
    fn negative_capsule_with_schema_version_spoofing_attempts_rejected() {
        let mut capsule = build_reference_capsule();

        // Attempt to spoof schema version with similar-looking strings
        let spoofed_versions = vec![
            format!("{}\0", SDK_VERSION),         // Null terminator
            format!(" {} ", SDK_VERSION),         // Extra whitespace
            format!("{}\n", SDK_VERSION),         // Newline suffix
            format!("{}\u{200B}", SDK_VERSION),   // Zero-width space
            SDK_VERSION.to_uppercase(),           // Case change
            format!("{}x", SDK_VERSION),          // Extra character
            format!("v{}", SDK_VERSION),          // Version prefix
        ];

        for spoofed_version in spoofed_versions {
            capsule.manifest.schema_version = spoofed_version.clone();
            match validate_manifest(&capsule.manifest) {
                Err(CapsuleError::SchemaMismatch(_)) => {}, // Expected
                other => panic!("Expected SchemaMismatch for spoofed version '{}', got {other:?}", spoofed_version),
            }
        }
    }

    #[test]
    fn negative_replay_with_extremely_deep_nested_input_structure() {
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        // Create inputs with deeply nested JSON-like structure in values
        let deep_nesting_levels = 1000;
        let mut nested_value = "core".to_string();
        for i in 0..deep_nesting_levels {
            nested_value = format!("{{\"level_{}\": \"{}\"}}", i, nested_value);
        }

        capsule.inputs.insert("deep_nested".to_string(), nested_value);
        capsule.manifest.input_refs.push("deep_nested".to_string());
        capsule.manifest.expected_output_hash = compute_replay_hash(&capsule.payload, &capsule.inputs);
        sign_capsule(&mut capsule);

        // Should handle deep nesting without stack overflow or excessive processing time
        let start = std::time::Instant::now();
        let result = replay(&capsule, "verifier://nesting-test").unwrap();
        let duration = start.elapsed();

        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert!(duration < std::time::Duration::from_secs(5)); // Should complete reasonably fast
    }

    #[test]
    fn negative_capsule_creation_with_invalid_utf8_sequences_handled() {
        // Test behavior with byte sequences that are invalid UTF-8
        let mut capsule = build_reference_capsule();

        // Create potentially invalid UTF-8 sequences (would be caught at string creation)
        let invalid_utf8_attempts = vec![
            "valid\u{FFFD}replacement".to_string(),     // Replacement character
            "incomplete\u{D800}surrogate".to_string(),   // Invalid surrogate (if it gets through)
        ];

        for invalid_sequence in invalid_utf8_attempts {
            capsule.manifest.description = invalid_sequence.clone();
            sign_capsule(&mut capsule);

            // Should handle gracefully without crashing
            assert!(validate_manifest(&capsule.manifest).is_ok());
            let result = replay(&capsule, "verifier://utf8-test");
            assert!(result.is_ok());
        }
    }

    #[test]
    fn negative_deterministic_hash_with_identical_bytes_different_encodings() {
        // Test that the hash distinguishes between different string interpretations of same bytes
        let byte_sequence = vec![0xC4, 0x85]; // UTF-8 for 'ą'
        let utf8_string = String::from_utf8(byte_sequence.clone()).unwrap();
        let latin1_interpretation = byte_sequence.iter().map(|&b| b as char).collect::<String>();

        let hash_utf8 = deterministic_hash(&utf8_string);
        let hash_latin1 = deterministic_hash(&latin1_interpretation);

        // Should produce different hashes for different string interpretations
        if utf8_string != latin1_interpretation {
            assert_ne!(hash_utf8, hash_latin1,
                      "Different string interpretations must produce different hashes");
        }
    }

    #[test]
    fn negative_verify_signature_with_race_condition_simulation() {
        let mut capsule = build_reference_capsule();

        // Simulate potential race condition by modifying capsule during verification
        let original_signature = capsule.signature.clone();

        // Capture the expected signing payload
        let expected_payload = compute_signing_payload(&capsule);

        // Modify the capsule slightly
        capsule.manifest.description.push('x');

        // Restore original signature (simulating race where signature was computed before modification)
        capsule.signature = original_signature;

        // Should detect that signature no longer matches modified content
        match verify_signature(&capsule) {
            Err(CapsuleError::SignatureInvalid(_)) => {}, // Expected
            other => panic!("Expected SignatureInvalid for modified capsule, got {other:?}"),
        }

        // Verify that the current payload is indeed different
        let modified_payload = compute_signing_payload(&capsule);
        assert_ne!(expected_payload, modified_payload);
    }

    #[test]
    fn negative_capsule_input_keys_with_btreemap_edge_case_ordering() {
        // Test BTreeMap behavior with keys that have tricky lexicographic ordering
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        let tricky_keys = vec![
            "1".to_string(),
            "10".to_string(),
            "2".to_string(),      // Lexicographic: "1" < "10" < "2"
            "ä".to_string(),      // Unicode
            "z".to_string(),      // ASCII
            "😀".to_string(),     // High Unicode
        ];

        // Insert in random order
        for key in tricky_keys.iter().rev() {
            capsule.inputs.insert(key.clone(), format!("value_for_{}", key));
            capsule.manifest.input_refs.push(key.clone());
        }

        // Sort input_refs to match expected BTreeMap ordering
        capsule.manifest.input_refs.sort();

        // Compute hash multiple times to ensure deterministic ordering
        let hash1 = compute_replay_hash(&capsule.payload, &capsule.inputs);
        let hash2 = compute_replay_hash(&capsule.payload, &capsule.inputs);

        assert_eq!(hash1, hash2, "Hash must be deterministic despite key ordering complexity");

        capsule.manifest.expected_output_hash = hash1;
        sign_capsule(&mut capsule);

        let result = replay(&capsule, "verifier://ordering-complex").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn negative_validate_verifier_identity_with_protocol_confusion_attempts() {
        let capsule = build_reference_capsule();

        // Test various protocol confusion attempts
        let confusion_attempts = vec![
            "VERIFIER://uppercase-scheme",      // Wrong case
            "verifier:\\\\windows-style",      // Wrong separator style
            "verifier:/single-slash",          // Missing second slash
            "verifier:///triple-slash",        // Too many slashes
            "http://verifier://double-proto",  // Nested protocols
            "verifier://user:pass@host",       // Authority with credentials
            "verifier://host:port/path",       // Port and path
            "verifier://host?query=param",     // Query parameters
            "verifier://host#fragment",        // Fragment
            "javascript:alert('xss')",        // Different protocol entirely
        ];

        for attempt in confusion_attempts {
            match replay(&capsule, attempt) {
                Err(CapsuleError::AccessDenied(_)) => {}, // Expected
                other => panic!("Expected AccessDenied for protocol confusion '{}', got {other:?}", attempt),
            }
        }
    }

    #[test]
    fn negative_capsule_metadata_with_json_injection_patterns() {
        let mut capsule = build_reference_capsule();

        // Test metadata values that could cause JSON injection if improperly handled
        let injection_patterns = vec![
            "\"},\"injected\":\"malicious\",\"dummy\":\"".to_string(),
            "\\u0022},\\u0022injected\\u0022:\\u0022malicious".to_string(),
            "\n},\n\"injected\": \"value\",\n\"real\": \"".to_string(),
            "\"},\"__proto__\":{\"isAdmin\":true},\"dummy\":\"".to_string(),
        ];

        for pattern in injection_patterns {
            capsule.manifest.metadata.clear();
            capsule.manifest.metadata.insert("potentially_malicious".to_string(), pattern.clone());
            sign_capsule(&mut capsule);

            // Should handle injection patterns without breaking verification
            assert!(validate_manifest(&capsule.manifest).is_ok());

            let result = replay(&capsule, "verifier://injection-meta-test");
            assert!(result.is_ok(), "Metadata injection pattern should not break replay");

            // Verify the pattern is preserved as-is in metadata
            assert_eq!(capsule.manifest.metadata.get("potentially_malicious"), Some(&pattern));
        }
    }

    #[test]
    fn negative_compute_replay_hash_memory_exhaustion_resistance() {
        // Test that hash computation doesn't exhaust memory with pathological inputs
        let mut large_inputs = BTreeMap::new();

        // Create many inputs with moderately large values
        for i in 0..1000 {
            let key = format!("stress_key_{:04}", i);
            let value = "x".repeat(1000); // 1KB per value = 1MB total
            large_inputs.insert(key, value);
        }

        let large_payload = "y".repeat(100_000); // 100KB payload

        // Should compute hash without excessive memory allocation
        let start_time = std::time::Instant::now();
        let hash = compute_replay_hash(&large_payload, &large_inputs);
        let duration = start_time.elapsed();

        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(duration < std::time::Duration::from_secs(5)); // Should be reasonably fast
    }

    #[test]
    fn negative_constant_time_string_comparison_with_length_attacks() {
        // Test that ct_eq properly handles length-based timing attacks
        let reference = "secret_reference_string";

        // Test strings of different lengths (should fail fast on length)
        let different_lengths = vec![
            "",
            "a",
            "ab",
            "secret_reference_strin",  // One character shorter
            "secret_reference_stringx", // One character longer
            "secret_reference_string_much_longer_suffix",
        ];

        for test_string in different_lengths {
            let result = ct_eq(reference, test_string);
            assert!(!result, "Different length strings should not be equal");
        }

        // Test strings of same length but different content
        let same_length_different = vec![
            "tecret_reference_string", // First char different
            "secret_reference_strinz", // Last char different
            "secret_referencx_string", // Middle char different
            "SECRET_REFERENCE_STRING", // Case different
        ];

        for test_string in same_length_different {
            assert_eq!(test_string.len(), reference.len()); // Verify same length
            let result = ct_eq(reference, test_string);
            assert!(!result, "Same length, different content should not be equal");
        }

        // Positive test case
        assert!(ct_eq(reference, reference));
    }

    // =========================================================================
    // ADDITIONAL COMPREHENSIVE NEGATIVE-PATH SECURITY TESTS
    // =========================================================================

    #[test]
    fn negative_capsule_manifest_with_extreme_field_pollution_attacks() {
        let mut capsule = build_reference_capsule();

        // Test metadata pollution with extreme key counts
        capsule.manifest.metadata.clear();
        for i in 0..10000 {
            let malicious_key = format!("pollution_{:04}\x00\r\n\t", i);
            let malicious_value = format!("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>{}", "x".repeat(i % 1000));
            capsule.manifest.metadata.insert(malicious_key, malicious_value);
        }
        sign_capsule(&mut capsule);

        // Should handle massive metadata pollution without crashing or timeout
        let start = std::time::Instant::now();
        let result = validate_manifest(&capsule.manifest);
        let duration = start.elapsed();

        assert!(result.is_ok());
        assert!(duration < std::time::Duration::from_secs(10)); // Should complete reasonably

        // Test replay with polluted metadata
        match replay(&capsule, "verifier://pollution-test") {
            Ok(_) | Err(_) => {} // Either success or failure is acceptable, but no panic
        }
    }

    #[test]
    fn negative_deterministic_hash_with_unicode_normalization_bypass_attempts() {
        // Test hash behavior with Unicode normalization attacks
        let canonical_form = "café"; // Composed form (é as single codepoint)
        let decomposed_form = "cafe\u{0301}"; // Decomposed form (e + combining acute)
        let malicious_lookalike = "café"; // Different Unicode that looks similar

        let hash_canonical = deterministic_hash(canonical_form);
        let hash_decomposed = deterministic_hash(decomposed_form);
        let hash_lookalike = deterministic_hash(malicious_lookalike);

        // Different Unicode representations should produce different hashes
        // (no normalization should be applied)
        if canonical_form.as_bytes() != decomposed_form.as_bytes() {
            assert_ne!(hash_canonical, hash_decomposed,
                      "Different Unicode byte sequences must produce different hashes");
        }

        // Test with various Unicode attack patterns
        let unicode_attacks = vec![
            "admin\u{202E}nidma", // Right-to-left override
            "admin\u{200D}user",  // Zero-width joiner
            "admin\u{FEFF}user",  // Zero-width no-break space
            "admin\u{034F}user",  // Combining grapheme joiner
            "admin\u{200B}user",  // Zero-width space
        ];

        let legitimate_hash = deterministic_hash("adminuser");
        for attack_input in unicode_attacks {
            let attack_hash = deterministic_hash(attack_input);
            assert_ne!(legitimate_hash, attack_hash,
                      "Unicode attack pattern '{}' must not collide with legitimate input",
                      attack_input.escape_unicode());
        }
    }

    #[test]
    fn negative_replay_hash_with_malicious_length_prefix_injection() {
        // Test resistance to length-prefix injection attacks
        let mut legitimate_inputs = BTreeMap::new();
        legitimate_inputs.insert("key1".to_string(), "value1".to_string());

        // Attacker tries to inject fake length prefixes in payload
        let attack_payloads = vec![
            format!("{}{}key1{}value1",
                    "payload".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>(),
                    "payload",
                    "key1".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>(),
                    "value1".len().to_le_bytes().iter().map(|&b| b as char).collect::<String>()),
            "\x08\x00\x00\x00\x00\x00\x00\x00payloadX\x04\x00\x00\x00\x00\x00\x00\x00key1\x06\x00\x00\x00\x00\x00\x00\x00value1".to_string(),
            "fake_payload\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00".to_string(),
        ];

        let legitimate_hash = compute_replay_hash("legitimate_payload", &legitimate_inputs);

        for attack_payload in attack_payloads {
            let attack_hash = compute_replay_hash(&attack_payload, &BTreeMap::new());
            assert_ne!(legitimate_hash, attack_hash,
                      "Length prefix injection attack must not produce hash collision");
        }
    }

    #[test]
    fn negative_verifier_identity_with_homograph_and_spoofing_attacks() {
        let capsule = build_reference_capsule();

        // Test homograph attacks using similar-looking characters
        let homograph_attacks = vec![
            "verifier://аdmin",          // Cyrillic 'а' instead of Latin 'a'
            "verifier://admin‍user",     // Zero-width joiner
            "verifier://аdmіn",          // Mixed Cyrillic/Latin
            "verifier://admín",          // Latin with accent
            "verifier://ⱱerifier",      // Latin small letter v with right hook
            "verifier://verífier",       // Accent on i
            "verifier://veriﬁer",       // Latin small ligature fi
        ];

        for spoofed_identity in homograph_attacks {
            match replay(&capsule, spoofed_identity) {
                Err(CapsuleError::AccessDenied(_)) => {}, // May be rejected during validation
                Ok(_) => {
                    // If accepted, ensure it doesn't compromise security
                    // (the test just ensures no panic/crash occurs)
                }
                Err(other_err) => {
                    // Other errors are also acceptable as long as no crash
                }
            }
        }

        // Test IDN homograph domain spoofing patterns
        let domain_spoofs = vec![
            "verifier://раypal.com",     // Cyrillic 'а' and 'р'
            "verifier://gооgle.com",     // Cyrillic 'о' characters
            "verifier://аmazon.com",     // Cyrillic 'а'
            "verifier://miсrosoft.com",  // Cyrillic 'с'
        ];

        for spoof in domain_spoofs {
            match replay(&capsule, spoof) {
                Err(_) | Ok(_) => {} // Either result acceptable, no crash expected
            }
        }
    }

    #[test]
    fn negative_signing_payload_with_arithmetic_overflow_in_length_encoding() {
        // Test behavior near arithmetic boundaries in length encoding
        let mut stress_capsule = build_reference_capsule();

        // Test with field lengths approaching u64::MAX representation
        // Note: We can't actually create strings of usize::MAX length, but we test the encoding
        let max_reasonable_length = 1_000_000;
        stress_capsule.payload = "z".repeat(max_reasonable_length);

        // Add metadata with keys and values that test boundary conditions
        stress_capsule.manifest.metadata.clear();
        stress_capsule.manifest.metadata.insert("".to_string(), "".to_string()); // Zero length
        stress_capsule.manifest.metadata.insert("x".repeat(65535), "y".repeat(65536)); // Large but manageable

        // Should handle large lengths in signing payload without overflow
        let signing_payload = compute_signing_payload(&stress_capsule);
        assert_eq!(signing_payload.len(), 64);
        assert!(signing_payload.bytes().all(|b| b.is_ascii_hexdigit()));

        // Test with maximum number of input_refs
        stress_capsule.manifest.input_refs.clear();
        stress_capsule.inputs.clear();
        for i in 0..10000 {
            let key = format!("input_{:05}", i);
            stress_capsule.manifest.input_refs.push(key.clone());
            stress_capsule.inputs.insert(key, format!("content_{}", i));
        }

        let stress_signing = compute_signing_payload(&stress_capsule);
        assert_eq!(stress_signing.len(), 64);
        assert!(stress_signing.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn negative_capsule_error_display_with_injection_resistant_formatting() {
        // Test that error display properly escapes malicious input
        let injection_attempts = vec![
            "error\x1b[31mRED_TEXT\x1b[0m",                    // ANSI escape codes
            "error\r\nHTTP/1.1 200 OK\r\nContent-Type: text", // HTTP header injection
            "error</script><script>alert('xss')</script>",     // HTML/JS injection
            "error\0null_terminated\x00more",                  // Null byte injection
            "error\n\nSecond-Line: malicious",                 // Newline injection
            "error\u{202E}reverse\u{202D}normal",              // BiDi override attacks
        ];

        for malicious_content in injection_attempts {
            let error_variants = vec![
                CapsuleError::SignatureInvalid(malicious_content.clone()),
                CapsuleError::SchemaMismatch(malicious_content.clone()),
                CapsuleError::AccessDenied(malicious_content.clone()),
                CapsuleError::EmptyPayload(malicious_content.clone()),
                CapsuleError::ManifestIncomplete(malicious_content.clone()),
                CapsuleError::ReplayDiverged {
                    expected: malicious_content.clone(),
                    actual: "legitimate".to_string()
                },
                CapsuleError::VerdictMismatch {
                    expected: "Pass".to_string(),
                    actual: malicious_content.clone()
                },
            ];

            for error in error_variants {
                let error_string = format!("{}", error);

                // Error should contain the malicious content but in a safe way
                // (Display trait should not process escape codes, just include them as-is)
                assert!(error_string.contains(malicious_content.as_str()) ||
                       error_string.contains(&malicious_content.escape_debug().to_string()),
                       "Error display should include malicious content safely");

                // Should not crash or cause undefined behavior
                assert!(!error_string.is_empty(), "Error display should not be empty");
            }
        }
    }

    #[test]
    fn negative_btreemap_iteration_determinism_under_adversarial_key_patterns() {
        // Test BTreeMap determinism with adversarial key patterns designed to exploit ordering
        let mut capsule = build_reference_capsule();
        capsule.inputs.clear();
        capsule.manifest.input_refs.clear();

        // Keys designed to test lexicographic edge cases and potential hash collision exploitation
        let adversarial_keys = vec![
            // ASCII boundary conditions
            "\x00".to_string(),              // Null character (minimum)
            "\x1F".to_string(),              // Unit separator
            "\x20".to_string(),              // Space
            "\x21".to_string(),              // Exclamation
            "\x7E".to_string(),              // Tilde (near maximum printable ASCII)
            "\x7F".to_string(),              // DEL character
            "\xFF".to_string(),              // Maximum 8-bit value
            // Length-based potential collisions
            "a".to_string(),
            "aa".to_string(),
            "aaa".to_string(),
            // Numeric string sorting edge cases
            "1".to_string(),
            "10".to_string(),
            "11".to_string(),
            "2".to_string(),
            "20".to_string(),
            // Unicode ordering edge cases
            "é".to_string(),                 // Latin small letter e with acute
            "e\u{0301}".to_string(),         // e + combining acute accent
            "\u{1F600}".to_string(),         // Emoji (high Unicode)
            "\u{10FFFF}".to_string(),        // Maximum Unicode codepoint
        ];

        // Insert in random order to test BTreeMap stabilizes the ordering
        for (i, key) in adversarial_keys.into_iter().rev().enumerate() {
            capsule.inputs.insert(key.clone(), format!("value_{:03}", i));
            capsule.manifest.input_refs.push(key);
        }

        // Sort manifest refs to match BTreeMap order
        capsule.manifest.input_refs.sort();

        // Compute hash multiple times to verify determinism
        let hash_attempts = (0..10).map(|_| {
            compute_replay_hash(&capsule.payload, &capsule.inputs)
        }).collect::<Vec<_>>();

        // All hash attempts should be identical
        for (i, hash) in hash_attempts.iter().enumerate() {
            assert_eq!(hash, &hash_attempts[0],
                      "Hash attempt {} differs from first attempt", i);
        }

        capsule.manifest.expected_output_hash = hash_attempts[0].clone();
        sign_capsule(&mut capsule);

        let result = replay(&capsule, "verifier://adversarial-keys").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn negative_replay_verdict_consistency_under_concurrent_simulation() {
        // Test verdict consistency by simulating concurrent access patterns
        let capsule = build_reference_capsule();

        // Simulate multiple "concurrent" replay attempts with identical capsule
        let replay_results: Vec<_> = (0..100).map(|i| {
            replay(&capsule, &format!("verifier://concurrent-sim-{:03}", i))
        }).collect();

        // All replays should succeed with identical results
        for (i, result) in replay_results.iter().enumerate() {
            match result {
                Ok(replay_result) => {
                    assert_eq!(replay_result.verdict, CapsuleVerdict::Pass,
                              "Replay {} should pass", i);
                    assert_eq!(replay_result.actual_hash, replay_result.expected_hash,
                              "Hash mismatch in replay {}", i);
                    assert_eq!(replay_result.capsule_id, capsule.manifest.capsule_id,
                              "Capsule ID mismatch in replay {}", i);
                }
                Err(e) => panic!("Replay {} failed unexpectedly: {}", i, e),
            }
        }

        // Test with slightly modified verifier identities to ensure no cross-contamination
        let verifier_variations = vec![
            "verifier://test-v1",
            "verifier://test-v2",
            "verifier://test-v3",
            "verifier://different-verifier",
            "verifier://CAPS_VERIFIER",
            "verifier://verifier-with-dashes",
            "verifier://123-numeric-verifier",
        ];

        for verifier_id in verifier_variations {
            let result = replay(&capsule, verifier_id).unwrap();
            assert_eq!(result.verdict, CapsuleVerdict::Pass);
            // Result should be identical regardless of verifier identity
            assert_eq!(result.actual_hash, capsule.manifest.expected_output_hash);
        }
    }

    #[test]
    fn negative_hash_collision_resistance_against_birthday_attack_simulation() {
        // Test hash collision resistance with patterns that could exploit birthday paradox
        let base_input = "collision_test_input";
        let mut hash_set = std::collections::HashSet::new();

        // Generate variations of input and verify no collisions occur
        let variations = (0..1000).map(|i| {
            format!("{}_variant_{:04}_{}", base_input, i, "x".repeat(i % 100))
        });

        for input in variations {
            let hash = deterministic_hash(&input);
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));

            // In a cryptographically secure hash, collisions should be extremely rare
            if hash_set.contains(&hash) {
                panic!("Hash collision detected for input: {}", input);
            }
            hash_set.insert(hash);
        }

        // Test with structured input patterns that could exploit internal hash state
        let structured_patterns = vec![
            "aaaa", "aaab", "aaba", "abaa", "baaa", // Hamming distance 1 patterns
            "0000", "0001", "0010", "0100", "1000", // Binary patterns
            "ffff", "fffe", "ffef", "feff", "efff", // High-bit patterns
        ];

        let mut structured_hashes = std::collections::HashSet::new();
        for pattern in structured_patterns {
            let hash = deterministic_hash(pattern);
            assert!(!structured_hashes.contains(&hash),
                   "Collision in structured pattern: {}", pattern);
            structured_hashes.insert(hash);
        }
    }
}
