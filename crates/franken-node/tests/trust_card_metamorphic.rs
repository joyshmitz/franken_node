//! Metamorphic tests for real trust-card canonicalization surfaces.
//!
//! DE-MOCKED: Now includes ed25519-dalek signature verification alongside existing HMAC verification
//! to catch signature/canonicalization bugs that HMAC alone might miss.

use frankenengine_node::supply_chain::{
    certification::{EvidenceType, VerifiedEvidenceRef},
    trust_card::{
        BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
        ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard, TrustCardInput,
        TrustCardRegistry, render_trust_card_human, to_canonical_json, compute_card_hash,
    },
};

// DE-MOCKED: Add ed25519-dalek for real cryptographic signature verification
use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const REGISTRY_KEY: &[u8] = b"trust-card-metamorphic-real-key";
const NOW_SECS: u64 = 1_777_000_000;
const TRACE_ID: &str = "trace-trust-card-metamorphic";

/// Generate a test ed25519 signing key for cryptographic verification
fn generate_test_ed25519_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign canonical trust card bytes using ed25519-dalek
fn sign_trust_card_ed25519(trust_card: &TrustCard, signing_key: &SigningKey) -> Signature {
    let canonical_bytes = to_canonical_json(trust_card)
        .expect("canonical JSON serialization")
        .into_bytes();
    signing_key.sign(&canonical_bytes)
}

/// Verify ed25519 signature on canonical trust card bytes
fn verify_trust_card_ed25519(
    trust_card: &TrustCard,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> bool {
    let canonical_bytes = to_canonical_json(trust_card)
        .expect("canonical JSON serialization")
        .into_bytes();
    verifying_key.verify(&canonical_bytes, signature).is_ok()
}

fn evidence_refs() -> Vec<VerifiedEvidenceRef> {
    vec![
        VerifiedEvidenceRef {
            evidence_id: "ev-provenance-001".to_string(),
            evidence_type: EvidenceType::ProvenanceChain,
            verified_at_epoch: NOW_SECS.saturating_sub(10),
            verification_receipt_hash: "a".repeat(64),
        },
        VerifiedEvidenceRef {
            evidence_id: "ev-test-coverage-001".to_string(),
            evidence_type: EvidenceType::TestCoverageReport,
            verified_at_epoch: NOW_SECS.saturating_sub(5),
            verification_receipt_hash: "b".repeat(64),
        },
    ]
}

fn input_with_order(
    capability_declarations: Vec<CapabilityDeclaration>,
    dependency_trust_summary: Vec<DependencyTrustStatus>,
) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: "npm:@metamorphic/order-stable".to_string(),
            version: "1.2.3".to_string(),
        },
        publisher: PublisherIdentity {
            publisher_id: "pub-metamorphic".to_string(),
            display_name: "Metamorphic Security Team".to_string(),
        },
        certification_level: CertificationLevel::Gold,
        capability_declarations,
        behavioral_profile: BehavioralProfile {
            network_access: true,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary: "Network-only policy checks".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: "slsa-l3".to_string(),
            source_uri: "https://example.invalid/metamorphic/order-stable".to_string(),
            artifact_hashes: vec![
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ],
            verified_at: "2026-04-22T10:00:00Z".to_string(),
        },
        reputation_score_basis_points: 912,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary,
        last_verified_timestamp: "2026-04-22T10:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            level: RiskLevel::Low,
            summary: "Bounded capabilities with verified provenance".to_string(),
        },
        evidence_refs: evidence_refs(),
    }
}

fn capabilities() -> Vec<CapabilityDeclaration> {
    vec![
        CapabilityDeclaration {
            name: "net.fetch".to_string(),
            description: "Fetch policy bundles from approved endpoints".to_string(),
            risk: CapabilityRisk::Medium,
        },
        CapabilityDeclaration {
            name: "auth.validate-token".to_string(),
            description: "Validate signed session tokens".to_string(),
            risk: CapabilityRisk::Low,
        },
        CapabilityDeclaration {
            name: "telemetry.emit".to_string(),
            description: "Emit bounded policy telemetry".to_string(),
            risk: CapabilityRisk::Low,
        },
    ]
}

fn dependencies() -> Vec<DependencyTrustStatus> {
    vec![
        DependencyTrustStatus {
            dependency_id: "npm:zod@3".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:jose@5".to_string(),
            trust_level: "verified".to_string(),
        },
        DependencyTrustStatus {
            dependency_id: "npm:undici@6".to_string(),
            trust_level: "monitored".to_string(),
        },
    ]
}

#[test]
fn capability_and_dependency_order_permutations_preserve_canonical_and_textual_content() {
    let mut baseline_registry = TrustCardRegistry::new(60, REGISTRY_KEY);
    let mut permuted_registry = TrustCardRegistry::new(60, REGISTRY_KEY);

    // DE-MOCKED: Generate real ed25519 keys for cryptographic signature verification
    let ed25519_signing_key = generate_test_ed25519_key();
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();

    let baseline = baseline_registry
        .create(input_with_order(capabilities(), dependencies()), NOW_SECS, TRACE_ID)
        .expect("baseline trust card");

    let mut permuted_capabilities = capabilities();
    permuted_capabilities.reverse();
    let mut permuted_dependencies = dependencies();
    permuted_dependencies.rotate_left(1);
    let permuted = permuted_registry
        .create(
            input_with_order(permuted_capabilities, permuted_dependencies),
            NOW_SECS,
            TRACE_ID,
        )
        .expect("permuted trust card");

    // DE-MOCKED: Add ed25519 signature verification alongside HMAC verification
    let baseline_ed25519_sig = sign_trust_card_ed25519(&baseline, &ed25519_signing_key);
    let permuted_ed25519_sig = sign_trust_card_ed25519(&permuted, &ed25519_signing_key);

    // Verify both signatures are valid
    assert!(
        verify_trust_card_ed25519(&baseline, &baseline_ed25519_sig, &ed25519_verifying_key),
        "baseline trust card ed25519 signature verification failed"
    );
    assert!(
        verify_trust_card_ed25519(&permuted, &permuted_ed25519_sig, &ed25519_verifying_key),
        "permuted trust card ed25519 signature verification failed"
    );

    // DE-MOCKED: ed25519 signatures should be identical for canonically equivalent cards
    assert_eq!(
        baseline_ed25519_sig, permuted_ed25519_sig,
        "ed25519 signatures differ for canonically equivalent trust cards"
    );

    assert_eq!(
        baseline
            .capability_declarations
            .iter()
            .map(|capability| capability.name.as_str())
            .collect::<Vec<_>>(),
        vec!["auth.validate-token", "net.fetch", "telemetry.emit"],
        "baseline capabilities should be canonicalized by name"
    );
    assert_eq!(
        baseline.capability_declarations,
        permuted.capability_declarations,
        "capability declaration order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.dependency_trust_summary,
        permuted.dependency_trust_summary,
        "dependency trust order should be semantic, not caller-order dependent"
    );
    assert_eq!(
        baseline.card_hash, permuted.card_hash,
        "card hash changed for an order-only input permutation"
    );
    assert_eq!(
        baseline.registry_signature, permuted.registry_signature,
        "registry signature changed for an order-only input permutation"
    );
    assert_eq!(
        to_canonical_json(&baseline).expect("baseline canonical JSON"),
        to_canonical_json(&permuted).expect("permuted canonical JSON"),
        "canonical JSON changed for an order-only input permutation"
    );
    assert_eq!(
        render_trust_card_human(&baseline),
        render_trust_card_human(&permuted),
        "user-facing textual content changed for an order-only input permutation"
    );
}
