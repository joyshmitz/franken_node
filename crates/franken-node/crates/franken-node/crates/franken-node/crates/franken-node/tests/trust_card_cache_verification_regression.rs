//! Regression test for trust card cache signature verification.
//!
//! Ensures that cached trust cards are always re-verified on cache hits
//! to prevent serving tampered cards from cache.

use frankenengine_node::supply_chain::trust_card::{
    TrustCardRegistry, TrustCardInput, ExtensionProfile, CertificationLevel,
    RevocationStatus, CapabilityDeclaration,
};
use frankenengine_node::security::constant_time;

const TEST_REGISTRY_KEY: &[u8] = b"test-trust-card-registry-key-v1";

fn sample_trust_card_input() -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionProfile {
            extension_id: "npm:@test/cache-verification".to_string(),
            publisher: "test-publisher".to_string(),
            package_name: "cache-verification".to_string(),
            package_version: "1.0.0".to_string(),
            release_date: "2026-01-01".to_string(),
            description: "Test extension for cache verification".to_string(),
            homepage: Some("https://example.com".to_string()),
            repository: Some("https://github.com/test/cache-verification".to_string()),
            license: Some("MIT".to_string()),
        },
        certification_level: CertificationLevel::Basic,
        capability_declarations: vec![
            CapabilityDeclaration {
                capability_type: "network".to_string(),
                scope: vec!["https://api.example.com".to_string()],
                justification: "API access for functionality".to_string(),
            }
        ],
        derivation_evidence_refs: vec![],
        active_quarantine: false,
        reputation_score_basis_points: 8500,
        user_facing_risk_assessment: "low".to_string(),
        revocation_status: RevocationStatus::Valid,
    }
}

#[test]
fn cache_hit_requires_signature_verification() {
    let mut registry = TrustCardRegistry::new(300, TEST_REGISTRY_KEY); // 5 min TTL

    // Create a trust card
    let input = sample_trust_card_input();
    let card = registry
        .create(input, 1000, "test-trace")
        .expect("create trust card");

    // Read it once to populate cache
    let cached_card = registry
        .read("npm:@test/cache-verification", 1001, "test-trace")
        .expect("read from cache")
        .expect("card should exist");

    assert_eq!(card.card_hash, cached_card.card_hash);

    // Verify cache contains the card
    assert!(registry.cache_by_extension.contains_key("npm:@test/cache-verification"));

    // Tamper with cached card signature (simulates cache poisoning)
    let mut tampered_cached = registry
        .cache_by_extension
        .get_mut("npm:@test/cache-verification")
        .expect("cached card exists");
    tampered_cached.card.registry_signature = "tampered_signature".to_string();

    // Attempt to read from cache - should detect tampering and fallback to source
    let result = registry
        .read("npm:@test/cache-verification", 1002, "test-trace")
        .expect("read should succeed")
        .expect("card should exist");

    // Should return the correct card from source, not the tampered cache
    assert_eq!(card.card_hash, result.card_hash);

    // Cache should be repaired with valid card
    let repaired_cached = registry
        .cache_by_extension
        .get("npm:@test/cache-verification")
        .expect("cache should be repaired");
    assert_eq!(card.card_hash, repaired_cached.card.card_hash);
    assert!(constant_time::ct_eq(&card.registry_signature, &repaired_cached.card.registry_signature));
}

#[test]
fn sync_cache_requires_signature_verification() {
    let mut registry = TrustCardRegistry::new(300, TEST_REGISTRY_KEY);

    // Create and cache a trust card
    let input = sample_trust_card_input();
    let card = registry
        .create(input, 1000, "test-trace")
        .expect("create trust card");

    // Tamper with cached card
    let mut tampered_cached = registry
        .cache_by_extension
        .get_mut("npm:@test/cache-verification")
        .expect("cached card exists");
    tampered_cached.card.reputation_score_basis_points = 1; // Tamper with content

    // Sync cache should detect tampering and rebuild from source
    let report = registry
        .sync_cache(1001, "test-trace", false)
        .expect("sync cache");

    // Should report cache miss due to invalid cached entry
    assert_eq!(report.cache_misses, 1);
    assert_eq!(report.cache_hits, 0);

    // Cache should be rebuilt with correct card
    let rebuilt_cached = registry
        .cache_by_extension
        .get("npm:@test/cache-verification")
        .expect("cache should be rebuilt");
    assert_eq!(card.card_hash, rebuilt_cached.card.card_hash);
    assert_eq!(card.reputation_score_basis_points, rebuilt_cached.card.reputation_score_basis_points);
}

#[test]
fn cache_verification_prevents_signature_bypass() {
    let mut registry = TrustCardRegistry::new(300, TEST_REGISTRY_KEY);

    // Create trust card
    let input = sample_trust_card_input();
    let original = registry
        .create(input, 1000, "test-trace")
        .expect("create trust card");

    // Read to populate cache
    registry
        .read("npm:@test/cache-verification", 1001, "test-trace")
        .expect("read");

    // Tamper with both card hash and signature in cache
    let mut tampered_cached = registry
        .cache_by_extension
        .get_mut("npm:@test/cache-verification")
        .expect("cached card exists");
    tampered_cached.card.card_hash = "malicious_hash".to_string();
    tampered_cached.card.registry_signature = "malicious_signature".to_string();

    // Subsequent read should reject tampered cache and return valid card
    let result = registry
        .read("npm:@test/cache-verification", 1002, "test-trace")
        .expect("read should succeed")
        .expect("card should exist");

    // Must return original valid card, not tampered one
    assert_eq!(original.card_hash, result.card_hash);
    assert_ne!(result.card_hash, "malicious_hash");
    assert_ne!(result.registry_signature, "malicious_signature");
}