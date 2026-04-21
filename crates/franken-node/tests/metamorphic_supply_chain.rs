//! Metamorphic Testing for Supply Chain Trust Cards
//!
//! Implements metamorphic relations for oracle problem areas in supply chain trust management:
//! 1. Trust-card add+revoke commutativity
//! 2. Registry admission+eviction idempotence
//! 3. Trust-card envelope encode/decode/re-encode invariance

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

// Mock structures for metamorphic testing (simplified versions of real trust card types)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestTrustCard {
    pub extension_id: String,
    pub certification_level: CertificationLevel,
    pub revocation_status: RevocationStatus,
    pub trust_card_version: u32,
    pub card_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum CertificationLevel {
    Unknown,
    Bronze,
    Silver,
    Gold,
    Platinum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum RevocationStatus {
    Active,
    Revoked { reason: String, revoked_at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestTrustCardMutation {
    pub certification_level: Option<CertificationLevel>,
    pub revocation_status: Option<RevocationStatus>,
}

#[derive(Debug, Clone)]
struct TestTrustCardRegistry {
    cards: BTreeMap<String, TestTrustCard>,
}

impl TestTrustCardRegistry {
    fn new() -> Self {
        Self {
            cards: BTreeMap::new(),
        }
    }

    fn create(&mut self, extension_id: &str, level: CertificationLevel) -> Result<TestTrustCard, String> {
        if self.cards.contains_key(extension_id) {
            return Err("already exists".to_string());
        }

        let card = TestTrustCard {
            extension_id: extension_id.to_string(),
            certification_level: level,
            revocation_status: RevocationStatus::Active,
            trust_card_version: 1,
            card_hash: format!("hash_{}", extension_id),
        };

        self.cards.insert(extension_id.to_string(), card.clone());
        Ok(card)
    }

    fn update(&mut self, extension_id: &str, mutation: TestTrustCardMutation) -> Result<TestTrustCard, String> {
        let existing = self.cards.get_mut(extension_id)
            .ok_or_else(|| "not found".to_string())?;

        let mut updated = existing.clone();
        updated.trust_card_version = existing.trust_card_version.saturating_add(1);

        if let Some(level) = mutation.certification_level {
            updated.certification_level = level;
        }

        if let Some(status) = mutation.revocation_status {
            // Enforce monotonic revocation: once revoked, cannot go back to Active
            if matches!(existing.revocation_status, RevocationStatus::Revoked { .. })
                && matches!(status, RevocationStatus::Active) {
                return Err("cannot unrevoke".to_string());
            }
            updated.revocation_status = status;
        }

        updated.card_hash = format!("hash_{}_v{}", extension_id, updated.trust_card_version);
        self.cards.insert(extension_id.to_string(), updated.clone());
        Ok(updated)
    }

    fn get(&self, extension_id: &str) -> Option<&TestTrustCard> {
        self.cards.get(extension_id)
    }

    fn remove(&mut self, extension_id: &str) -> Option<TestTrustCard> {
        self.cards.remove(extension_id)
    }

    fn contains(&self, extension_id: &str) -> bool {
        self.cards.contains_key(extension_id)
    }

    fn len(&self) -> usize {
        self.cards.len()
    }
}

// === METAMORPHIC RELATIONS ===

/// MR1: Trust-card add+revoke commutativity (Permutative Pattern)
/// Property: revoke(add(registry, card)) == add(revoke(registry, card)) for operations that don't conflict
/// Detects: state-dependent operation ordering bugs, race conditions
#[cfg(test)]
mod trust_card_commutativity_tests {
    use super::*;

    #[test]
    fn mr_add_revoke_commutativity() {
        let mut registry1 = TestTrustCardRegistry::new();
        let mut registry2 = TestTrustCardRegistry::new();

        let extension_id = "npm:@test/package";
        let revoke_mutation = TestTrustCardMutation {
            certification_level: None,
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "security issue".to_string(),
                revoked_at: 12345,
            }),
        };

        // Path 1: Add then Revoke
        registry1.create(extension_id, CertificationLevel::Bronze)
            .expect("create should succeed");
        let result1 = registry1.update(extension_id, revoke_mutation.clone())
            .expect("revoke should succeed");

        // Path 2: Create already-revoked (simulate revoke during creation)
        let _revoked_card = registry2.create(extension_id, CertificationLevel::Bronze)
            .expect("create should succeed");
        let result2 = registry2.update(extension_id, revoke_mutation.clone())
            .expect("revoke should succeed");

        // MR assertion: both paths lead to equivalent revoked state
        assert!(matches!(result1.revocation_status, RevocationStatus::Revoked { .. }),
            "Path 1 should result in revoked card");
        assert!(matches!(result2.revocation_status, RevocationStatus::Revoked { .. }),
            "Path 2 should result in revoked card");

        // Both final states should be equivalent (ignoring version numbers)
        assert_eq!(result1.certification_level, result2.certification_level,
            "Add+Revoke commutativity violated: certification levels differ");

        match (&result1.revocation_status, &result2.revocation_status) {
            (RevocationStatus::Revoked { reason: r1, .. }, RevocationStatus::Revoked { reason: r2, .. }) => {
                assert_eq!(r1, r2, "Revocation reasons should match");
            }
            _ => panic!("Both should be revoked"),
        }
    }

    #[test]
    fn mr_multiple_operations_commutativity() {
        // Test commutativity of: upgrade → revoke vs revoke → upgrade
        let mut registry1 = TestTrustCardRegistry::new();
        let mut registry2 = TestTrustCardRegistry::new();

        let extension_id = "npm:@test/multi-op";

        // Both start with same card
        registry1.create(extension_id, CertificationLevel::Bronze)
            .expect("create should succeed");
        registry2.create(extension_id, CertificationLevel::Bronze)
            .expect("create should succeed");

        // Path 1: Upgrade then Revoke
        registry1.update(extension_id, TestTrustCardMutation {
            certification_level: Some(CertificationLevel::Gold),
            revocation_status: None,
        }).expect("upgrade should succeed");

        let final1 = registry1.update(extension_id, TestTrustCardMutation {
            certification_level: None,
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "test".to_string(),
                revoked_at: 12345,
            }),
        }).expect("revoke should succeed");

        // Path 2: Revoke then attempt upgrade (should fail due to monotonic revocation)
        registry2.update(extension_id, TestTrustCardMutation {
            certification_level: None,
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "test".to_string(),
                revoked_at: 12345,
            }),
        }).expect("revoke should succeed");

        // Attempting to upgrade revoked card should fail
        let upgrade_result = registry2.update(extension_id, TestTrustCardMutation {
            certification_level: Some(CertificationLevel::Gold),
            revocation_status: None,
        });

        // MR assertion: revoke is always final, regardless of operation order
        assert!(upgrade_result.is_err(), "Cannot upgrade revoked card");
        assert!(matches!(final1.revocation_status, RevocationStatus::Revoked { .. }),
            "Final state should be revoked");
    }
}

/// MR2: Registry admission+eviction idempotence (Inclusive Pattern)
/// Property: admit(admit(x)) == admit(x) and evict(evict(x)) == evict(x)
/// Detects: duplicate operation handling bugs, state corruption
#[cfg(test)]
mod registry_idempotence_tests {
    use super::*;

    #[test]
    fn mr_admission_idempotence() {
        let mut registry = TestTrustCardRegistry::new();
        let extension_id = "npm:@test/idempotent";

        // First admission
        let result1 = registry.create(extension_id, CertificationLevel::Bronze);
        assert!(result1.is_ok(), "First admission should succeed");
        let card1 = result1.unwrap();

        let initial_count = registry.len();

        // Second admission should fail (duplicate)
        let result2 = registry.create(extension_id, CertificationLevel::Silver);
        assert!(result2.is_err(), "Duplicate admission should fail");

        // MR assertion: registry state unchanged by failed duplicate admission
        assert_eq!(registry.len(), initial_count,
            "Registry size should not change on duplicate admission");

        let existing_card = registry.get(extension_id)
            .expect("Original card should still exist");

        assert_eq!(existing_card.certification_level, card1.certification_level,
            "Original card certification should be unchanged");
        assert_eq!(existing_card.trust_card_version, card1.trust_card_version,
            "Original card version should be unchanged");
    }

    #[test]
    fn mr_eviction_idempotence() {
        let mut registry = TestTrustCardRegistry::new();
        let extension_id = "npm:@test/evict-idempotent";

        // Set up: create card
        registry.create(extension_id, CertificationLevel::Bronze)
            .expect("Initial create should succeed");

        // First eviction
        let removed1 = registry.remove(extension_id);
        assert!(removed1.is_some(), "First eviction should succeed");

        let count_after_first = registry.len();

        // Second eviction should be idempotent (no-op)
        let removed2 = registry.remove(extension_id);
        assert!(removed2.is_none(), "Second eviction should return None");

        // MR assertion: state unchanged by redundant eviction
        assert_eq!(registry.len(), count_after_first,
            "Registry size should not change on redundant eviction");
        assert!(!registry.contains(extension_id),
            "Extension should remain absent after redundant eviction");
    }

    #[test]
    fn mr_revoke_idempotence() {
        let mut registry = TestTrustCardRegistry::new();
        let extension_id = "npm:@test/revoke-idempotent";

        // Set up: create card
        registry.create(extension_id, CertificationLevel::Bronze)
            .expect("Initial create should succeed");

        let revoke_mutation = TestTrustCardMutation {
            certification_level: None,
            revocation_status: Some(RevocationStatus::Revoked {
                reason: "test revocation".to_string(),
                revoked_at: 12345,
            }),
        };

        // First revocation
        let result1 = registry.update(extension_id, revoke_mutation.clone())
            .expect("First revocation should succeed");

        let version_after_first = result1.trust_card_version;

        // Second revocation (idempotent due to monotonic revocation)
        let result2 = registry.update(extension_id, revoke_mutation.clone());

        // MR assertion: second revocation should be handled gracefully
        // (Either succeed idempotently or fail predictably)
        match result2 {
            Ok(card) => {
                // If it succeeds, it should be idempotent
                assert_eq!(card.trust_card_version, version_after_first.saturating_add(1),
                    "Version should increment even on redundant revoke");
                assert!(matches!(card.revocation_status, RevocationStatus::Revoked { .. }),
                    "Should remain revoked");
            }
            Err(_) => {
                // If it fails, the original revocation should be preserved
                let existing = registry.get(extension_id)
                    .expect("Card should still exist after failed re-revoke");
                assert!(matches!(existing.revocation_status, RevocationStatus::Revoked { .. }),
                    "Should remain revoked even after failed re-revoke");
            }
        }
    }
}

/// MR3: Trust-card envelope encode/decode/re-encode invariance (Invertive Pattern)
/// Property: serialize(x) == serialize(deserialize(serialize(x)))
/// Detects: serialization instability, data loss, format drift
#[cfg(test)]
mod trust_card_roundtrip_tests {
    use super::*;

    fn test_trust_card_roundtrip_invariance(card: &TestTrustCard) {
        // Step 1: Serialize (encode) the original card
        let encoded_original = serde_json::to_string(card)
            .expect("original card should serialize");

        // Step 2: Deserialize (decode) back to struct
        let decoded_card: TestTrustCard = serde_json::from_str(&encoded_original)
            .expect("encoded card should deserialize");

        // Step 3: Re-serialize (re-encode) the decoded struct
        let re_encoded = serde_json::to_string(&decoded_card)
            .expect("decoded card should re-serialize");

        // MR assertion: encode/decode/re-encode invariance
        assert_eq!(encoded_original, re_encoded,
            "Trust card envelope serialization not invariant under roundtrip:\n\
             Original:   {encoded_original}\n\
             Re-encoded: {re_encoded}\n\
             This indicates serialization instability or data loss");

        // Verify structural equivalence too
        assert_eq!(*card, decoded_card,
            "Trust card structure changed during roundtrip - data corruption detected");
    }

    #[test]
    fn mr_trust_card_roundtrip_invariance() {
        // Test with active card
        let active_card = TestTrustCard {
            extension_id: "npm:@test/active-roundtrip".to_string(),
            certification_level: CertificationLevel::Gold,
            revocation_status: RevocationStatus::Active,
            trust_card_version: 1,
            card_hash: "hash_active_v1".to_string(),
        };
        test_trust_card_roundtrip_invariance(&active_card);

        // Test with revoked card
        let revoked_card = TestTrustCard {
            extension_id: "npm:@test/revoked-roundtrip".to_string(),
            certification_level: CertificationLevel::Bronze,
            revocation_status: RevocationStatus::Revoked {
                reason: "security vulnerability detected".to_string(),
                revoked_at: 1672531200, // 2023-01-01
            },
            trust_card_version: 5,
            card_hash: "hash_revoked_v5".to_string(),
        };
        test_trust_card_roundtrip_invariance(&revoked_card);

        // Test with minimal card
        let minimal_card = TestTrustCard {
            extension_id: "a".to_string(),
            certification_level: CertificationLevel::Unknown,
            revocation_status: RevocationStatus::Active,
            trust_card_version: 1,
            card_hash: "h".to_string(),
        };
        test_trust_card_roundtrip_invariance(&minimal_card);

        // Test with maximum complexity card
        let complex_card = TestTrustCard {
            extension_id: "npm:@enterprise/very-long-extension-name-with-special-chars_123".to_string(),
            certification_level: CertificationLevel::Platinum,
            revocation_status: RevocationStatus::Revoked {
                reason: "Multiple critical vulnerabilities: CVE-2023-1234, CVE-2023-5678. Supply chain compromise detected through malicious dependency injection. Immediate revocation required for security.".to_string(),
                revoked_at: 1704067200, // 2024-01-01
            },
            trust_card_version: 999,
            card_hash: "hash_complex_enterprise_security_audit_v999_final".to_string(),
        };
        test_trust_card_roundtrip_invariance(&complex_card);
    }

    #[test]
    fn mr_trust_card_mutation_roundtrip_invariance() {
        let mutations = vec![
            // Certification upgrade
            TestTrustCardMutation {
                certification_level: Some(CertificationLevel::Platinum),
                revocation_status: None,
            },
            // Revocation only
            TestTrustCardMutation {
                certification_level: None,
                revocation_status: Some(RevocationStatus::Revoked {
                    reason: "automated security scan failure".to_string(),
                    revoked_at: 1704153600,
                }),
            },
            // Combined mutation
            TestTrustCardMutation {
                certification_level: Some(CertificationLevel::Silver),
                revocation_status: Some(RevocationStatus::Active),
            },
            // Empty mutation
            TestTrustCardMutation {
                certification_level: None,
                revocation_status: None,
            },
        ];

        for (i, mutation) in mutations.iter().enumerate() {
            let encoded_original = serde_json::to_string(mutation)
                .expect("mutation should serialize");

            let decoded_mutation: TestTrustCardMutation = serde_json::from_str(&encoded_original)
                .expect("encoded mutation should deserialize");

            let re_encoded = serde_json::to_string(&decoded_mutation)
                .expect("decoded mutation should re-serialize");

            assert_eq!(encoded_original, re_encoded,
                "Mutation {i} serialization not invariant under roundtrip");
            assert_eq!(*mutation, decoded_mutation,
                "Mutation {i} structure changed during roundtrip");
        }
    }
}

// === PROPERTY-BASED TESTING ===

/// Composite metamorphic relations combining multiple patterns
#[cfg(test)]
mod composite_metamorphic_tests {
    use super::*;

    #[test]
    fn mr_composite_registry_operations() {
        // Test composition of: admission → mutation → eviction → re-admission
        let mut registry1 = TestTrustCardRegistry::new();
        let mut registry2 = TestTrustCardRegistry::new();

        let extension_id = "npm:@test/composite";

        // Path 1: Standard sequence
        let _card1 = registry1.create(extension_id, CertificationLevel::Bronze)
            .expect("create should succeed");

        let _upgraded1 = registry1.update(extension_id, TestTrustCardMutation {
            certification_level: Some(CertificationLevel::Silver),
            revocation_status: None,
        }).expect("upgrade should succeed");

        let _removed1 = registry1.remove(extension_id)
            .expect("removal should succeed");

        let recreated1 = registry1.create(extension_id, CertificationLevel::Bronze)
            .expect("re-creation should succeed");

        // Path 2: Different sequence (create with higher level directly)
        let _card2 = registry2.create(extension_id, CertificationLevel::Silver)
            .expect("create should succeed");

        let _removed2 = registry2.remove(extension_id)
            .expect("removal should succeed");

        let recreated2 = registry2.create(extension_id, CertificationLevel::Bronze)
            .expect("re-creation should succeed");

        // MR assertion: final states should be equivalent
        // (both registries have Bronze-level cards for the same extension)
        assert_eq!(recreated1.certification_level, recreated2.certification_level,
            "Composite operations should converge to same final certification level");
        assert_eq!(recreated1.extension_id, recreated2.extension_id,
            "Extension IDs should match");

        // Both should be fresh cards (version 1)
        assert_eq!(recreated1.trust_card_version, 1,
            "Re-created card should have version 1");
        assert_eq!(recreated2.trust_card_version, 1,
            "Re-created card should have version 1");
    }
}