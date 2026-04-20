//! Regression tests derived from fuzzing campaigns.
//!
//! These tests capture specific edge cases discovered during fuzzing
//! and ensure they remain fixed as the codebase evolves.

#[cfg(test)]
mod fuzz_regression {
    use crate::security::constant_time::{ct_eq, ct_eq_bytes};
    use crate::security::threshold_sig::{ThresholdConfig, SignerKey, verify_threshold, PublicationArtifact, PartialSignature};
    use crate::security::epoch_scoped_keys::{RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature};
    use crate::control_plane::control_epoch::ControlEpoch;

    /// Regression test for constant-time comparison with Unicode normalization differences
    #[test]
    fn regression_constant_time_unicode_normalization() {
        // Test case discovered during structure-aware fuzzing:
        // NFC vs NFD normalization should not be considered equal
        let nfc_string = "café"; // Single codepoint é (U+00E9)
        let nfd_string = "cafe\u{0301}"; // e + combining acute accent (U+0065 U+0301)

        // These look identical when rendered but have different byte representations
        assert!(!ct_eq(nfc_string, nfd_string));
        assert!(!ct_eq_bytes(nfc_string.as_bytes(), nfd_string.as_bytes()));

        // Verify they are indeed different at the byte level
        assert_ne!(nfc_string.as_bytes(), nfd_string.as_bytes());
    }

    /// Regression test for constant-time comparison with zero-width character injection
    #[test]
    fn regression_constant_time_zero_width_injection() {
        // Test case for zero-width space injection attack
        let normal_string = "marker";
        let injected_string = "mark\u{200B}er"; // Zero-width space

        assert!(!ct_eq(normal_string, injected_string));
        assert!(!ct_eq_bytes(normal_string.as_bytes(), injected_string.as_bytes()));
    }

    /// Regression test for threshold signature verification with empty artifact ID
    #[test]
    fn regression_threshold_sig_empty_artifact_id() {
        // Minimal valid config
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "deadbeef".repeat(8), // 64 chars
            }],
        };

        // Artifact with empty ID should be rejected
        let artifact = PublicationArtifact {
            artifact_id: String::new(), // Empty ID
            connector_id: "test-connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        assert!(!result.verified);
        assert!(matches!(result.failure_reason, Some(crate::security::threshold_sig::FailureReason::InvalidArtifactId { .. })));
    }

    /// Regression test for threshold signature verification with path traversal in connector ID
    #[test]
    fn regression_threshold_sig_path_traversal() {
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "deadbeef".repeat(8),
            }],
        };

        // Connector ID with path traversal should be rejected
        let artifact = PublicationArtifact {
            artifact_id: "test-artifact".to_string(),
            connector_id: "../../../admin/connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        assert!(!result.verified);
        assert!(matches!(result.failure_reason, Some(crate::security::threshold_sig::FailureReason::InvalidConnectorId { .. })));
    }

    /// Regression test for epoch key derivation with domain containing control characters
    #[test]
    fn regression_epoch_keys_control_char_domain() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);
        let domain_with_newline = "test\ndomain";

        // Domain with control characters should be rejected by signing function
        let result = sign_epoch_artifact(b"test-data", epoch, domain_with_newline, &secret);
        assert!(result.is_err());

        // Verify it's specifically a domain validation error
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));
    }

    /// Regression test for epoch key derivation with empty domain
    #[test]
    fn regression_epoch_keys_empty_domain() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);

        // Empty domain should be rejected
        let result = sign_epoch_artifact(b"test-data", epoch, "", &secret);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));

        // Whitespace-only domain should also be rejected
        let result = sign_epoch_artifact(b"test-data", epoch, "   ", &secret);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));
    }

    /// Regression test for epoch signature cross-domain replay protection
    #[test]
    fn regression_epoch_keys_cross_domain_replay() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);
        let artifact = b"sensitive-data";

        // Create signature for one domain
        let source_domain = "source-domain";
        let target_domain = "target-domain";

        let signature = sign_epoch_artifact(artifact, epoch, source_domain, &secret)
            .expect("Should create valid signature");

        // Signature should verify with original domain
        verify_epoch_signature(artifact, &signature, epoch, source_domain, &secret)
            .expect("Should verify with original domain");

        // But should fail with different domain
        let replay_result = verify_epoch_signature(artifact, &signature, epoch, target_domain, &secret);
        assert!(replay_result.is_err(), "Cross-domain replay should fail");
    }

    /// Regression test for threshold signature with malformed hex
    #[test]
    fn regression_threshold_sig_malformed_hex() {
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "not-valid-hex-chars".to_string(), // Invalid hex
            }],
        };

        let artifact = PublicationArtifact {
            artifact_id: "test-artifact".to_string(),
            connector_id: "test-connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![PartialSignature {
                signer_id: "test-signer".to_string(),
                key_id: "test-signer".to_string(),
                signature_hex: "deadbeef".repeat(16), // Valid format but won't verify
            }],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        // Should fail due to malformed public key
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
    }

    /// Performance regression test - ensure constant-time operations complete reasonably fast
    #[test]
    fn regression_constant_time_performance() {
        let large_input_a = "x".repeat(4096);
        let large_input_b = "x".repeat(4096);

        let start = std::time::Instant::now();
        let result = ct_eq(&large_input_a, &large_input_b);
        let duration = start.elapsed();

        assert!(result, "Identical large inputs should be equal");
        assert!(duration.as_millis() < 100, "Constant-time comparison should be fast");
    }
}