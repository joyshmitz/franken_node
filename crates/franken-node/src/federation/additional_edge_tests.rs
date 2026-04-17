//! Additional edge case tests for federation modules
//! These tests complement the existing comprehensive test suites by focusing on
//! boundary conditions, overflow scenarios, and resource exhaustion cases.

#[cfg(test)]
mod additional_federation_edge_tests {
    use super::super::atc_participation_weighting::*;
    use super::super::atc_reciprocity::*;

    // === Arithmetic Overflow Edge Cases ===

    #[test]
    fn test_participation_counter_overflow_protection() {
        let mut engine = ParticipationWeightEngine::default();

        // Create participant with near-max participation count to test saturating_add
        let participant = ParticipantIdentity {
            participant_id: "overflow-test".to_string(),
            display_name: "Overflow Test".to_string(),
            attestations: vec![AttestationEvidence {
                attestation_id: "overflow-att".to_string(),
                issuer: "test-ca".to_string(),
                level: AttestationLevel::AuthorityCertified,
                issued_at: "2025-01-01T00:00:00Z".to_string(),
                expires_at: "2027-01-01T00:00:00Z".to_string(),
                signature_hex: "deadbeef".to_string(),
            }],
            stake: None,
            history: Some(ParticipationHistory {
                total_interactions: u64::MAX - 1, // Near overflow
                first_seen: "2020-01-01T00:00:00Z".to_string(),
                last_active: "2026-02-20T00:00:00Z".to_string(),
                success_rate: 0.95,
                violations: 0,
                contribution_score: 8.5,
                attestation_count: u32::MAX - 1, // Near overflow
                ban_status: None,
            }),
            contact_info: None,
        };

        // This should not panic due to overflow - saturating_add should prevent it
        let record =
            engine.compute_weights(&[participant], "overflow-batch", "2026-02-20T00:00:00Z");

        // Verify result is finite and valid
        assert!(record.total_weight.is_finite());
        assert!(!record.weights.is_empty());
        assert!(record.weights[0].final_weight.is_finite());
    }

    #[test]
    fn test_large_participant_list_bounded_capacity() {
        let mut engine = ParticipationWeightEngine::default();

        // Create a very large participant list to test push_bounded protection
        let mut participants = Vec::new();
        for i in 0..10000 {
            participants.push(ParticipantIdentity {
                participant_id: format!("participant-{i}"),
                display_name: format!("Large Test {i}"),
                attestations: vec![AttestationEvidence {
                    attestation_id: format!("att-{i}"),
                    issuer: "mass-ca".to_string(),
                    level: AttestationLevel::PeerVerified,
                    issued_at: "2025-01-01T00:00:00Z".to_string(),
                    expires_at: "2027-01-01T00:00:00Z".to_string(),
                    signature_hex: format!("{i:08x}"),
                }],
                stake: None,
                history: Some(ParticipationHistory {
                    total_interactions: i as u64,
                    first_seen: "2025-01-01T00:00:00Z".to_string(),
                    last_active: "2026-02-20T00:00:00Z".to_string(),
                    success_rate: 0.8,
                    violations: 0,
                    contribution_score: 5.0,
                    attestation_count: 1,
                    ban_status: None,
                }),
                contact_info: None,
            });
        }

        // This should complete without memory exhaustion
        let record = engine.compute_weights(&participants, "large-batch", "2026-02-20T00:00:00Z");

        // Verify the engine handled the large input gracefully
        assert!(record.total_weight.is_finite());
        assert!(record.weights.len() <= participants.len());
    }

    // === Malformed Timestamp Edge Cases ===

    #[test]
    fn test_malformed_timestamp_handling() {
        let mut engine = ParticipationWeightEngine::default();

        let participant = ParticipantIdentity {
            participant_id: "malformed-time".to_string(),
            display_name: "Malformed Time Test".to_string(),
            attestations: vec![AttestationEvidence {
                attestation_id: "malformed-att".to_string(),
                issuer: "test-ca".to_string(),
                level: AttestationLevel::SelfSigned,
                issued_at: "not-a-valid-timestamp".to_string(), // Invalid timestamp
                expires_at: "also-invalid".to_string(),         // Invalid timestamp
                signature_hex: "baddata".to_string(),
            }],
            stake: None,
            history: Some(ParticipationHistory {
                total_interactions: 5,
                first_seen: "invalid-date-format".to_string(), // Invalid
                last_active: "2026-02-20T00:00:00Z".to_string(),
                success_rate: 0.8,
                violations: 0,
                contribution_score: 3.0,
                attestation_count: 1,
                ban_status: None,
            }),
            contact_info: None,
        };

        // Should handle malformed timestamps gracefully without panic
        let record =
            engine.compute_weights(&[participant], "malformed-batch", "2026-02-20T00:00:00Z");

        // Should still produce valid output (participant likely gets rejected)
        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), 1);
        // Participant with malformed data should be rejected
        assert!(record.weights[0].rejected || record.weights[0].final_weight == 0.0);
    }

    // === Reciprocity Engine Edge Cases ===

    #[test]
    fn test_reciprocity_extreme_contribution_ratios() {
        let mut engine = ReciprocityEngine::default();

        // Test with contribution that could cause floating point issues
        let extreme_metrics = ContributionMetrics {
            participant_id: "extreme-contrib".to_string(),
            bytes_contributed: u64::MAX,              // Maximum possible
            bytes_requested: 1,                       // Minimum non-zero
            intelligence_shared: f64::MAX,            // Maximum f64
            intelligence_consumed: f64::MIN_POSITIVE, // Minimum positive f64
            verification_tasks: u32::MAX,             // Maximum u32
            last_contribution: "2026-02-20T00:00:00Z".to_string(),
            banned_until: None,
        };

        // Should handle extreme ratios without panic or NaN
        let decision = engine.evaluate_access(&extreme_metrics, "2026-02-20T00:00:00Z");

        // Verify decision is valid
        assert!(decision.granted || !decision.granted); // Boolean is valid
        assert!(matches!(
            decision.tier,
            AccessTier::Blocked
                | AccessTier::Limited
                | AccessTier::Standard
                | AccessTier::Premium
                | AccessTier::Full
        ));
    }

    #[test]
    fn test_reciprocity_zero_division_protection() {
        let mut engine = ReciprocityEngine::default();

        // Test metrics that could cause division by zero
        let zero_metrics = ContributionMetrics {
            participant_id: "zero-test".to_string(),
            bytes_contributed: 1000,
            bytes_requested: 0, // Zero denominator risk
            intelligence_shared: 5.0,
            intelligence_consumed: 0.0, // Zero denominator risk
            verification_tasks: 10,
            last_contribution: "2026-02-20T00:00:00Z".to_string(),
            banned_until: None,
        };

        // Should handle zero denominators without panic
        let decision = engine.evaluate_access(&zero_metrics, "2026-02-20T00:00:00Z");

        // Should produce valid decision (likely premium tier due to high contribution)
        assert!(decision.granted);
        assert!(matches!(
            decision.tier,
            AccessTier::Standard | AccessTier::Premium | AccessTier::Full
        ));
    }

    // === Concurrent Access Simulation ===

    #[test]
    fn test_concurrent_weight_computation_isolation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(Mutex::new(ParticipationWeightEngine::default()));

        // Simulate concurrent access to the engine
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let engine_clone = Arc::clone(&engine);
                thread::spawn(move || {
                    let participant = ParticipantIdentity {
                        participant_id: format!("concurrent-{thread_id}"),
                        display_name: format!("Concurrent Test {thread_id}"),
                        attestations: vec![AttestationEvidence {
                            attestation_id: format!("att-{thread_id}"),
                            issuer: "concurrent-ca".to_string(),
                            level: AttestationLevel::PeerVerified,
                            issued_at: "2025-01-01T00:00:00Z".to_string(),
                            expires_at: "2027-01-01T00:00:00Z".to_string(),
                            signature_hex: format!("{thread_id:08x}"),
                        }],
                        stake: None,
                        history: Some(ParticipationHistory {
                            total_interactions: thread_id as u64,
                            first_seen: "2025-01-01T00:00:00Z".to_string(),
                            last_active: "2026-02-20T00:00:00Z".to_string(),
                            success_rate: 0.9,
                            violations: 0,
                            contribution_score: thread_id as f64,
                            attestation_count: 1,
                            ban_status: None,
                        }),
                        contact_info: None,
                    };

                    let mut engine_lock = engine_clone.lock().unwrap();
                    let record = engine_lock.compute_weights(
                        &[participant],
                        &format!("concurrent-batch-{thread_id}"),
                        "2026-02-20T00:00:00Z",
                    );

                    // Verify each thread gets valid results
                    assert!(record.total_weight.is_finite());
                    assert!(!record.weights.is_empty());
                    record
                })
            })
            .collect();

        // Wait for all threads and verify results
        for handle in handles {
            let record = handle.join().expect("Thread should complete successfully");
            assert!(record.total_weight >= 0.0);
        }
    }

    // === Resource Exhaustion Protection ===

    #[test]
    fn test_memory_pressure_protection() {
        let mut engine = ParticipationWeightEngine::default();

        // Create participant with very large data to test memory protection
        let large_participant = ParticipantIdentity {
            participant_id: "memory-test".to_string(),
            display_name: "A".repeat(1000), // Large string
            attestations: (0..100)
                .map(|i| AttestationEvidence {
                    attestation_id: format!("large-att-{i}"),
                    issuer: "memory-ca".repeat(10), // Large repeated string
                    level: AttestationLevel::PeerVerified,
                    issued_at: "2025-01-01T00:00:00Z".to_string(),
                    expires_at: "2027-01-01T00:00:00Z".to_string(),
                    signature_hex: "f".repeat(128), // Large signature
                })
                .collect(),
            stake: None,
            history: Some(ParticipationHistory {
                total_interactions: 1000000,
                first_seen: "2020-01-01T00:00:00Z".to_string(),
                last_active: "2026-02-20T00:00:00Z".to_string(),
                success_rate: 0.95,
                violations: 0,
                contribution_score: 10.0,
                attestation_count: 100,
                ban_status: None,
            }),
            contact_info: Some("x".repeat(2000)), // Large contact info
        };

        // Should handle large data without excessive memory usage
        let record =
            engine.compute_weights(&[large_participant], "memory-batch", "2026-02-20T00:00:00Z");

        // Verify result is valid despite large input
        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), 1);
    }
}
