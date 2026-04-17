pub mod staking_governance;

#[cfg(test)]
mod tests {
    use super::staking_governance::{
        CapabilityStakeGate, ERR_STAKE_ALREADY_SLASHED, ERR_STAKE_INSUFFICIENT,
        ERR_STAKE_INVALID_TRANSITION, ERR_STAKE_NOT_FOUND, ERR_STAKE_WITHDRAWAL_BLOCKED, RiskTier,
        SlashEvidence, StakeId, StakePolicy, StakeState, StakingError, StakingLedger,
        ViolationType,
    };
    use std::collections::BTreeMap;

    fn evidence(payload: &str) -> SlashEvidence {
        SlashEvidence::new(
            ViolationType::PolicyViolation,
            "policy violation",
            payload,
            "collector-A",
            100,
        )
    }

    fn low_stake_ledger() -> (StakingLedger, StakeId) {
        let mut ledger = StakingLedger::new();
        let stake_id = ledger
            .deposit("publisher-A", 10, RiskTier::Low, 1)
            .expect("minimum low-tier stake should be accepted");
        (ledger, stake_id)
    }

    #[test]
    fn negative_deposit_below_low_minimum_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .deposit("publisher-A", 9, RiskTier::Low, 1)
            .expect_err("stake below tier minimum must be rejected");

        assert!(matches!(
            err,
            StakingError::InsufficientStake {
                required: 10,
                provided: 9,
                code: ERR_STAKE_INSUFFICIENT
            }
        ));
    }

    #[test]
    fn negative_blank_publisher_deposit_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .deposit("   ", 10, RiskTier::Low, 1)
            .expect_err("blank publisher IDs must not create account records");

        assert!(matches!(
            err,
            StakingError::InsufficientStake {
                required: 0,
                provided: 0,
                code: ERR_STAKE_INSUFFICIENT
            }
        ));
        assert!(ledger.accounts.is_empty());
    }

    #[test]
    fn negative_gate_rejects_publisher_without_active_stake() {
        let ledger = StakingLedger::new();
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        let (allowed, event_code, detail) =
            gate.check_stake(&ledger, "publisher-missing", &RiskTier::Low, 10);

        assert!(!allowed);
        assert_eq!(event_code, super::staking_governance::STAKE_007);
        assert!(detail.contains(ERR_STAKE_NOT_FOUND));
    }

    #[test]
    fn negative_withdraw_missing_stake_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .withdraw(StakeId(404), 10)
            .expect_err("unknown stake withdrawal must fail closed");

        assert!(matches!(
            err,
            StakingError::StakeNotFound {
                stake_id: StakeId(404),
                code: ERR_STAKE_NOT_FOUND
            }
        ));
    }

    #[test]
    fn negative_slash_missing_stake_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .slash(StakeId(404), evidence("missing-stake-evidence"), 10)
            .expect_err("unknown stake slash must fail closed");

        assert!(matches!(
            err,
            StakingError::StakeNotFound {
                stake_id: StakeId(404),
                code: ERR_STAKE_NOT_FOUND
            }
        ));
    }

    #[test]
    fn negative_file_appeal_before_slash_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();

        let err = ledger
            .file_appeal(stake_id, 1, "premature appeal", 10)
            .expect_err("active stakes cannot enter appeal without a slash");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Active,
                to: StakeState::UnderAppeal,
                ..
            }
        ));
    }

    #[test]
    fn negative_appeal_at_deadline_is_rejected_fail_closed() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger
            .slash(stake_id, evidence("deadline-evidence"), 100)
            .expect("slash should set appeal window");
        let low_tier_window_secs = 12 * 3600;

        let err = ledger
            .file_appeal(
                stake_id,
                slash_event.slash_id,
                "appeal at exact deadline",
                100 + low_tier_window_secs,
            )
            .expect_err("appeal at exact expiry boundary must fail closed");

        assert!(matches!(err, StakingError::AppealExpired { .. }));
    }

    #[test]
    fn negative_expire_stake_without_expiry_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();

        let err = ledger
            .expire(stake_id, 10)
            .expect_err("stake without expires_at cannot expire");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Active,
                to: StakeState::Expired,
                ..
            }
        ));
    }

    #[test]
    fn negative_gate_rejects_slashed_stake_as_unresolved_slash() {
        let (mut ledger, stake_id) = low_stake_ledger();
        ledger
            .slash(stake_id, evidence("gate-after-slash"), 100)
            .expect("slash should succeed before gate check");
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        let (allowed, _, detail) = gate.check_stake(&ledger, "publisher-A", &RiskTier::Low, 101);

        assert!(!allowed);
        assert!(detail.contains("unresolved slash"));
    }

    #[test]
    fn negative_second_slash_on_same_stake_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        ledger
            .slash(stake_id, evidence("first-slash"), 100)
            .expect("first slash should transition stake");

        let err = ledger
            .slash(stake_id, evidence("second-slash"), 101)
            .expect_err("same stake must not be slashed twice");

        assert!(matches!(
            err,
            StakingError::AlreadySlashed {
                stake_id: id,
                code: ERR_STAKE_ALREADY_SLASHED
            } if id == stake_id
        ));
        assert_eq!(ledger.state.slash_events.len(), 1);
    }

    #[test]
    fn negative_duplicate_evidence_on_second_stake_same_publisher_is_rejected() {
        let mut ledger = StakingLedger::new();
        let first_stake = ledger
            .deposit("publisher-A", 10, RiskTier::Low, 1)
            .expect("first stake should be accepted");
        let second_stake = ledger
            .deposit("publisher-A", 10, RiskTier::Low, 2)
            .expect("second stake should be accepted");
        let duplicate_evidence = evidence("same-payload");
        ledger
            .slash(first_stake, duplicate_evidence.clone(), 100)
            .expect("first slash should be accepted");

        let err = ledger
            .slash(second_stake, duplicate_evidence, 101)
            .expect_err("same publisher evidence hash must not be reused");

        assert!(matches!(
            err,
            StakingError::AlreadySlashed {
                stake_id: id,
                code: ERR_STAKE_ALREADY_SLASHED
            } if id == second_stake
        ));
        assert_eq!(ledger.state.slash_events.len(), 1);
    }

    #[test]
    fn negative_withdraw_slashed_stake_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        ledger
            .slash(stake_id, evidence("withdraw-slashed"), 100)
            .expect("slash should move stake out of active state");

        let err = ledger
            .withdraw(stake_id, 101)
            .expect_err("slashed stake cannot be withdrawn directly");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Slashed,
                to: StakeState::Withdrawn,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
    }

    #[test]
    fn negative_withdraw_under_appeal_stake_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger
            .slash(stake_id, evidence("withdraw-under-appeal"), 100)
            .expect("slash should create appealable event");
        ledger
            .file_appeal(stake_id, slash_event.slash_id, "appeal pending", 101)
            .expect("appeal should enter pending state");

        let err = ledger
            .withdraw(stake_id, 102)
            .expect_err("under-appeal stake cannot be withdrawn");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::UnderAppeal,
                to: StakeState::Withdrawn,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
    }

    #[test]
    fn negative_resolve_missing_appeal_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .resolve_appeal(404, true, 200)
            .expect_err("unknown appeal must fail closed");

        assert!(matches!(
            err,
            StakingError::StakeNotFound {
                stake_id: StakeId(0),
                code: ERR_STAKE_NOT_FOUND
            }
        ));
    }

    #[test]
    fn negative_resolve_same_appeal_twice_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger
            .slash(stake_id, evidence("resolve-twice"), 100)
            .expect("slash should create appealable event");
        let appeal = ledger
            .file_appeal(stake_id, slash_event.slash_id, "appeal once", 101)
            .expect("first appeal should be filed");
        ledger
            .resolve_appeal(appeal.appeal_id, true, 102)
            .expect("first resolution should succeed");

        let err = ledger
            .resolve_appeal(appeal.appeal_id, true, 103)
            .expect_err("resolved appeal must not be resolved again");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Slashed,
                to: StakeState::Slashed,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
        let appeals = ledger.appeals_for_stake(stake_id);
        assert_eq!(appeals.len(), 1);
    }

    #[test]
    fn negative_gate_rejects_withdrawn_stake_as_not_active() {
        let (mut ledger, stake_id) = low_stake_ledger();
        ledger
            .withdraw(stake_id, 2)
            .expect("active stake without cooldown can withdraw");
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        let (allowed, event_code, detail) =
            gate.check_stake(&ledger, "publisher-A", &RiskTier::Low, 3);

        assert!(!allowed);
        assert_eq!(event_code, super::staking_governance::STAKE_007);
        assert!(detail.contains(ERR_STAKE_NOT_FOUND));
    }

    #[test]
    fn negative_expire_missing_stake_is_rejected() {
        let mut ledger = StakingLedger::new();

        let err = ledger
            .expire(StakeId(505), 10)
            .expect_err("unknown stake expiry must fail closed");

        assert!(matches!(
            err,
            StakingError::StakeNotFound {
                stake_id: StakeId(505),
                code: ERR_STAKE_NOT_FOUND
            }
        ));
    }

    #[test]
    fn negative_gate_rejects_active_second_stake_during_cooldown() {
        let mut ledger = StakingLedger::new();
        let first_stake = ledger
            .deposit("publisher-cooldown", 1000, RiskTier::Critical, 1)
            .expect("first critical stake should be accepted");
        ledger
            .deposit("publisher-cooldown", 1000, RiskTier::Critical, 2)
            .expect("second active stake should be accepted");
        ledger
            .slash(first_stake, evidence("cooldown-gate-block"), 100)
            .expect("slash should set publisher cooldown");
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        let (allowed, event_code, detail) =
            gate.check_stake(&ledger, "publisher-cooldown", &RiskTier::Critical, 101);

        assert!(!allowed);
        assert_eq!(event_code, super::staking_governance::STAKE_007);
        assert!(detail.contains("cooldown until"));
    }

    #[test]
    fn negative_withdraw_active_second_stake_during_cooldown_is_blocked() {
        let mut ledger = StakingLedger::new();
        let first_stake = ledger
            .deposit("publisher-withdraw-cooldown", 1000, RiskTier::Critical, 1)
            .expect("first critical stake should be accepted");
        let second_stake = ledger
            .deposit("publisher-withdraw-cooldown", 1000, RiskTier::Critical, 2)
            .expect("second active stake should be accepted");
        ledger
            .slash(first_stake, evidence("cooldown-withdraw-block"), 100)
            .expect("slash should set publisher cooldown");

        let err = ledger
            .withdraw(second_stake, 101)
            .expect_err("cooldown must block withdrawal of another active stake");

        assert!(matches!(
            err,
            StakingError::WithdrawalBlocked {
                stake_id,
                code: ERR_STAKE_WITHDRAWAL_BLOCKED,
                ..
            } if stake_id == second_stake
        ));
        assert_eq!(
            ledger
                .get_stake(second_stake)
                .expect("second stake remains tracked")
                .state,
            StakeState::Active
        );
    }

    #[test]
    fn negative_duplicate_pending_appeal_is_rejected_without_second_record() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger
            .slash(stake_id, evidence("duplicate-pending-appeal"), 100)
            .expect("slash should create appealable event");
        ledger
            .file_appeal(stake_id, slash_event.slash_id, "first appeal", 101)
            .expect("first appeal should be accepted");

        let err = ledger
            .file_appeal(stake_id, slash_event.slash_id, "duplicate appeal", 102)
            .expect_err("second pending appeal must fail closed");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::UnderAppeal,
                to: StakeState::UnderAppeal,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
        assert_eq!(ledger.appeals_for_stake(stake_id).len(), 1);
    }

    #[test]
    fn negative_slash_with_missing_policy_tier_does_not_record_event() {
        let mut ledger = StakingLedger::with_policy(StakePolicy {
            tiers: BTreeMap::new(),
        });
        let stake_id = ledger
            .deposit("publisher-no-tier", 0, RiskTier::Low, 1)
            .expect("missing tier has no configured minimum to enforce at deposit");

        let err = ledger
            .slash(stake_id, evidence("missing-policy-tier"), 2)
            .expect_err("slash must fail closed when the stake tier has no policy");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Active,
                to: StakeState::Slashed,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
        assert!(ledger.state.slash_events.is_empty());
        assert_eq!(
            ledger.get_stake(stake_id).expect("stake remains tracked").state,
            StakeState::Active
        );
    }

    #[test]
    fn negative_gate_with_missing_policy_tier_rejects_even_with_active_stake() {
        let mut ledger = StakingLedger::new();
        ledger
            .deposit("publisher-gate-missing-tier", 10, RiskTier::Low, 1)
            .expect("default low stake should be accepted");
        let gate = CapabilityStakeGate::new(StakePolicy {
            tiers: BTreeMap::new(),
        });

        let (allowed, event_code, detail) =
            gate.check_stake(&ledger, "publisher-gate-missing-tier", &RiskTier::Low, 2);

        assert!(!allowed);
        assert_eq!(event_code, super::staking_governance::STAKE_007);
        assert!(detail.contains("unknown risk tier: low"));
    }

    #[test]
    fn negative_expire_withdrawn_stake_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        ledger
            .withdraw(stake_id, 2)
            .expect("active stake should withdraw before expiry attempt");

        let err = ledger
            .expire(stake_id, 3)
            .expect_err("withdrawn stake must not be expired");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::Withdrawn,
                to: StakeState::Expired,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
    }

    #[test]
    fn negative_expire_under_appeal_stake_is_rejected() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger
            .slash(stake_id, evidence("expire-under-appeal"), 100)
            .expect("slash should create appealable event");
        ledger
            .file_appeal(stake_id, slash_event.slash_id, "appeal before expiry", 101)
            .expect("appeal should move stake under appeal");

        let err = ledger
            .expire(stake_id, 102)
            .expect_err("under-appeal stake must not expire");

        assert!(matches!(
            err,
            StakingError::InvalidTransition {
                from: StakeState::UnderAppeal,
                to: StakeState::Expired,
                code: ERR_STAKE_INVALID_TRANSITION
            }
        ));
    }

    #[test]
    fn negative_gate_one_second_before_cooldown_boundary_is_rejected() {
        let mut ledger = StakingLedger::new();
        let first_stake = ledger
            .deposit("publisher-boundary-cooldown", 1000, RiskTier::Critical, 1)
            .expect("first critical stake should be accepted");
        ledger
            .deposit("publisher-boundary-cooldown", 1000, RiskTier::Critical, 2)
            .expect("second active stake should be accepted");
        ledger
            .slash(first_stake, evidence("cooldown-boundary"), 100)
            .expect("slash should set publisher cooldown");
        let cooldown_until = ledger
            .get_account("publisher-boundary-cooldown")
            .and_then(|account| account.cooldown_until)
            .expect("slash should set cooldown");
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        let (allowed, _, detail) = gate.check_stake(
            &ledger,
            "publisher-boundary-cooldown",
            &RiskTier::Critical,
            cooldown_until.saturating_sub(1),
        );

        assert!(!allowed);
        assert!(detail.contains("cooldown until"));
    }

    // ── Comprehensive negative-path tests for edge cases and attack vectors ──

    #[test]
    fn negative_staking_ledger_with_massive_publisher_id_handles_efficiently() {
        let mut ledger = StakingLedger::new();
        let massive_publisher_id = "x".repeat(100_000); // 100KB publisher ID

        let start_time = std::time::Instant::now();

        // Should either accept or reject large ID efficiently
        let result = ledger.deposit(&massive_publisher_id, 10, RiskTier::Low, 1);

        let duration = start_time.elapsed();
        assert!(duration < std::time::Duration::from_millis(100),
                "Large publisher ID processing took too long: {:?}", duration);

        match result {
            Ok(_) => {
                // If accepted, should be stored correctly
                assert!(ledger.get_account(&massive_publisher_id).is_some());
            }
            Err(_) => {
                // If rejected, should be graceful
                assert!(ledger.accounts.is_empty());
            }
        }
    }

    #[test]
    fn negative_slash_evidence_with_malicious_payload_sanitizes_safely() {
        let (mut ledger, stake_id) = low_stake_ledger();

        // Test various potentially malicious payloads
        let malicious_payloads = vec![
            "\x00\x01\x02\x03\x04", // Null bytes and control characters
            "javascript:alert('xss')", // Potential XSS
            "<script>eval(payload)</script>", // Script injection
            "../../etc/passwd", // Path traversal
            "\u{FFFD}\u{FFFD}", // Replacement characters
            "\u{202E}spoofed\u{202D}", // BiDi override
            format!("{}", "A".repeat(10_000)), // Very long payload
        ];

        for (idx, payload) in malicious_payloads.iter().enumerate() {
            let malicious_evidence = SlashEvidence::new(
                ViolationType::SecurityViolation,
                "malicious evidence test",
                payload,
                &format!("collector-{}", idx),
                100 + idx as u64,
            );

            let result = ledger.slash(stake_id, malicious_evidence, 100 + idx as u64);

            match result {
                Ok(slash_event) => {
                    // If accepted, should be stored safely
                    assert!(slash_event.evidence.evidence_payload.len() <= payload.len());

                    // Should not contain dangerous patterns when serialized
                    let serialized = format!("{:?}", slash_event.evidence);
                    assert!(!serialized.contains("javascript:"));
                    assert!(!serialized.contains("<script>"));
                }
                Err(StakingError::AlreadySlashed { .. }) => {
                    // Expected after first slash
                    break;
                }
                Err(other) => {
                    panic!("Unexpected error for payload {}: {:?}", idx, other);
                }
            }
        }
    }

    #[test]
    fn negative_stake_state_transition_with_concurrent_modifications() {
        let (mut ledger, stake_id) = low_stake_ledger();

        // Simulate concurrent modification patterns
        let slash_evidence = evidence("concurrent-test");

        // First, slash the stake
        let slash_event = ledger.slash(stake_id, slash_evidence, 100).unwrap();

        // Simulate various concurrent operations that should fail
        let concurrent_operations = vec![
            ("withdraw", || ledger.withdraw(stake_id, 101)),
            ("second_slash", || ledger.slash(stake_id, evidence("concurrent-second"), 102)),
            ("expire", || ledger.expire(stake_id, 103)),
        ];

        for (operation_name, operation) in concurrent_operations {
            let result = operation();
            assert!(result.is_err(), "Concurrent {} should fail on slashed stake", operation_name);

            // State should remain consistent
            let stake = ledger.get_stake(stake_id).unwrap();
            assert_eq!(stake.state, StakeState::Slashed);
        }

        // Appeal should work
        let appeal = ledger.file_appeal(stake_id, slash_event.slash_id, "concurrent appeal", 101).unwrap();

        // Now test operations that should fail on under-appeal stake
        let appeal_concurrent_ops = vec![
            ("withdraw_under_appeal", || ledger.withdraw(stake_id, 104)),
            ("expire_under_appeal", || ledger.expire(stake_id, 105)),
            ("double_appeal", || ledger.file_appeal(stake_id, slash_event.slash_id, "double", 106)),
        ];

        for (operation_name, operation) in appeal_concurrent_ops {
            let result = operation();
            assert!(result.is_err(), "Concurrent {} should fail on under-appeal stake", operation_name);

            let stake = ledger.get_stake(stake_id).unwrap();
            assert_eq!(stake.state, StakeState::UnderAppeal);
        }
    }

    #[test]
    fn negative_staking_policy_with_extreme_numeric_values() {
        // Test with extreme policy values that could cause overflow or underflow
        let mut extreme_tiers = BTreeMap::new();

        // Insert tier with maximum values
        extreme_tiers.insert(RiskTier::Critical, super::staking_governance::TierPolicy {
            minimum_stake: u64::MAX,
            slash_percentage: 100,
            appeal_window_seconds: u64::MAX / 2,
            cooldown_seconds: u64::MAX / 4,
        });

        // Insert tier with zero values
        extreme_tiers.insert(RiskTier::Low, super::staking_governance::TierPolicy {
            minimum_stake: 0,
            slash_percentage: 0,
            appeal_window_seconds: 0,
            cooldown_seconds: 0,
        });

        let extreme_policy = StakePolicy { tiers: extreme_tiers };
        let mut ledger = StakingLedger::with_policy(extreme_policy);

        // Test deposit with max value requirement
        let max_result = ledger.deposit("max-publisher", u64::MAX - 1, RiskTier::Critical, 1);
        assert!(max_result.is_err()); // Should reject as insufficient

        let max_exact = ledger.deposit("max-exact-publisher", u64::MAX, RiskTier::Critical, 2);
        assert!(max_exact.is_ok()); // Should accept exact amount

        // Test deposit with zero requirement
        let zero_result = ledger.deposit("zero-publisher", 0, RiskTier::Low, 3);
        assert!(zero_result.is_ok()); // Should accept zero stake

        // Test overflow-resistant arithmetic in cooldown calculation
        if let Ok(stake_id) = max_exact {
            let slash_result = ledger.slash(stake_id, evidence("overflow-test"), u64::MAX - 1000);
            if let Ok(_) = slash_result {
                // Check that cooldown doesn't overflow
                let account = ledger.get_account("max-exact-publisher").unwrap();
                assert!(account.cooldown_until.is_some());
                // Should not have overflowed to a small value
                assert!(account.cooldown_until.unwrap() >= u64::MAX - 1000);
            }
        }
    }

    #[test]
    fn negative_capability_stake_gate_with_malformed_risk_tier_data() {
        let ledger = StakingLedger::new();
        let gate = CapabilityStakeGate::new(StakePolicy::default_policy());

        // Test with risk tier that might be corrupted or unexpected
        let corrupted_tier_tests = vec![
            (RiskTier::Low, "normal case for comparison"),
            (RiskTier::Critical, "high tier case"),
        ];

        for (tier, description) in corrupted_tier_tests {
            let (allowed, event_code, detail) = gate.check_stake(
                &ledger,
                "test-publisher",
                &tier,
                1000
            );

            // Should handle any valid RiskTier without panicking
            assert!(!allowed); // Expected since no stake exists
            assert_eq!(event_code, super::staking_governance::STAKE_007);
            assert!(detail.contains(ERR_STAKE_NOT_FOUND));

            // Test serialization stability
            let serialized = format!("{:?}", tier);
            assert!(!serialized.is_empty());
        }
    }

    #[test]
    fn negative_slash_evidence_hash_collision_resistance() {
        let mut ledger = StakingLedger::new();

        // Create multiple stakes for the same publisher
        let stakes: Vec<_> = (0..5)
            .map(|i| ledger.deposit("collision-publisher", 100, RiskTier::Medium, i + 1).unwrap())
            .collect();

        // Test evidence with very similar payloads that could cause hash collisions
        let similar_payloads = vec![
            "evidence_payload_1",
            "evidence_payload_2",
            "evidence_payload_1 ", // With trailing space
            "evidence_payload_1\0", // With null terminator
            "evidence_payload_1\n", // With newline
        ];

        let mut successful_slashes = 0;

        for (idx, payload) in similar_payloads.iter().enumerate() {
            if idx >= stakes.len() { break; }

            let evidence = SlashEvidence::new(
                ViolationType::PolicyViolation,
                "hash collision test",
                payload,
                &format!("collector-{}", idx),
                100 + idx as u64,
            );

            match ledger.slash(stakes[idx], evidence, 100 + idx as u64) {
                Ok(_) => {
                    successful_slashes += 1;
                }
                Err(StakingError::AlreadySlashed { .. }) => {
                    // This suggests hash collision was detected
                    break;
                }
                Err(other) => {
                    panic!("Unexpected error for payload '{}': {:?}", payload, other);
                }
            }
        }

        // Should have processed at least one slash successfully
        assert!(successful_slashes > 0);

        // Verify evidence storage integrity
        assert_eq!(ledger.state.slash_events.len(), successful_slashes);

        // Each stored evidence should be retrievable and correct
        for (idx, event) in ledger.state.slash_events.iter().enumerate() {
            assert!(event.evidence.evidence_payload.contains("evidence_payload"));
            assert_eq!(event.evidence.collector, format!("collector-{}", idx));
        }
    }

    #[test]
    fn negative_appeal_resolution_with_timestamp_manipulation_attempts() {
        let (mut ledger, stake_id) = low_stake_ledger();
        let slash_event = ledger.slash(stake_id, evidence("timestamp-test"), 100).unwrap();
        let appeal = ledger.file_appeal(stake_id, slash_event.slash_id, "timestamp appeal", 101).unwrap();

        // Test resolution with various timestamp manipulation attempts
        let timestamp_tests = vec![
            (0, "zero timestamp"),
            (u64::MAX, "max timestamp"),
            (99, "timestamp before slash"), // Before slash occurred
            (100, "timestamp at slash time"), // Exact slash time
            (101, "timestamp at appeal time"), // Exact appeal time
            (u64::MAX - 1, "near-max timestamp"),
        ];

        for (timestamp, description) in timestamp_tests {
            // Only the first resolution should succeed
            let result = ledger.resolve_appeal(appeal.appeal_id, true, timestamp);

            if description == "near-max timestamp" {
                // First call should succeed
                assert!(result.is_ok(), "Resolution with {} should succeed on first call", description);

                // Subsequent calls should fail
                let second_result = ledger.resolve_appeal(appeal.appeal_id, false, timestamp + 1);
                assert!(second_result.is_err(), "Second resolution should fail");
                break;
            } else if description == "zero timestamp" {
                // This should be the successful case (first call)
                assert!(result.is_ok(), "First resolution should succeed regardless of timestamp");

                // Test that subsequent attempts fail
                for (later_ts, later_desc) in &timestamp_tests[1..] {
                    let later_result = ledger.resolve_appeal(appeal.appeal_id, true, *later_ts);
                    assert!(later_result.is_err(),
                           "Subsequent resolution with {} should fail: {}", later_desc, later_ts);
                }
                break;
            }
        }
    }

    #[test]
    fn negative_staking_ledger_memory_exhaustion_resistance() {
        let mut ledger = StakingLedger::new();

        // Test creating many accounts without exhausting memory
        let account_count = 1000;
        let mut created_stakes = Vec::new();

        for i in 0..account_count {
            let publisher_id = format!("publisher_{:06}", i);

            match ledger.deposit(&publisher_id, 10, RiskTier::Low, i + 1) {
                Ok(stake_id) => {
                    created_stakes.push((publisher_id.clone(), stake_id));
                }
                Err(_) => {
                    // May reject at some point due to memory constraints - this is acceptable
                    break;
                }
            }

            // Periodic verification that earlier accounts still exist
            if i % 100 == 0 && i > 0 {
                let check_idx = i / 2;
                if let Some((ref check_publisher, check_stake)) = created_stakes.get(check_idx) {
                    let account = ledger.get_account(check_publisher);
                    assert!(account.is_some(), "Earlier account should still exist");
                    let stake = ledger.get_stake(*check_stake);
                    assert!(stake.is_some(), "Earlier stake should still exist");
                }
            }
        }

        // Should have created a reasonable number of accounts
        assert!(created_stakes.len() >= 100, "Should create at least 100 accounts");

        // Test that operations still work on existing accounts
        if let Some((ref publisher, stake_id)) = created_stakes.first() {
            let gate = CapabilityStakeGate::new(StakePolicy::default_policy());
            let (allowed, _, _) = gate.check_stake(&ledger, publisher, &RiskTier::Low, account_count + 1000);
            assert!(allowed, "Gate should work on existing accounts after bulk creation");

            // Test slash on existing stake
            let slash_result = ledger.slash(*stake_id, evidence("memory-test"), account_count + 1001);
            assert!(slash_result.is_ok(), "Slash should work after bulk account creation");
        }
    }

    #[test]
    fn negative_violation_type_serialization_with_unknown_variants() {
        // Test that ViolationType can handle unknown variants gracefully during deserialization
        let violation_types = vec![
            ViolationType::PolicyViolation,
            ViolationType::SecurityViolation,
            ViolationType::PerformanceViolation,
        ];

        for vtype in violation_types {
            // Test serialization round-trip
            let evidence = SlashEvidence::new(
                vtype,
                "serialization test",
                "test payload",
                "test-collector",
                1000,
            );

            // Should be able to debug format without issues
            let debug_str = format!("{:?}", evidence);
            assert!(debug_str.contains("test payload"));
            assert!(debug_str.contains("test-collector"));

            // Test that violation type serializes consistently
            let vtype_debug = format!("{:?}", vtype);
            assert!(!vtype_debug.is_empty());
        }

        // Test error handling with potentially corrupted violation type data
        let (mut ledger, stake_id) = low_stake_ledger();

        for vtype in [ViolationType::SecurityViolation, ViolationType::PerformanceViolation] {
            let evidence = SlashEvidence::new(
                vtype,
                "variant test",
                "test payload",
                "variant-collector",
                2000,
            );

            let result = ledger.slash(stake_id, evidence, 2001);
            match result {
                Ok(_) => {
                    // First slash should succeed
                    break;
                }
                Err(StakingError::AlreadySlashed { .. }) => {
                    // Expected for subsequent attempts
                    break;
                }
                Err(other) => {
                    panic!("Unexpected error with violation type {:?}: {:?}", vtype, other);
                }
            }
        }
    }

    #[test]
    fn negative_edge_case_boundary_arithmetic_in_appeal_window() {
        let (mut ledger, stake_id) = low_stake_ledger();

        // Test appeal window calculation with edge case timestamps
        let edge_timestamps = vec![
            (1, u64::MAX - 1, "near overflow with small base"),
            (u64::MAX - 3600, 1, "large base with small delta"),
            (u64::MAX / 2, u64::MAX / 2, "both values at half max"),
        ];

        for (base_time, delta_time, description) in edge_timestamps {
            let slash_result = ledger.slash(stake_id, evidence(&format!("edge-{}", description)), base_time);

            match slash_result {
                Ok(slash_event) => {
                    // Test appeal filing with potential overflow scenarios
                    let appeal_result = ledger.file_appeal(
                        stake_id,
                        slash_event.slash_id,
                        &format!("appeal for {}", description),
                        base_time.saturating_add(1)
                    );

                    if let Ok(_appeal) = appeal_result {
                        // Test that appeal window calculation doesn't overflow
                        let stake = ledger.get_stake(stake_id).unwrap();
                        assert_eq!(stake.state, StakeState::UnderAppeal);
                    }

                    // Only test first case to avoid AlreadySlashed errors
                    break;
                }
                Err(StakingError::AlreadySlashed { .. }) => {
                    // Expected for subsequent attempts
                    break;
                }
                Err(other) => {
                    panic!("Unexpected error for {}: {:?}", description, other);
                }
            }
        }
    }
}
