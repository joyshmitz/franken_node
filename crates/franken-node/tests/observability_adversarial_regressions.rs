use frankenengine_node::observability::evidence_ledger::DecisionKind;
use frankenengine_node::observability::test_support::{
    malicious_replay_bundle_locators, obs_digest, obs_entry, obs_single_witness_set, obs_witness,
    safe_replay_bundle_locators,
};
use frankenengine_node::observability::witness_ref::{
    WitnessKind, WitnessValidationError, WitnessValidator,
};

#[test]
fn observability_adversarial_regressions_locator_injection_attacks_fail_closed() {
    for locator in malicious_replay_bundle_locators() {
        let entry = obs_entry("obs-locator-injection", DecisionKind::Quarantine);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-malicious-locator", WitnessKind::ProofArtifact, 42)
                .with_locator(locator.clone()),
        );
        let mut validator = WitnessValidator::strict();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("strict validator must reject unsafe replay bundle locators");

        assert!(
            matches!(
                err,
                WitnessValidationError::UnresolvableLocator { .. }
                    | WitnessValidationError::MissingWitnesses { .. }
            ),
            "unexpected error for locator {locator:?}: {err:?}"
        );
        assert_eq!(validator.rejected_count(), 1);
        assert_eq!(validator.validated_count(), 0);
    }
}

#[test]
fn observability_adversarial_regressions_safe_relative_locators_pass_strict() {
    for locator in safe_replay_bundle_locators() {
        let entry = obs_entry("obs-safe-locator", DecisionKind::Quarantine);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-safe-locator-witness", WitnessKind::ProofArtifact, 43)
                .with_locator(*locator),
        );
        let mut validator = WitnessValidator::strict();

        validator
            .validate(&entry, &witnesses)
            .expect("strict validator should accept safe relative replay bundle locators");

        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 0);
    }
}

#[test]
fn observability_adversarial_regressions_hash_collision_attempts_fail_integrity() {
    let collision_attempts = [
        ([0x00; 32], "zero digest"),
        ([0x01; 32], "one digest"),
        ([0xff; 32], "max digest"),
        ([0xaa; 32], "alternating high bits"),
        ([0x55; 32], "alternating low bits"),
    ];
    let witness = obs_witness("obs-collision-witness", WitnessKind::StateSnapshot, 50);
    let mut validator = WitnessValidator::new();

    for (malicious_digest, description) in collision_attempts {
        assert_ne!(obs_digest(50), malicious_digest);
        let err = validator
            .verify_integrity("obs-collision-entry", &witness, &malicious_digest)
            .expect_err("hash collision attempt should fail integrity check");

        assert_eq!(
            err.code(),
            "ERR_INTEGRITY_HASH_MISMATCH",
            "unexpected integrity error for {description}"
        );
    }

    assert_eq!(validator.validated_count(), 0);
    assert_eq!(validator.rejected_count(), collision_attempts.len() as u64);
}

#[test]
fn observability_adversarial_regressions_high_impact_missing_witness_is_typed() {
    let entry = obs_entry("obs-high-impact-missing", DecisionKind::Release);
    let witnesses = frankenengine_node::observability::witness_ref::WitnessSet::new();
    let mut validator = WitnessValidator::new();

    let err = validator
        .validate(&entry, &witnesses)
        .expect_err("release decisions without witnesses must fail closed");

    assert!(matches!(
        err,
        WitnessValidationError::MissingWitnesses { ref entry_id, .. }
            if entry_id == "obs-high-impact-missing"
    ));
    assert_eq!(err.code(), "ERR_MISSING_WITNESSES");
    assert_eq!(validator.rejected_count(), 1);
    assert_eq!(validator.validated_count(), 0);
}
