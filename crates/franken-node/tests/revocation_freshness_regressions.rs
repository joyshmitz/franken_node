use frankenengine_node::security::revocation_freshness::{
    FreshnessCheck, FreshnessError, FreshnessPolicy, OverrideReceipt, SafetyTier,
    evaluate_freshness,
};

fn policy() -> FreshnessPolicy {
    FreshnessPolicy {
        risky_max_age_secs: 3600,
        dangerous_max_age_secs: 300,
    }
}

fn check(tier: SafetyTier, age: u64) -> FreshnessCheck {
    FreshnessCheck {
        action_id: "action-a".to_string(),
        tier,
        revocation_age_secs: age,
        trace_id: "trace-a".to_string(),
        timestamp: "2026-04-25T01:00:00Z".to_string(),
    }
}

fn override_receipt() -> OverrideReceipt {
    OverrideReceipt {
        action_id: "action-a".to_string(),
        actor: "operator-a".to_string(),
        reason: "break-glass maintenance".to_string(),
        timestamp: "2026-04-25T01:01:00Z".to_string(),
        trace_id: "trace-a".to_string(),
    }
}

#[test]
fn invalid_policy_is_rejected_before_decision() {
    let invalid_policy = FreshnessPolicy {
        risky_max_age_secs: 10,
        dangerous_max_age_secs: 11,
    };

    let err = evaluate_freshness(
        &invalid_policy,
        &check(SafetyTier::Dangerous, 1),
        Some(&override_receipt()),
    )
    .expect_err("invalid policy must fail closed before evaluation");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "dangerous_max_age must be <= risky_max_age".to_string(),
        }
    );
}

#[test]
fn standard_tier_rejects_whitespace_padded_action_id() {
    let mut malformed = check(SafetyTier::Standard, 0);
    malformed.action_id = " action-a".to_string();

    let err =
        evaluate_freshness(&policy(), &malformed, None).expect_err("malformed check must fail");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "freshness check action_id must not contain leading or trailing whitespace"
                .to_string(),
        }
    );
}

#[test]
fn fresh_risky_action_rejects_control_character_trace_id() {
    let mut malformed = check(SafetyTier::Risky, 1);
    malformed.trace_id = "trace-a\n".to_string();

    let err = evaluate_freshness(&policy(), &malformed, None).expect_err("control chars must fail");

    assert_eq!(
        err,
        FreshnessError::PolicyInvalid {
            reason: "freshness check trace_id must not contain leading or trailing whitespace"
                .to_string(),
        }
    );
}

#[test]
fn stale_override_rejects_actor_with_trailing_space() {
    let stale = check(SafetyTier::Risky, 7200);
    let mut receipt = override_receipt();
    receipt.actor = "operator-a ".to_string();

    let err = evaluate_freshness(&policy(), &stale, Some(&receipt))
        .expect_err("invalid override metadata must fail closed");

    assert_eq!(
        err,
        FreshnessError::OverrideRequired {
            tier: "Risky".to_string(),
            age_secs: 7200,
        }
    );
}
