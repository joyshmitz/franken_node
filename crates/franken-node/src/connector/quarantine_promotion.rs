//! bd-3cm3: Schema-gated quarantine promotion rules and provenance receipts.
//!
//! Promotion requires reachability + authenticated request + schema validation.
//! Provenance receipt emitted on every successful promotion. Invalid promotions fail closed.

/// Promotion rule configuration.
#[derive(Debug, Clone)]
pub struct PromotionRule {
    pub required_schema_version: String,
    pub require_reachability: bool,
    pub require_pin: bool,
}

impl PromotionRule {
    pub fn default_rule() -> Self {
        Self {
            required_schema_version: "1.0".into(),
            require_reachability: true,
            require_pin: false,
        }
    }
}

/// Request to promote an object from quarantine.
#[derive(Debug, Clone)]
pub struct PromotionRequest {
    pub object_id: String,
    pub requester_id: String,
    pub authenticated: bool,
    pub schema_version: String,
    pub reachable: bool,
    pub pinned: bool,
    pub reason: String,
}

/// Provenance receipt for a successful promotion.
#[derive(Debug, Clone)]
pub struct ProvenanceReceipt {
    pub object_id: String,
    pub promoted_at: String,
    pub requester_id: String,
    pub reason: String,
    pub schema_version: String,
    pub validator_id: String,
    pub trace_id: String,
}

/// Rejection reason for a failed promotion.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectionReason {
    SchemaFailed { expected: String, got: String },
    NotAuthenticated,
    NotReachable,
    NotPinned,
}

/// Result of a promotion attempt.
#[derive(Debug, Clone)]
pub struct PromotionResult {
    pub object_id: String,
    pub promoted: bool,
    pub receipt: Option<ProvenanceReceipt>,
    pub rejection_reasons: Vec<RejectionReason>,
}

/// Errors from promotion operations.
#[derive(Debug, Clone, PartialEq)]
pub enum PromotionError {
    SchemaFailed {
        object_id: String,
        expected: String,
        got: String,
    },
    NotAuthenticated {
        object_id: String,
        requester_id: String,
    },
    NotReachable {
        object_id: String,
    },
    NotPinned {
        object_id: String,
    },
    InvalidRequest {
        reason: String,
    },
    InvalidRule {
        reason: String,
    },
}

impl PromotionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaFailed { .. } => "QPR_SCHEMA_FAILED",
            Self::NotAuthenticated { .. } => "QPR_NOT_AUTHENTICATED",
            Self::NotReachable { .. } => "QPR_NOT_REACHABLE",
            Self::NotPinned { .. } => "QPR_NOT_PINNED",
            Self::InvalidRequest { .. } => "QPR_INVALID_REQUEST",
            Self::InvalidRule { .. } => "QPR_INVALID_RULE",
        }
    }
}

impl std::fmt::Display for PromotionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaFailed {
                object_id,
                expected,
                got,
            } => write!(
                f,
                "QPR_SCHEMA_FAILED: {object_id} expected={expected} got={got}"
            ),
            Self::NotAuthenticated {
                object_id,
                requester_id,
            } => write!(
                f,
                "QPR_NOT_AUTHENTICATED: {object_id} requester={requester_id}"
            ),
            Self::NotReachable { object_id } => write!(f, "QPR_NOT_REACHABLE: {object_id}"),
            Self::NotPinned { object_id } => write!(f, "QPR_NOT_PINNED: {object_id}"),
            Self::InvalidRequest { reason } => write!(f, "QPR_INVALID_REQUEST: {reason}"),
            Self::InvalidRule { reason } => write!(f, "QPR_INVALID_RULE: {reason}"),
        }
    }
}

/// Validate a promotion rule.
pub fn validate_rule(rule: &PromotionRule) -> Result<(), PromotionError> {
    if rule.required_schema_version.trim().is_empty() {
        return Err(PromotionError::InvalidRule {
            reason: "required_schema_version must not be empty".into(),
        });
    }
    Ok(())
}

fn validate_request(
    request: &PromotionRequest,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<(), PromotionError> {
    for (field, value) in [
        ("object_id", request.object_id.as_str()),
        ("requester_id", request.requester_id.as_str()),
        ("reason", request.reason.as_str()),
        ("validator_id", validator_id),
        ("trace_id", trace_id),
        ("timestamp", timestamp),
    ] {
        if value.trim().is_empty() {
            return Err(PromotionError::InvalidRequest {
                reason: format!("{field} must not be empty"),
            });
        }
    }
    Ok(())
}

/// Evaluate a promotion request against a rule.
///
/// INV-QPR-SCHEMA-GATED: schema version must match.
/// INV-QPR-AUTHENTICATED: request must be authenticated.
/// INV-QPR-FAIL-CLOSED: any failure → object stays quarantined.
/// INV-QPR-RECEIPT: success → provenance receipt emitted.
pub fn evaluate_promotion(
    request: &PromotionRequest,
    rule: &PromotionRule,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<PromotionResult, PromotionError> {
    validate_rule(rule)?;
    validate_request(request, validator_id, trace_id, timestamp)?;

    let mut rejections = Vec::new();

    // Check authentication (INV-QPR-AUTHENTICATED)
    if !request.authenticated {
        rejections.push(RejectionReason::NotAuthenticated);
    }

    // Check schema version (INV-QPR-SCHEMA-GATED)
    if request.schema_version != rule.required_schema_version {
        rejections.push(RejectionReason::SchemaFailed {
            expected: rule.required_schema_version.clone(),
            got: request.schema_version.clone(),
        });
    }

    // Check reachability
    if rule.require_reachability && !request.reachable {
        rejections.push(RejectionReason::NotReachable);
    }

    // Check pin
    if rule.require_pin && !request.pinned {
        rejections.push(RejectionReason::NotPinned);
    }

    // INV-QPR-FAIL-CLOSED: any rejection → not promoted
    if !rejections.is_empty() {
        return Ok(PromotionResult {
            object_id: request.object_id.clone(),
            promoted: false,
            receipt: None,
            rejection_reasons: rejections,
        });
    }

    // All checks passed → emit provenance receipt (INV-QPR-RECEIPT)
    let receipt = ProvenanceReceipt {
        object_id: request.object_id.clone(),
        promoted_at: timestamp.to_string(),
        requester_id: request.requester_id.clone(),
        reason: request.reason.clone(),
        schema_version: request.schema_version.clone(),
        validator_id: validator_id.to_string(),
        trace_id: trace_id.to_string(),
    };

    Ok(PromotionResult {
        object_id: request.object_id.clone(),
        promoted: true,
        receipt: Some(receipt),
        rejection_reasons: Vec::new(),
    })
}

/// Batch evaluate promotions. Returns results in order.
pub fn evaluate_batch(
    requests: &[PromotionRequest],
    rule: &PromotionRule,
    validator_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> Result<Vec<PromotionResult>, PromotionError> {
    validate_rule(rule)?;
    let mut results = Vec::with_capacity(requests.len());
    for req in requests {
        let result = evaluate_promotion(req, rule, validator_id, trace_id, timestamp)?;
        results.push(result);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> PromotionRule {
        PromotionRule {
            required_schema_version: "1.0".into(),
            require_reachability: true,
            require_pin: false,
        }
    }

    fn req(id: &str, auth: bool, schema: &str, reachable: bool, pinned: bool) -> PromotionRequest {
        PromotionRequest {
            object_id: id.into(),
            requester_id: "admin".into(),
            authenticated: auth,
            schema_version: schema.into(),
            reachable,
            pinned,
            reason: "test promotion".into(),
        }
    }

    #[test]
    fn promote_valid_object() {
        let r = req("obj1", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(result.promoted);
        assert!(result.receipt.is_some());
        assert!(result.rejection_reasons.is_empty());
    }

    #[test]
    fn reject_unauthenticated() {
        let r = req("obj1", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotAuthenticated)
        );
    }

    #[test]
    fn reject_wrong_schema() {
        let r = req("obj1", true, "2.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|r| matches!(r, RejectionReason::SchemaFailed { .. }))
        );
    }

    #[test]
    fn reject_unreachable() {
        let r = req("obj1", true, "1.0", false, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotReachable)
        );
    }

    #[test]
    fn reject_not_pinned_when_required() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj1", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
    }

    #[test]
    fn pinned_passes_when_required() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj1", true, "1.0", true, true);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();
        assert!(result.promoted);
    }

    #[test]
    fn multiple_rejections() {
        let r = req("obj1", false, "2.0", false, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
        assert_eq!(result.rejection_reasons.len(), 3);
    }

    #[test]
    fn receipt_has_provenance() {
        let r = req("obj1", true, "1.0", true, false);
        let result =
            evaluate_promotion(&r, &rule(), "validator-1", "trace-x", "2026-01-01").unwrap();
        let receipt = result.receipt.unwrap();
        assert_eq!(receipt.object_id, "obj1");
        assert_eq!(receipt.requester_id, "admin");
        assert_eq!(receipt.validator_id, "validator-1");
        assert_eq!(receipt.trace_id, "trace-x");
        assert_eq!(receipt.promoted_at, "2026-01-01");
        assert_eq!(receipt.schema_version, "1.0");
    }

    #[test]
    fn no_receipt_on_rejection() {
        let r = req("obj1", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(result.receipt.is_none());
    }

    #[test]
    fn fail_closed_on_any_error() {
        // Even if only one check fails, promotion is denied
        let r = req("obj1", true, "1.0", false, false); // only reachability fails
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert!(!result.promoted);
    }

    #[test]
    fn batch_evaluation() {
        let requests = vec![
            req("obj1", true, "1.0", true, false),  // should pass
            req("obj2", false, "1.0", true, false), // fail auth
            req("obj3", true, "1.0", true, false),  // should pass
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].promoted);
        assert!(!results[1].promoted);
        assert!(results[2].promoted);
    }

    #[test]
    fn deterministic_evaluation() {
        let r = req("obj1", true, "1.0", true, false);
        let r1 = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        let r2 = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();
        assert_eq!(r1.promoted, r2.promoted);
        assert_eq!(r1.rejection_reasons, r2.rejection_reasons);
    }

    #[test]
    fn invalid_rule_empty_schema() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: false,
        };
        let r = req("obj1", true, "1.0", true, false);
        let err = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap_err();
        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn schema_rejection_preserves_expected_and_got_versions() {
        let mut rl = rule();
        rl.required_schema_version = "schema-2026".into();
        let r = req("obj-schema", true, "schema-2025", true, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(
            result.rejection_reasons,
            vec![RejectionReason::SchemaFailed {
                expected: "schema-2026".into(),
                got: "schema-2025".into(),
            }]
        );
        assert!(result.receipt.is_none());
    }

    #[test]
    fn rejected_result_preserves_object_id_for_audit() {
        let r = req("quarantined-object-7", false, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(result.object_id, "quarantined-object-7");
        assert!(result.receipt.is_none());
    }

    #[test]
    fn all_required_gates_can_fail_together() {
        let mut rl = rule();
        rl.require_pin = true;
        let r = req("obj-all-fail", false, "0.9", false, false);
        let result = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap();

        assert!(!result.promoted);
        assert_eq!(result.rejection_reasons.len(), 4);
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotAuthenticated)
        );
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotReachable)
        );
        assert!(
            result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
        assert!(
            result
                .rejection_reasons
                .iter()
                .any(|reason| matches!(reason, RejectionReason::SchemaFailed { .. }))
        );
        assert!(result.receipt.is_none());
    }

    #[test]
    fn invalid_rule_short_circuits_before_request_rejections() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: true,
        };
        let r = req("obj-short-circuit", false, "bad-schema", false, false);
        let err = evaluate_promotion(&r, &rl, "v1", "tr", "ts").unwrap_err();

        assert_eq!(
            err,
            PromotionError::InvalidRule {
                reason: "required_schema_version must not be empty".into(),
            }
        );
    }

    #[test]
    fn batch_rejects_invalid_rule_for_empty_input() {
        let rl = PromotionRule {
            required_schema_version: "".into(),
            require_reachability: true,
            require_pin: false,
        };
        let err = evaluate_batch(&[], &rl, "v1", "tr", "ts").unwrap_err();

        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn batch_preserves_rejected_items_without_receipts() {
        let requests = vec![
            req("obj-auth", false, "1.0", true, false),
            req("obj-reach", true, "1.0", false, false),
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].promoted);
        assert!(!results[1].promoted);
        assert!(results[0].receipt.is_none());
        assert!(results[1].receipt.is_none());
        assert_eq!(
            results[0].rejection_reasons,
            vec![RejectionReason::NotAuthenticated]
        );
        assert_eq!(
            results[1].rejection_reasons,
            vec![RejectionReason::NotReachable]
        );
    }

    #[test]
    fn batch_keeps_rejection_order_for_mixed_failures() {
        let requests = vec![
            req("obj-schema", true, "2.0", true, false),
            req("obj-auth", false, "1.0", true, false),
            req("obj-reach", true, "1.0", false, false),
        ];
        let results = evaluate_batch(&requests, &rule(), "v1", "tr", "ts").unwrap();

        assert_eq!(
            results
                .iter()
                .map(|result| result.object_id.as_str())
                .collect::<Vec<_>>(),
            vec!["obj-schema", "obj-auth", "obj-reach"]
        );
        assert!(
            results[0]
                .rejection_reasons
                .iter()
                .any(|reason| matches!(reason, RejectionReason::SchemaFailed { .. }))
        );
        assert_eq!(
            results[1].rejection_reasons,
            vec![RejectionReason::NotAuthenticated]
        );
        assert_eq!(
            results[2].rejection_reasons,
            vec![RejectionReason::NotReachable]
        );
    }

    #[test]
    fn pin_rejection_is_not_reported_when_pin_gate_disabled() {
        let r = req("obj-pin-disabled", true, "1.0", true, false);
        let result = evaluate_promotion(&r, &rule(), "v1", "tr", "ts").unwrap();

        assert!(result.promoted);
        assert!(
            !result
                .rejection_reasons
                .contains(&RejectionReason::NotPinned)
        );
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            PromotionError::SchemaFailed {
                object_id: "".into(),
                expected: "".into(),
                got: "".into()
            }
            .code(),
            "QPR_SCHEMA_FAILED"
        );
        assert_eq!(
            PromotionError::NotAuthenticated {
                object_id: "".into(),
                requester_id: "".into()
            }
            .code(),
            "QPR_NOT_AUTHENTICATED"
        );
        assert_eq!(
            PromotionError::NotReachable {
                object_id: "".into()
            }
            .code(),
            "QPR_NOT_REACHABLE"
        );
        assert_eq!(
            PromotionError::NotPinned {
                object_id: "".into()
            }
            .code(),
            "QPR_NOT_PINNED"
        );
        assert_eq!(
            PromotionError::InvalidRequest { reason: "".into() }.code(),
            "QPR_INVALID_REQUEST"
        );
        assert_eq!(
            PromotionError::InvalidRule { reason: "".into() }.code(),
            "QPR_INVALID_RULE"
        );
    }

    #[test]
    fn error_display() {
        let e = PromotionError::SchemaFailed {
            object_id: "obj1".into(),
            expected: "1.0".into(),
            got: "2.0".into(),
        };
        assert!(e.to_string().contains("QPR_SCHEMA_FAILED"));
    }

    #[test]
    fn default_rule_valid() {
        assert!(validate_rule(&PromotionRule::default_rule()).is_ok());
    }
}

#[cfg(test)]
mod quarantine_promotion_additional_negative_tests {
    use super::*;

    fn rule() -> PromotionRule {
        PromotionRule::default_rule()
    }

    fn request(object_id: &str) -> PromotionRequest {
        PromotionRequest {
            object_id: object_id.to_string(),
            requester_id: "operator-a".to_string(),
            authenticated: true,
            schema_version: "1.0".to_string(),
            reachable: true,
            pinned: false,
            reason: "validated quarantine release".to_string(),
        }
    }

    fn expect_invalid_request(err: PromotionError, field: &str) {
        assert!(matches!(
            err,
            PromotionError::InvalidRequest { ref reason } if reason.contains(field)
        ));
    }

    #[test]
    fn whitespace_schema_rule_is_invalid() {
        let invalid = PromotionRule {
            required_schema_version: " \t\n ".to_string(),
            require_reachability: true,
            require_pin: false,
        };
        let err = validate_rule(&invalid).expect_err("blank schema must fail closed");

        assert_eq!(err.code(), "QPR_INVALID_RULE");
    }

    #[test]
    fn blank_object_id_is_invalid_request() {
        let err = evaluate_promotion(&request(" "), &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank object ID must fail closed");

        expect_invalid_request(err, "object_id");
    }

    #[test]
    fn blank_requester_id_is_invalid_request() {
        let mut req = request("object-a");
        req.requester_id = "\t ".to_string();

        let err = evaluate_promotion(&req, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank requester ID must fail closed");

        expect_invalid_request(err, "requester_id");
    }

    #[test]
    fn blank_reason_is_invalid_request() {
        let mut req = request("object-a");
        req.reason.clear();

        let err = evaluate_promotion(&req, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("blank promotion reason must fail closed");

        expect_invalid_request(err, "reason");
    }

    #[test]
    fn blank_validator_id_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), " ", "trace-a", "ts-a")
            .expect_err("blank validator ID must fail closed");

        expect_invalid_request(err, "validator_id");
    }

    #[test]
    fn blank_trace_id_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), "validator-a", "\n", "ts-a")
            .expect_err("blank trace ID must fail closed");

        expect_invalid_request(err, "trace_id");
    }

    #[test]
    fn blank_timestamp_is_invalid_request() {
        let err = evaluate_promotion(&request("object-a"), &rule(), "validator-a", "trace-a", "")
            .expect_err("blank timestamp must fail closed");

        expect_invalid_request(err, "timestamp");
    }

    #[test]
    fn batch_aborts_on_invalid_request_without_receipt() {
        let requests = vec![request("valid-a"), request(" ")];

        let err = evaluate_batch(&requests, &rule(), "validator-a", "trace-a", "ts-a")
            .expect_err("batch should fail closed on invalid request metadata");

        expect_invalid_request(err, "object_id");
    }
}
