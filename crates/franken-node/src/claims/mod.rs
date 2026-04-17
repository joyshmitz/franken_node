pub mod claim_compiler;

#[cfg(test)]
mod additional_negative_tests {
    use super::claim_compiler::{
        ClaimCompiler, ClaimRejectionReason, CompilationResult, CompiledContract, CompilerConfig,
        ScoreboardConfig, ScoreboardPipeline, ScoreboardRejectionReason, ScoreboardUpdateResult,
        error_codes, make_test_claim,
    };

    fn claims_mod_compiler(now_epoch_ms: u64) -> ClaimCompiler {
        ClaimCompiler::new(CompilerConfig::new(
            "claims-mod-signer",
            "claims-mod-key",
            now_epoch_ms,
        ))
    }

    fn claims_mod_contract(claim_id: &str, compiled_at_epoch_ms: u64) -> CompiledContract {
        let claim = make_test_claim(claim_id, "claims-mod-source");
        match claims_mod_compiler(compiled_at_epoch_ms).compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            CompilationResult::Rejected { .. } => {
                panic!("fixture claim should compile");
            }
        }
    }

    fn claims_mod_scoreboard(now_epoch_ms: u64) -> ScoreboardPipeline {
        ScoreboardPipeline::new(ScoreboardConfig::new(
            "claims-mod-signer",
            "claims-mod-key",
            now_epoch_ms,
            60_000,
        ))
    }

    fn claims_mod_limited_scoreboard(
        now_epoch_ms: u64,
        max_contracts: usize,
    ) -> ScoreboardPipeline {
        let config =
            ScoreboardConfig::new("claims-mod-signer", "claims-mod-key", now_epoch_ms, 60_000)
                .with_max_contracts_per_publish(max_contracts);
        ScoreboardPipeline::new(config)
    }

    fn claims_mod_blocking_compiler(now_epoch_ms: u64, blocked_source: &str) -> ClaimCompiler {
        ClaimCompiler::new(
            CompilerConfig::new("claims-mod-signer", "claims-mod-key", now_epoch_ms)
                .with_blocked_source(blocked_source),
        )
    }

    fn assert_claim_rejected(
        result: CompilationResult,
        expected_reason: ClaimRejectionReason,
        expected_code: &str,
    ) {
        match result {
            CompilationResult::Rejected {
                reason, error_code, ..
            } => {
                assert_eq!(reason, expected_reason);
                assert_eq!(error_code, expected_code);
            }
            CompilationResult::Compiled { .. } => {
                panic!("claim should have been rejected");
            }
        }
    }

    fn assert_scoreboard_rejected(
        result: ScoreboardUpdateResult,
        expected_reason: ScoreboardRejectionReason,
        expected_code: &str,
    ) {
        match result {
            ScoreboardUpdateResult::Rejected { reason, error_code } => {
                assert_eq!(reason, expected_reason);
                assert_eq!(error_code, expected_code);
            }
            ScoreboardUpdateResult::Published { .. } => {
                panic!("scoreboard update should have been rejected");
            }
        }
    }

    #[test]
    fn negative_compile_prioritizes_invalid_source_before_empty_claim_text() {
        let mut claim = make_test_claim("claims-mod-null-source-precedence", "claims-mod-source");
        claim.source_id = "claims\0source".to_string();
        claim.claim_text.clear();

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::InvalidSource,
            error_codes::ERR_CLAIM_SOURCE_INVALID,
        );
    }

    #[test]
    fn negative_compile_prioritizes_invalid_source_before_missing_evidence() {
        let mut claim = make_test_claim("claims-mod-source-before-evidence", "claims-mod-source");
        claim.source_id = "\0claims-mod-source".to_string();
        claim.evidence_uris.clear();

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::InvalidSource,
            error_codes::ERR_CLAIM_SOURCE_INVALID,
        );
    }

    #[test]
    fn negative_compile_rejects_trimmed_evidence_uri_with_null_byte() {
        let mut claim = make_test_claim("claims-mod-trimmed-null-evidence", "claims-mod-source");
        claim.evidence_uris = vec!["  https://evidence.example.com/claim\0tail  ".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_compile_rejects_mixed_evidence_with_relative_member() {
        let mut claim = make_test_claim("claims-mod-relative-evidence", "claims-mod-source");
        claim.evidence_uris = vec![
            "urn:claims-mod:valid".to_string(),
            "file://evidence/valid.json".to_string(),
            "../relative/evidence.json".to_string(),
        ];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_epoch_zero_contract_at_freshness_boundary() {
        let contract = claims_mod_contract("claims-mod-zero-stale-boundary", 0);
        let result = claims_mod_scoreboard(60_000).publish("claims-mod-zero-stale", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::StaleEvidence,
            error_codes::ERR_SCOREBOARD_STALE_EVIDENCE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_evidence_link_tamper() {
        let mut contract = claims_mod_contract("claims-mod-evidence-tamper", 10_000);
        contract.evidence_uris[0] = "https://evidence.example.com/tampered".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-evidence-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_snapshot_rejects_signer_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-signer-tamper", 10_000);
        contract.signer_id = "claims-mod-other-signer".to_string();

        assert!(
            claims_mod_scoreboard(10_000)
                .build_snapshot("claims-mod-signer-tamper", &[contract])
                .is_none()
        );
    }

    #[test]
    fn negative_scoreboard_rate_limits_contract_set() {
        let first = claims_mod_contract("claims-mod-rate-a", 10_000);
        let second = claims_mod_contract("claims-mod-rate-b", 10_000);
        let result =
            claims_mod_limited_scoreboard(10_000, 1).publish("claims-mod-rate", &[first, second]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::RateLimited,
            error_codes::ERR_SCOREBOARD_RATE_LIMITED,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_one_stale_member_in_publish_batch() {
        let fresh = claims_mod_contract("claims-mod-fresh-member", 69_999);
        let stale = claims_mod_contract("claims-mod-stale-member", 0);
        let result =
            claims_mod_scoreboard(60_000).publish("claims-mod-mixed-stale", &[fresh, stale]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::StaleEvidence,
            error_codes::ERR_SCOREBOARD_STALE_EVIDENCE,
        );
    }

    #[test]
    fn negative_compile_blocked_source_precedes_empty_claim_text() {
        let mut claim = make_test_claim("claims-mod-blocked-empty-text", "claims-mod-blocked");
        claim.claim_text.clear();

        assert_claim_rejected(
            claims_mod_blocking_compiler(10_000, "claims-mod-blocked").compile(&claim),
            ClaimRejectionReason::Blocked,
            error_codes::ERR_CLAIM_BLOCKED,
        );
    }

    #[test]
    fn negative_compile_blocked_source_normalizes_padded_claim_source() {
        let claim = make_test_claim("claims-mod-padded-blocked", " claims-mod-blocked ");

        assert_claim_rejected(
            claims_mod_blocking_compiler(10_000, "claims-mod-blocked").compile(&claim),
            ClaimRejectionReason::Blocked,
            error_codes::ERR_CLAIM_BLOCKED,
        );
    }

    #[test]
    fn negative_compile_rejects_evidence_uri_with_empty_scheme() {
        let mut claim = make_test_claim("claims-mod-empty-scheme", "claims-mod-source");
        claim.evidence_uris = vec!["://missing-scheme".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_compile_rejects_uppercase_evidence_scheme() {
        let mut claim = make_test_claim("claims-mod-uppercase-scheme", "claims-mod-source");
        claim.evidence_uris = vec!["HTTPS://evidence.example.com/claim".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_claim_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-claim-id-tamper", 10_000);
        contract.claim_id = "claims-mod-claim-id-tampered".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-claim-id-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_source_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-source-id-tamper", 10_000);
        contract.source_id = "claims-mod-other-source".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-source-id-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_rate_limit_precedes_signature_tamper() {
        let valid = claims_mod_contract("claims-mod-rate-valid", 10_000);
        let mut tampered = claims_mod_contract("claims-mod-rate-tampered", 10_000);
        tampered.signature.clear();
        let result = claims_mod_limited_scoreboard(10_000, 1)
            .publish("claims-mod-rate-before-signature", &[valid, tampered]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::RateLimited,
            error_codes::ERR_SCOREBOARD_RATE_LIMITED,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::claim_compiler::{
        ClaimCompiler, ClaimRejectionReason, CompilationResult, CompiledContract, CompilerConfig,
        ExternalClaim, ScoreboardConfig, ScoreboardPipeline, ScoreboardRejectionReason,
        ScoreboardUpdateResult, make_test_claim,
    };

    fn compiler(now_epoch_ms: u64) -> ClaimCompiler {
        ClaimCompiler::new(CompilerConfig::new(
            "scoreboard-signer",
            "test-key",
            now_epoch_ms,
        ))
    }

    fn compile_contract(claim_id: &str, compiled_at_epoch_ms: u64) -> CompiledContract {
        match compiler(compiled_at_epoch_ms).compile(&make_test_claim(claim_id, "source-A")) {
            CompilationResult::Compiled { contract, .. } => contract,
            CompilationResult::Rejected { reason, .. } => {
                panic!("fixture claim should compile, got {reason:?}")
            }
        }
    }

    fn scoreboard(now_epoch_ms: u64) -> ScoreboardPipeline {
        ScoreboardPipeline::new(ScoreboardConfig::new(
            "scoreboard-signer",
            "test-key",
            now_epoch_ms,
            60_000,
        ))
    }

    fn rejection_reason(result: CompilationResult) -> ClaimRejectionReason {
        match result {
            CompilationResult::Rejected { reason, .. } => reason,
            CompilationResult::Compiled { .. } => panic!("expected claim rejection"),
        }
    }

    fn scoreboard_rejection(result: ScoreboardUpdateResult) -> ScoreboardRejectionReason {
        match result {
            ScoreboardUpdateResult::Rejected { reason, .. } => reason,
            ScoreboardUpdateResult::Published { .. } => panic!("expected scoreboard rejection"),
        }
    }

    #[test]
    fn compile_rejects_source_id_containing_null_byte() {
        let claim = ExternalClaim {
            source_id: "source-A\0shadow".to_string(),
            ..make_test_claim("claim-null-source", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::InvalidSource));
    }

    #[test]
    fn compile_rejects_null_byte_evidence_uri() {
        let claim = ExternalClaim {
            evidence_uris: vec!["https://example.test/evidence\0.json".to_string()],
            ..make_test_claim("claim-null-evidence", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::Unverifiable));
    }

    #[test]
    fn compile_rejects_blank_member_in_mixed_evidence_list() {
        let claim = ExternalClaim {
            evidence_uris: vec![
                "https://example.test/evidence.json".to_string(),
                " \t ".to_string(),
            ],
            ..make_test_claim("claim-blank-evidence-member", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::Unverifiable));
    }

    #[test]
    fn compile_rejects_claim_text_with_only_control_whitespace() {
        let claim = ExternalClaim {
            claim_text: "\n\t\r".to_string(),
            ..make_test_claim("claim-control-whitespace", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::SyntaxInvalid));
    }

    #[test]
    fn scoreboard_publish_rejects_tampered_contract_text() {
        let mut contract = compile_contract("claim-tampered-text", 10_000);
        contract.claim_text = "The claim text changed after signing".to_string();

        let reason = scoreboard_rejection(scoreboard(20_000).publish("snap-tampered", &[contract]));

        assert!(matches!(
            reason,
            ScoreboardRejectionReason::SignatureInvalid
        ));
    }

    #[test]
    fn scoreboard_publish_rejects_tampered_signature() {
        let mut contract = compile_contract("claim-tampered-signature", 10_000);
        contract.signature = "0".repeat(64);

        let reason =
            scoreboard_rejection(scoreboard(20_000).publish("snap-signature", &[contract]));

        assert!(matches!(
            reason,
            ScoreboardRejectionReason::SignatureInvalid
        ));
    }

    #[test]
    fn scoreboard_publish_rejects_exact_staleness_boundary() {
        let contract = compile_contract("claim-stale-boundary", 10_000);

        let reason = scoreboard_rejection(scoreboard(70_000).publish("snap-stale", &[contract]));

        assert!(matches!(reason, ScoreboardRejectionReason::StaleEvidence));
    }

    #[test]
    fn scoreboard_publish_rejects_one_contract_when_limit_is_zero() {
        let contract = compile_contract("claim-zero-limit", 10_000);
        let pipeline = ScoreboardPipeline::new(
            ScoreboardConfig::new("scoreboard-signer", "test-key", 20_000, 60_000)
                .with_max_contracts_per_publish(0),
        );

        let reason = scoreboard_rejection(pipeline.publish("snap-zero-limit", &[contract]));

        assert!(matches!(reason, ScoreboardRejectionReason::RateLimited));
    }

    #[test]
    fn scoreboard_build_snapshot_returns_none_for_tampered_digest() {
        let mut contract = compile_contract("claim-tampered-digest", 10_000);
        contract.contract_digest = "0".repeat(64);

        let snapshot = scoreboard(20_000).build_snapshot("snap-digest", &[contract]);

        assert!(snapshot.is_none());
    }

    #[test]
    fn scoreboard_build_snapshot_returns_none_when_any_contract_is_stale() {
        let fresh = compile_contract("claim-fresh-member", 69_999);
        let stale = compile_contract("claim-stale-member", 10_000);

        let snapshot = scoreboard(70_000).build_snapshot("snap-mixed-stale", &[fresh, stale]);

        assert!(snapshot.is_none());
    }
}
