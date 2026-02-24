pub mod connector_method_validator;
pub mod fsqlite_inspired_suite;
pub mod protocol_harness;

/// Initialize tracing subscriber for test runs.
///
/// Call at the top of integration tests to get structured debug output.
/// Uses `try_init` so it's safe to call multiple times (only the first
/// call actually installs the subscriber).
#[cfg(test)]
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}

#[cfg(test)]
mod tracing_integration_tests {
    use super::*;
    use connector_method_validator::{MethodDeclaration, all_methods};
    use protocol_harness::{PolicyOverride, check_publication, run_harness};

    fn full_declarations() -> Vec<MethodDeclaration> {
        all_methods()
            .into_iter()
            .map(|name| MethodDeclaration {
                name: name.to_string(),
                version: "1.0.0".to_string(),
                has_input_schema: true,
                has_output_schema: true,
            })
            .collect()
    }

    fn missing_handshake_declarations() -> Vec<MethodDeclaration> {
        full_declarations()
            .into_iter()
            .filter(|d| d.name != "handshake")
            .collect()
    }

    #[test]
    fn test_tracing_init_does_not_panic() {
        init_test_tracing();
        init_test_tracing(); // safe to call twice
    }

    #[test]
    fn test_validate_contract_emits_traces() {
        init_test_tracing();
        let report =
            connector_method_validator::validate_contract("traced-conn", &full_declarations());
        assert_eq!(report.verdict, "PASS");
    }

    #[test]
    fn test_validate_contract_failure_emits_warn() {
        init_test_tracing();
        let report = connector_method_validator::validate_contract(
            "traced-fail",
            &missing_handshake_declarations(),
        );
        assert_eq!(report.verdict, "FAIL");
        assert!(report.summary.failing > 0);
    }

    #[test]
    fn test_check_publication_traces_pass() {
        init_test_tracing();
        let result = check_publication(
            "traced-conn",
            &full_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW");
    }

    #[test]
    fn test_check_publication_traces_block() {
        init_test_tracing();
        let result = check_publication(
            "traced-fail",
            &missing_handshake_declarations(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
    }

    #[test]
    fn test_check_publication_traces_override() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-TRACE-001".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Testing".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "ALLOW_OVERRIDE");
    }

    #[test]
    fn test_check_publication_traces_expired_override() {
        init_test_tracing();
        let policy = PolicyOverride {
            override_id: "OVERRIDE-EXP-001".to_string(),
            connector_id: "traced-conn".to_string(),
            reason: "Expired".to_string(),
            authorized_by: "admin".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(),
            scope: vec!["METHOD_MISSING:handshake".to_string()],
        };
        let result = check_publication(
            "traced-conn",
            &missing_handshake_declarations(),
            Some(&policy),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(result.gate_decision, "BLOCK");
    }

    #[test]
    fn test_run_harness_traces_full_run() {
        init_test_tracing();
        let connectors = vec![
            ("conn-ok".to_string(), full_declarations(), None),
            (
                "conn-fail".to_string(),
                missing_handshake_declarations(),
                None,
            ),
        ];
        let report = run_harness(&connectors, "2026-01-01T00:00:00Z");
        assert_eq!(report.total_connectors, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 1);
    }

    #[test]
    fn test_run_harness_empty_traced() {
        init_test_tracing();
        let report = run_harness(&[], "2026-01-01T00:00:00Z");
        assert_eq!(report.verdict, "PASS");
    }

    #[test]
    fn test_version_mismatch_traced() {
        init_test_tracing();
        let mut decls = full_declarations();
        decls[0].version = "2.0.0".to_string(); // major version mismatch
        let report = connector_method_validator::validate_contract("version-mismatch", &decls);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn test_schema_missing_traced() {
        init_test_tracing();
        let mut decls = full_declarations();
        decls[0].has_input_schema = false;
        let report = connector_method_validator::validate_contract("schema-missing", &decls);
        assert_eq!(report.verdict, "FAIL");
    }
}
