//! Integration tests for state schema migration contracts (bd-b44).
//!
//! Verifies end-to-end migration path resolution, plan execution,
//! idempotency, and error handling.

use frankenengine_node::connector::schema_migration::*;

fn v(major: u32, minor: u32, patch: u32) -> SchemaVersion {
    SchemaVersion::new(major, minor, patch)
}

fn sample_registry() -> MigrationRegistry {
    let mut reg = MigrationRegistry::new();
    reg.register(MigrationHint {
        from_version: v(1, 0, 0),
        to_version: v(1, 1, 0),
        hint_type: HintType::AddField,
        description: "Add email field".into(),
        idempotent: true,
        rollback_safe: true,
    });
    reg.register(MigrationHint {
        from_version: v(1, 1, 0),
        to_version: v(1, 2, 0),
        hint_type: HintType::RenameField,
        description: "Rename name to full_name".into(),
        idempotent: true,
        rollback_safe: true,
    });
    reg.register(MigrationHint {
        from_version: v(1, 2, 0),
        to_version: v(2, 0, 0),
        hint_type: HintType::Transform,
        description: "Major schema overhaul".into(),
        idempotent: false,
        rollback_safe: false,
    });
    reg
}

#[test]
fn end_to_end_migration() {
    let reg = sample_registry();
    let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(2, 0, 0)).unwrap();
    assert_eq!(plan.steps.len(), 3);
    let receipt = execute_plan(&plan, "2026-01-01T00:00:00Z");
    assert_eq!(receipt.outcome, MigrationOutcome::Applied);
    assert_eq!(receipt.steps_applied, 3);
}

#[test]
fn partial_migration() {
    let reg = sample_registry();
    let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 2, 0)).unwrap();
    assert_eq!(plan.steps.len(), 2);
    let receipt = execute_plan(&plan, "t");
    assert_eq!(receipt.outcome, MigrationOutcome::Applied);
}

#[test]
fn no_op_migration_same_version() {
    let reg = sample_registry();
    let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 0, 0)).unwrap();
    assert!(plan.steps.is_empty());
    let receipt = execute_plan(&plan, "t");
    assert_eq!(receipt.outcome, MigrationOutcome::Applied);
    assert_eq!(receipt.steps_applied, 0);
}

#[test]
fn missing_path_produces_error() {
    let reg = sample_registry();
    let err = reg.build_plan("conn-1", &v(1, 0, 0), &v(3, 0, 0)).unwrap_err();
    assert!(matches!(err, MigrationError::MigrationPathMissing { .. }));
}

#[test]
fn idempotent_reapplication() {
    let hint = MigrationHint {
        from_version: v(1, 0, 0),
        to_version: v(1, 1, 0),
        hint_type: HintType::AddField,
        description: "test".into(),
        idempotent: true,
        rollback_safe: true,
    };
    // Already at target version
    let outcome = check_idempotency(&v(1, 1, 0), &hint);
    assert_eq!(outcome, MigrationOutcome::AlreadyApplied);
}

#[test]
fn schema_contract_range_check() {
    let contract = SchemaContract {
        connector_id: "conn-1".into(),
        current_version: v(1, 2, 0),
        min_supported: v(1, 0, 0),
        max_supported: v(2, 0, 0),
    };
    assert!(contract.is_version_supported(&v(1, 0, 0)));
    assert!(contract.is_version_supported(&v(1, 5, 0)));
    assert!(contract.is_version_supported(&v(2, 0, 0)));
    assert!(!contract.is_version_supported(&v(0, 9, 0)));
    assert!(!contract.is_version_supported(&v(2, 1, 0)));
}

#[test]
fn version_parsing_roundtrip() {
    let original = "1.2.3";
    let parsed = SchemaVersion::parse(original).unwrap();
    assert_eq!(parsed.to_string(), original);
}

#[test]
fn migration_receipt_serde() {
    let reg = sample_registry();
    let plan = reg.build_plan("conn-1", &v(1, 0, 0), &v(1, 2, 0)).unwrap();
    let receipt = execute_plan(&plan, "2026-01-01T00:00:00Z");
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: MigrationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.connector_id, "conn-1");
    assert_eq!(parsed.steps_applied, 2);
}
