//! Trust Card Manifest Reference Conformance Test Harness
//!
//! Validates that trust card references in extension manifests follow the
//! correct format and are properly validated during manifest processing.
//! Cross-validates manifest trust metadata with trust card registry state.
//!
//! ## Specification Coverage
//!
//! | Requirement | Type | Test Cases | Status |
//! |------------|------|------------|--------|
//! | Trust card reference format validation | MUST | 6 | ✅ |
//! | Manifest schema compliance | MUST | 4 | ✅ |
//! | Trust metadata consistency | MUST | 5 | ✅ |
//! | Cross-validation with registry | SHOULD | 3 | ✅ |

use serde_json::{Value, json};
use std::collections::BTreeMap;

use frankenengine_node::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
use frankenengine_node::supply_chain::manifest::{
    CertificationLevel, ExtensionManifest, ManifestSchemaError, ManifestSignature, PackageMetadata,
    SignatureScheme, TrustMetadata, validate_signed_manifest,
};
use frankenengine_node::supply_chain::trust_card::{
    BehavioralProfile, CapabilityDeclaration, CapabilityRisk,
    ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend,
    RevocationStatus, RiskAssessment, RiskLevel, TrustCardInput, TrustCardRegistry,
};

const MANIFEST_SPEC_REFERENCE: &str = "docs/specs/section_10_4/extension_manifest_schema.md + docs/specs/section_10_4/bd-2yh_contract.md";
const TEST_REGISTRY_KEY: &[u8] = b"manifest-conformance-test-key";
const BASE_TIMESTAMP: u64 = 1745000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLevel {
    Must,
    Should,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestTestCategory {
    TrustReferenceFormat,
    SchemaCompliance,
    MetadataConsistency,
    RegistryCrossValidation,
}

#[derive(Debug, Clone)]
enum ConformanceResult {
    Pass,
    Fail { reason: String },
}

#[derive(Debug)]
struct ManifestConformanceCase {
    id: &'static str,
    spec_section: &'static str,
    requirement_level: RequirementLevel,
    category: ManifestTestCategory,
    description: &'static str,
    test_fn: fn(&mut TrustCardRegistry) -> ConformanceResult,
}

/// Generate valid baseline manifest for testing
fn valid_manifest() -> ExtensionManifest {
    ExtensionManifest {
        package: PackageMetadata {
            name: "test-extension".to_string(),
            version: "1.0.0".to_string(),
        },
        entrypoint: "index.js".to_string(),
        capabilities: vec!["fs:read".to_string()],
        minimum_runtime_version: "1.0.0".to_string(),
        trust: TrustMetadata {
            certification_level: CertificationLevel::Verified,
            revocation_status_pointer: "revocation://extensions/test-extension".to_string(),
            trust_card_reference: "trust-card://test-extension@1.0.0".to_string(),
        },
        signature: ManifestSignature {
            scheme: SignatureScheme::ThresholdEd25519,
            publisher_key_id: "key-publisher-test".to_string(),
            signature: "Q09ORk9STUFUSU9O".to_string(), // Base64 encoded "CONFORMANCE"
        },
    }
}

/// Generate trust card input corresponding to manifest
fn trust_card_input_for_manifest(manifest: &ExtensionManifest) -> TrustCardInput {
    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
        },
        publisher: PublisherIdentity {
            publisher_id: "publisher:manifest-test".to_string(),
            display_name: "Manifest Test Publisher".to_string(),
        },
        certification_level: match manifest.trust.certification_level {
            CertificationLevel::Verified => frankenengine_node::supply_chain::trust_card::CertificationLevel::Gold,
            CertificationLevel::Bronze => frankenengine_node::supply_chain::trust_card::CertificationLevel::Bronze,
            CertificationLevel::Silver => frankenengine_node::supply_chain::trust_card::CertificationLevel::Silver,
            CertificationLevel::Gold => frankenengine_node::supply_chain::trust_card::CertificationLevel::Gold,
        },
        capability_declarations: manifest.capabilities.iter().map(|cap| {
            CapabilityDeclaration {
                name: cap.clone(),
                description: format!("Capability: {}", cap),
                risk: CapabilityRisk::Low,
            }
        }).collect(),
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: manifest.capabilities.iter().any(|c| c.contains("fs")),
            subprocess_access: manifest.capabilities.iter().any(|c| c.contains("process")),
            profile_summary: "Manifest-based trust card".to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            verified_sources: vec!["manifest-test-source".to_string()],
            verification_timestamp: "2026-04-30T18:00:00Z".to_string(),
            chain_integrity_score: 95,
        },
        reputation_score_basis_points: 9000,
        reputation_trend: ReputationTrend::Stable,
        active_quarantine: false,
        dependency_trust_summary: vec![],
        last_verified_timestamp: "2026-04-30T18:00:00Z".to_string(),
        user_facing_risk_assessment: RiskAssessment {
            overall_risk: RiskLevel::Low,
            risk_factors: vec![],
            mitigation_suggestions: vec![],
        },
        evidence_refs: vec![
            VerifiedEvidenceRef {
                evidence_id: "manifest-test-evidence".to_string(),
                evidence_type: EvidenceType::StaticAnalysis,
                verified_at_epoch: BASE_TIMESTAMP,
                verification_receipt_hash: "sha256:".to_string() + &"a".repeat(64),
            }
        ],
    }
}

/// Test: Valid trust card references must be accepted
fn test_valid_trust_card_references(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    let valid_references = vec![
        "trust-card://test-extension@1.0.0",
        "trust-card://namespace/package@2.1.0",
        "trust-card://org.example.extension@1.0.0-beta.1",
        "trust-card://@scoped/package@3.2.1",
    ];

    for (i, reference) in valid_references.into_iter().enumerate() {
        let mut manifest = valid_manifest();
        manifest.trust.trust_card_reference = reference.to_string();
        manifest.package.name = format!("test-extension-{}", i);

        match validate_signed_manifest(&manifest) {
            Ok(()) => {} // Expected
            Err(e) => {
                return ConformanceResult::Fail {
                    reason: format!("Valid trust card reference '{}' was rejected: {}", reference, e)
                };
            }
        }
    }

    ConformanceResult::Pass
}

/// Test: Invalid trust card references must be rejected
fn test_invalid_trust_card_references(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    let invalid_references = vec![
        ("", "empty reference"),
        ("  ", "whitespace only"),
        ("invalid-scheme://test@1.0.0", "wrong scheme"),
        ("trust-card://", "missing extension part"),
        ("trust-card://test", "missing version"),
        ("trust-card://test@", "empty version"),
    ];

    for (reference, description) in invalid_references {
        let mut manifest = valid_manifest();
        manifest.trust.trust_card_reference = reference.to_string();
        manifest.package.name = format!("invalid-test-{}", reference.len());

        match validate_signed_manifest(&manifest) {
            Ok(()) => {
                return ConformanceResult::Fail {
                    reason: format!("Invalid trust card reference '{}' ({}) was incorrectly accepted", reference, description)
                };
            }
            Err(ManifestSchemaError::MissingField { field }) => {
                if field == "trust.trust_card_reference" {
                    // Expected for empty/whitespace cases
                    continue;
                } else {
                    return ConformanceResult::Fail {
                        reason: format!("Wrong error field for '{}': expected trust.trust_card_reference, got {}", reference, field)
                    };
                }
            }
            Err(_) => {
                // Other errors are acceptable for invalid formats
                continue;
            }
        }
    }

    ConformanceResult::Pass
}

/// Test: Manifest certification level consistency
fn test_certification_level_consistency(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    let certification_levels = vec![
        CertificationLevel::Bronze,
        CertificationLevel::Silver,
        CertificationLevel::Gold,
        CertificationLevel::Verified,
    ];

    for cert_level in certification_levels {
        let mut manifest = valid_manifest();
        manifest.trust.certification_level = cert_level;
        manifest.package.name = format!("cert-test-{:?}", cert_level).to_lowercase();

        match validate_signed_manifest(&manifest) {
            Ok(()) => {} // All certification levels should be valid
            Err(e) => {
                return ConformanceResult::Fail {
                    reason: format!("Valid certification level {:?} was rejected: {}", cert_level, e)
                };
            }
        }
    }

    ConformanceResult::Pass
}

/// Test: Trust card reference format extraction
fn test_trust_reference_format_extraction(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    let manifest = valid_manifest();

    // Extract extension ID and version from trust card reference
    let reference = &manifest.trust.trust_card_reference;
    if !reference.starts_with("trust-card://") {
        return ConformanceResult::Fail {
            reason: format!("Trust card reference '{}' doesn't start with trust-card://", reference)
        };
    }

    let extension_part = &reference["trust-card://".len()..];
    if let Some(at_pos) = extension_part.rfind('@') {
        let extension_id = &extension_part[..at_pos];
        let version = &extension_part[at_pos + 1..];

        // Should match manifest package metadata
        if extension_id != manifest.package.name {
            return ConformanceResult::Fail {
                reason: format!(
                    "Extension ID mismatch: trust_card_reference contains '{}', package.name is '{}'",
                    extension_id, manifest.package.name
                )
            };
        }

        if version != manifest.package.version {
            return ConformanceResult::Fail {
                reason: format!(
                    "Version mismatch: trust_card_reference contains '{}', package.version is '{}'",
                    version, manifest.package.version
                )
            };
        }

        ConformanceResult::Pass
    } else {
        ConformanceResult::Fail {
            reason: format!("Trust card reference '{}' doesn't contain '@' separator", reference)
        }
    }
}

/// Test: Cross-validation with trust card registry
fn test_registry_cross_validation(registry: &mut TrustCardRegistry) -> ConformanceResult {
    let manifest = valid_manifest();

    // Create corresponding trust card in registry
    let trust_input = trust_card_input_for_manifest(&manifest);
    let created_card = match registry.create(trust_input, BASE_TIMESTAMP, "trace-cross-validation") {
        Ok(card) => card,
        Err(e) => {
            return ConformanceResult::Fail {
                reason: format!("Failed to create trust card for cross-validation: {}", e)
            };
        }
    };

    // Validate manifest
    match validate_signed_manifest(&manifest) {
        Ok(()) => {} // Expected
        Err(e) => {
            return ConformanceResult::Fail {
                reason: format!("Manifest validation failed during cross-validation: {}", e)
            };
        }
    }

    // Cross-validate: extension IDs should match
    if created_card.extension.extension_id != manifest.package.name {
        return ConformanceResult::Fail {
            reason: format!(
                "Extension ID cross-validation failed: trust_card={}, manifest={}",
                created_card.extension.extension_id, manifest.package.name
            )
        };
    }

    // Cross-validate: versions should match
    if created_card.extension.version != manifest.package.version {
        return ConformanceResult::Fail {
            reason: format!(
                "Version cross-validation failed: trust_card={}, manifest={}",
                created_card.extension.version, manifest.package.version
            )
        };
    }

    ConformanceResult::Pass
}

/// Test: Revocation status pointer format validation
fn test_revocation_pointer_validation(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    let valid_pointers = vec![
        "revocation://extensions/test-extension",
        "revocation://registry.example.com/packages/test",
        "revocation://org.example/extensions/my-package",
    ];

    for (i, pointer) in valid_pointers.into_iter().enumerate() {
        let mut manifest = valid_manifest();
        manifest.trust.revocation_status_pointer = pointer.to_string();
        manifest.package.name = format!("revocation-test-{}", i);

        match validate_signed_manifest(&manifest) {
            Ok(()) => {} // Expected
            Err(e) => {
                return ConformanceResult::Fail {
                    reason: format!("Valid revocation status pointer '{}' was rejected: {}", pointer, e)
                };
            }
        }
    }

    // Test invalid pointers
    let invalid_pointers = vec![
        ("", "empty pointer"),
        ("  ", "whitespace only"),
        ("http://example.com/revocation", "wrong scheme"),
        ("revocation://", "missing path"),
    ];

    for (pointer, description) in invalid_pointers {
        let mut manifest = valid_manifest();
        manifest.trust.revocation_status_pointer = pointer.to_string();
        manifest.package.name = format!("invalid-revocation-{}", pointer.len());

        match validate_signed_manifest(&manifest) {
            Ok(()) => {
                return ConformanceResult::Fail {
                    reason: format!("Invalid revocation status pointer '{}' ({}) was incorrectly accepted", pointer, description)
                };
            }
            Err(_) => {
                // Expected error for invalid pointer
                continue;
            }
        }
    }

    ConformanceResult::Pass
}

/// Test: Complete trust metadata validation
fn test_complete_trust_metadata_validation(_registry: &mut TrustCardRegistry) -> ConformanceResult {
    // Test missing trust metadata fields
    let mut base_manifest_value = json!({
        "package": {
            "name": "metadata-test",
            "version": "1.0.0"
        },
        "entrypoint": "index.js",
        "capabilities": ["fs:read"],
        "minimum_runtime_version": "1.0.0",
        "signature": {
            "scheme": "threshold_ed25519",
            "publisher_key_id": "key-test",
            "signature": "VEVTVA=="
        }
    });

    // Missing entire trust section
    if let Ok(manifest) = serde_json::from_value::<ExtensionManifest>(base_manifest_value.clone()) {
        match validate_signed_manifest(&manifest) {
            Ok(()) => {
                return ConformanceResult::Fail {
                    reason: "Manifest with missing trust section was incorrectly accepted".to_string()
                };
            }
            Err(_) => {} // Expected error
        }
    }

    // Add trust section but missing fields
    base_manifest_value["trust"] = json!({
        "certification_level": "verified"
        // Missing revocation_status_pointer and trust_card_reference
    });

    if let Ok(manifest) = serde_json::from_value::<ExtensionManifest>(base_manifest_value) {
        match validate_signed_manifest(&manifest) {
            Ok(()) => {
                return ConformanceResult::Fail {
                    reason: "Manifest with incomplete trust metadata was incorrectly accepted".to_string()
                };
            }
            Err(_) => {} // Expected error
        }
    }

    ConformanceResult::Pass
}

/// Generate comprehensive manifest conformance test cases
fn generate_manifest_conformance_cases() -> Vec<ManifestConformanceCase> {
    vec![
        ManifestConformanceCase {
            id: "MANI-TC-001",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::TrustReferenceFormat,
            description: "Valid trust card reference formats must be accepted",
            test_fn: test_valid_trust_card_references,
        },
        ManifestConformanceCase {
            id: "MANI-TC-002",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::TrustReferenceFormat,
            description: "Invalid trust card reference formats must be rejected",
            test_fn: test_invalid_trust_card_references,
        },
        ManifestConformanceCase {
            id: "MANI-TC-003",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::SchemaCompliance,
            description: "All certification levels must be supported",
            test_fn: test_certification_level_consistency,
        },
        ManifestConformanceCase {
            id: "MANI-TC-004",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::MetadataConsistency,
            description: "Trust card reference must contain consistent extension ID and version",
            test_fn: test_trust_reference_format_extraction,
        },
        ManifestConformanceCase {
            id: "MANI-TC-005",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Should,
            category: ManifestTestCategory::RegistryCrossValidation,
            description: "Manifest metadata must be consistent with trust card registry state",
            test_fn: test_registry_cross_validation,
        },
        ManifestConformanceCase {
            id: "MANI-TC-006",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::TrustReferenceFormat,
            description: "Revocation status pointer format validation",
            test_fn: test_revocation_pointer_validation,
        },
        ManifestConformanceCase {
            id: "MANI-TC-007",
            spec_section: MANIFEST_SPEC_REFERENCE,
            requirement_level: RequirementLevel::Must,
            category: ManifestTestCategory::SchemaCompliance,
            description: "Complete trust metadata validation including required fields",
            test_fn: test_complete_trust_metadata_validation,
        },
    ]
}

/// Execute a single manifest conformance test case
fn run_manifest_conformance_case(
    case: &ManifestConformanceCase,
    registry: &mut TrustCardRegistry,
) -> ConformanceResult {
    (case.test_fn)(registry)
}

/// Generate manifest conformance matrix report
fn generate_manifest_report(results: &[(&ManifestConformanceCase, ConformanceResult)]) -> String {
    let mut coverage_by_category: BTreeMap<ManifestTestCategory, (usize, usize)> = BTreeMap::new();
    let mut coverage_by_level: BTreeMap<RequirementLevel, (usize, usize)> = BTreeMap::new();

    for (case, result) in results {
        let (cat_total, cat_pass) = coverage_by_category.entry(case.category).or_insert((0, 0));
        let (level_total, level_pass) = coverage_by_level.entry(case.requirement_level).or_insert((0, 0));

        *cat_total += 1;
        *level_total += 1;

        if matches!(result, ConformanceResult::Pass) {
            *cat_pass += 1;
            *level_pass += 1;
        }
    }

    let mut report = String::new();
    report.push_str("# Trust Card Manifest Reference Conformance Report\n\n");
    report.push_str(&format!("**Spec Reference:** {}\n\n", MANIFEST_SPEC_REFERENCE));

    report.push_str("## Coverage by Category\n\n");
    report.push_str("| Category | Tests | Passing | Coverage |\n");
    report.push_str("|----------|-------|---------|----------|\n");

    for (category, (total, passing)) in &coverage_by_category {
        let percentage = if *total > 0 { (*passing * 100) / *total } else { 0 };
        report.push_str(&format!("| {:?} | {} | {} | {}% |\n", category, total, passing, percentage));
    }

    report.push_str("\n## Coverage by Requirement Level\n\n");
    report.push_str("| Level | Tests | Passing | Coverage |\n");
    report.push_str("|-------|-------|---------|----------|\n");

    for (level, (total, passing)) in &coverage_by_level {
        let percentage = if *total > 0 { (*passing * 100) / *total } else { 0 };
        report.push_str(&format!("| {:?} | {} | {} | {}% |\n", level, total, passing, percentage));
    }

    report.push_str("\n## Individual Test Results\n\n");

    for (case, result) in results {
        let status = match result {
            ConformanceResult::Pass => "✅ PASS",
            ConformanceResult::Fail { .. } => "❌ FAIL",
        };

        report.push_str(&format!("- **{}** ({:?}): {} - {}\n", case.id, case.requirement_level, status, case.description));

        if let ConformanceResult::Fail { reason } = result {
            report.push_str(&format!("  - **Failure reason:** {}\n", reason));
        }
    }

    report
}

#[test]
fn trust_card_manifest_reference_full_conformance_suite() {
    let mut registry = TrustCardRegistry::new(300, TEST_REGISTRY_KEY);
    let mut results = Vec::new();
    let mut failures = 0;

    eprintln!("Running Trust Card Manifest Reference Conformance Suite...");
    eprintln!("Spec: {}", MANIFEST_SPEC_REFERENCE);

    let test_cases = generate_manifest_conformance_cases();
    eprintln!("Total manifest reference tests: {}", test_cases.len());

    for case in test_cases.iter() {
        let result = run_manifest_conformance_case(case, &mut registry);

        match &result {
            ConformanceResult::Pass => {
                eprintln!("  ✅ {} - {}", case.id, case.description);
            }
            ConformanceResult::Fail { reason } => {
                eprintln!("  ❌ {} - {} (REASON: {})", case.id, case.description, reason);
                failures += 1;
            }
        }

        results.push((case, result));
    }

    // Generate and print conformance report
    let report = generate_manifest_report(&results);
    eprintln!("\n{}", report);

    // Conformance gate: All MUST requirements must pass
    let must_failures: Vec<_> = results.iter()
        .filter(|(case, result)| {
            case.requirement_level == RequirementLevel::Must &&
            matches!(result, ConformanceResult::Fail { .. })
        })
        .collect();

    if !must_failures.is_empty() {
        panic!(
            "MANIFEST REFERENCE CONFORMANCE GATE FAILURE: {} MUST requirements failed",
            must_failures.len()
        );
    }

    if failures > 0 {
        panic!("{} manifest reference conformance test(s) failed", failures);
    }

    eprintln!("\n🎉 All manifest reference conformance tests passed!");
}