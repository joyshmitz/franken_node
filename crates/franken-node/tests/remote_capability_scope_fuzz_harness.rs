//! Structure-aware fuzzing for remote capability scope parsing.
//!
//! Tests capability name validation, hierarchical scope parsing,
//! profile validation, and boundary conditions following patterns
//! established in canonical_serializer_fuzz_harness.

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use frankenengine_node::connector::capability_guard::{
    CapabilityName, CapabilityProfile, CapabilityGuard, RiskLevel,
    CAPABILITY_TAXONOMY, error_codes,
};

/// Seed corpus for capability scope fuzzing.
const CAPABILITY_SEED_CORPUS: &[&[u8]] = &[
    // Valid capability names from taxonomy
    b"cap:network:listen",
    b"cap:network:connect",
    b"cap:fs:read",
    b"cap:fs:write",
    b"cap:fs:temp",
    b"cap:process:spawn",
    b"cap:crypto:sign",
    b"cap:crypto:verify",
    b"cap:crypto:derive",
    b"cap:trust:read",
    b"cap:trust:write",
    b"cap:trust:revoke",

    // Boundary conditions
    b"",                           // Empty capability name
    b"cap",                        // Incomplete hierarchy
    b"cap:",                       // Missing domain and action
    b"cap:domain",                 // Missing action
    b"cap:domain:",                // Empty action
    b":domain:action",             // Missing cap prefix
    b"cap::action",                // Empty domain
    b"cap:domain:action:extra",    // Too many levels

    // Case sensitivity tests
    b"CAP:network:listen",         // Uppercase prefix
    b"cap:NETWORK:listen",         // Uppercase domain
    b"cap:network:LISTEN",         // Uppercase action
    b"Cap:Network:Listen",         // Mixed case

    // Special characters and injection attempts
    b"cap:network\0:listen",       // Null byte in domain
    b"cap:network:listen\0",       // Null byte suffix
    b"cap:network\n:listen",       // Newline in domain
    b"cap:network:listen\n",       // Newline suffix
    b"cap:network\r:listen",       // Carriage return
    b"cap:network:listen\r",       // CR suffix
    b"cap:network\t:listen",       // Tab in domain
    b"cap:network:listen\t",       // Tab suffix
    b"cap:network :listen",        // Space in domain
    b"cap:network:listen ",        // Space suffix
    b" cap:network:listen",        // Leading space

    // Unicode edge cases
    b"cap:network:\xc0\x80",       // Invalid UTF-8 (overlong encoding)
    b"cap:network:\xff\xfe",       // Invalid UTF-8 bytes
    b"cap:\xe2\x82\xac:listen",    // Euro symbol in domain
    b"cap:network:\xe2\x82\xac",   // Euro symbol in action
    b"cap:\xf0\x9f\x94\x92:listen", // Lock emoji in domain
    b"cap:network:\xf0\x9f\x94\x92", // Lock emoji in action

    // Very long capability names
    &[b'x'; 1000],                // 1KB of x's
    &[b'A'; 10000],               // 10KB of A's

    // Path traversal attempts in capability names
    b"cap:../admin:escalate",      // Path traversal in domain
    b"cap:network:../admin",       // Path traversal in action
    b"cap:../:listen",             // Path traversal as domain
    b"cap:network:..",             // Path traversal as action

    // SQL injection patterns (should be safely rejected)
    b"cap:'; DROP TABLE caps; --:listen",
    b"cap:network:'; DELETE FROM profiles; --",
    b"cap:network' OR '1'='1:listen",

    // Command injection patterns
    b"cap:network`whoami`:listen",
    b"cap:network:listen; rm -rf /",
    b"cap:network$(id):listen",

    // JSON injection attempts
    b"cap:network\":\"admin\":\"true\":listen",
    b"cap:network:listen\",\"admin\":true,\"",
];

/// Capability profile JSON seed corpus for complex validation.
const PROFILE_JSON_CORPUS: &[&str] = &[
    // Valid minimal profile
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low","capabilities":{}}"#,

    // Profile with valid capabilities
    r#"{"subsystem":"trust_fabric","version":"1.0.0","risk_level":"high","capabilities":{"cap:trust:read":"read trust","cap:trust:write":"write trust"}}"#,

    // Boundary conditions
    r#"{"subsystem":"","version":"1.0.0","risk_level":"low","capabilities":{}}"#, // Empty subsystem
    r#"{"subsystem":"test","version":"","risk_level":"low","capabilities":{}}"#,   // Empty version
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"","capabilities":{}}"#, // Empty risk level

    // Invalid risk levels
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"invalid","capabilities":{}}"#,
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"CRITICAL","capabilities":{}}"#, // Wrong case
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"super","capabilities":{}}"#,    // Non-existent level

    // Invalid JSON structures
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low""#,                // Truncated JSON
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low","capabilities""#, // Truncated capabilities
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low","capabilities":}"#, // Invalid capabilities value
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low","capabilities":[]}"#, // Array instead of object

    // JSON injection attempts
    r#"{"subsystem":"test\", \"admin\": true, \"","version":"1.0.0","risk_level":"low","capabilities":{}}"#,
    r#"{"subsystem":"test","version":"1.0.0","risk_level":"low","capabilities":{"cap:trust:read\":\"bypass"#,

    // Very large profiles
    &format!(r#"{{"subsystem":"{}","version":"1.0.0","risk_level":"low","capabilities":{{}}}}"#, "x".repeat(10000)),
];

fuzz_target!(|data: &[u8]| {
    fuzz_capability_scope_parsing(data);
});

fn fuzz_capability_scope_parsing(data: &[u8]) {
    // Test 1: Basic capability name validation with boundary conditions
    if let Ok(name_str) = std::str::from_utf8(data) {
        let capability_name = CapabilityName::new(name_str.to_string());

        // Test validation logic - should never panic
        let is_valid = capability_name.is_valid();
        let as_str = capability_name.as_str();
        let display_str = capability_name.to_string();

        // Verify consistency: as_str and display should match input
        assert_eq!(as_str, name_str);
        assert_eq!(display_str, name_str);

        // Test clone and equality
        let cloned = capability_name.clone();
        assert_eq!(capability_name, cloned);

        // Test ordering for BTreeMap compatibility
        let other_name = CapabilityName::new("cap:fs:read".to_string());
        let _ = capability_name.cmp(&other_name);

        // Test guard capability checking with boundary inputs
        test_capability_guard_boundary_conditions(&capability_name, name_str);
    }

    // Test 2: Profile parsing and validation with malformed inputs
    if data.len() > 10 && data.len() < 100_000 {
        test_profile_json_parsing(data);
    }

    // Test 3: Round-trip determinism for valid capability names
    if let Ok(valid_name) = std::str::from_utf8(data) {
        if !valid_name.is_empty() && valid_name.len() < 1000 {
            test_capability_roundtrip_determinism(valid_name);
        }
    }

    // Test 4: Hierarchical scope validation edge cases
    test_hierarchical_scope_validation(data);

    // Test 5: Capability taxonomy consistency checks
    test_capability_taxonomy_consistency(data);
}

fn test_capability_guard_boundary_conditions(capability_name: &CapabilityName, name_str: &str) {
    let mut guard = CapabilityGuard::new();

    // Create a test profile with the fuzzer capability (if valid)
    let mut profile = CapabilityProfile::new("fuzz_test", "1.0.0", RiskLevel::Low);

    // Only add capability if it's in the taxonomy (guards against injection)
    if capability_name.is_valid() {
        profile.add_capability(name_str, "fuzz test capability");

        if let Ok(()) = guard.register_profile(profile) {
            // Test capability checking with various edge cases
            let _ = guard.check_capability("fuzz_test", name_str, "2026-04-20T00:00:00Z");
            let _ = guard.check_capability("fuzz_test", "", "2026-04-20T00:00:00Z");
            let _ = guard.check_capability("", name_str, "2026-04-20T00:00:00Z");
            let _ = guard.check_capability("nonexistent", name_str, "2026-04-20T00:00:00Z");
        }
    }

    // Test with invalid capability names - should always be rejected
    let result = guard.check_capability("fuzz_test", name_str, "2026-04-20T00:00:00Z");
    if !capability_name.is_valid() {
        // Invalid capabilities should be denied
        assert!(result.is_err());
        if let Err(error) = result {
            let error_code = error.code();
            assert!(
                error_code == error_codes::ERR_CAP_DENIED ||
                error_code == error_codes::ERR_CAP_UNDECLARED ||
                error_code == error_codes::ERR_CAP_PROFILE_MISSING
            );
        }
    }
}

fn test_profile_json_parsing(data: &[u8]) {
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Test JSON deserialization boundary conditions
        let parse_result: Result<CapabilityProfile, _> = serde_json::from_str(json_str);

        // Parsing should never panic, even with malformed JSON
        match parse_result {
            Ok(profile) => {
                // If parsing succeeded, test validation
                let validation_errors = profile.validate();

                // Test profile serialization round-trip
                if let Ok(serialized) = serde_json::to_string(&profile) {
                    let _reparse_result: Result<CapabilityProfile, _> = serde_json::from_str(&serialized);
                    // Serialization of valid parsed profiles should work
                }

                // Test profile methods don't panic
                let _ = profile.subsystem();
                let _ = profile.version();
                let _ = profile.risk_level();
                let _ = profile.capability_count();

                // Test cloning
                let _cloned = profile.clone();
            }
            Err(_) => {
                // JSON parsing failed as expected for malformed input
                // This is normal and should not cause panics
            }
        }
    }
}

fn test_capability_roundtrip_determinism(name_str: &str) {
    // Test that capability operations are deterministic
    let name1 = CapabilityName::new(name_str.to_string());
    let name2 = CapabilityName::new(name_str.to_string());

    // Same input should produce identical objects
    assert_eq!(name1, name2);
    assert_eq!(name1.as_str(), name2.as_str());
    assert_eq!(name1.is_valid(), name2.is_valid());

    // Test BTreeSet insertion for deterministic ordering
    let mut set = BTreeSet::new();
    set.insert(name1.clone());
    set.insert(name2);
    assert_eq!(set.len(), 1); // Duplicates should be deduplicated
}

fn test_hierarchical_scope_validation(data: &[u8]) {
    if let Ok(scope_str) = std::str::from_utf8(data) {
        if scope_str.len() > 0 && scope_str.len() < 500 {
            // Test hierarchical parsing logic
            let parts: Vec<&str> = scope_str.split(':').collect();

            // Test expected hierarchy: cap:domain:action
            match parts.len() {
                0 => {
                    // Empty scope - should be invalid
                    let name = CapabilityName::new(scope_str.to_string());
                    assert!(!name.is_valid());
                }
                1 => {
                    // Single part - should be invalid unless exact match
                    let name = CapabilityName::new(scope_str.to_string());
                    if scope_str != "cap" {
                        assert!(!name.is_valid());
                    }
                }
                2 => {
                    // Two parts - should be invalid (missing action)
                    let name = CapabilityName::new(scope_str.to_string());
                    assert!(!name.is_valid());
                }
                3 => {
                    // Three parts - check if it matches taxonomy
                    let name = CapabilityName::new(scope_str.to_string());
                    let validity = name.is_valid();

                    // Check against known taxonomy
                    let expected_valid = CAPABILITY_TAXONOMY.iter().any(|entry| entry.name == scope_str);
                    assert_eq!(validity, expected_valid);
                }
                _ => {
                    // More than three parts - should be invalid
                    let name = CapabilityName::new(scope_str.to_string());
                    assert!(!name.is_valid());
                }
            }
        }
    }
}

fn test_capability_taxonomy_consistency(data: &[u8]) {
    // Test that taxonomy validation is consistent
    for entry in CAPABILITY_TAXONOMY {
        let name = CapabilityName::new(entry.name.to_string());
        assert!(name.is_valid(), "Taxonomy entry '{}' should be valid", entry.name);

        // Test that all taxonomy entries are well-formed
        let parts: Vec<&str> = entry.name.split(':').collect();
        assert_eq!(parts.len(), 3, "Taxonomy entry '{}' should have exactly 3 parts", entry.name);
        assert_eq!(parts[0], "cap", "Taxonomy entry '{}' should start with 'cap'", entry.name);
        assert!(!parts[1].is_empty(), "Taxonomy entry '{}' should have non-empty domain", entry.name);
        assert!(!parts[2].is_empty(), "Taxonomy entry '{}' should have non-empty action", entry.name);
    }

    // Test with fuzzer data as potential new capability names
    if let Ok(fuzz_name) = std::str::from_utf8(data) {
        if fuzz_name.len() > 0 && fuzz_name.len() < 200 {
            let name = CapabilityName::new(fuzz_name.to_string());
            let is_valid = name.is_valid();

            // If fuzzer input is marked as valid, it must be in taxonomy
            if is_valid {
                assert!(
                    CAPABILITY_TAXONOMY.iter().any(|entry| entry.name == fuzz_name),
                    "Valid capability '{}' must be in taxonomy", fuzz_name
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_corpus_coverage() {
        // Test that our seed corpus covers key boundary conditions
        for &seed in CAPABILITY_SEED_CORPUS {
            fuzz_capability_scope_parsing(seed);
        }
    }

    #[test]
    fn test_profile_json_corpus() {
        for &json_str in PROFILE_JSON_CORPUS {
            fuzz_capability_scope_parsing(json_str.as_bytes());
        }
    }

    #[test]
    fn test_empty_input_handling() {
        fuzz_capability_scope_parsing(&[]);
    }

    #[test]
    fn test_large_input_handling() {
        let large_input = vec![b'x'; 100_000];
        fuzz_capability_scope_parsing(&large_input);
    }

    #[test]
    fn test_binary_input_handling() {
        let binary_input: &[u8] = &[0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
        fuzz_capability_scope_parsing(binary_input);
    }

    #[test]
    fn test_capability_taxonomy_validation() {
        // Verify all taxonomy entries pass validation
        for entry in CAPABILITY_TAXONOMY {
            let name = CapabilityName::new(entry.name.to_string());
            assert!(name.is_valid(), "Taxonomy entry should be valid: {}", entry.name);
        }
    }
}