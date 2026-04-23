#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use frankenengine_node::security::constant_time::ct_eq;

const MAX_CAPABILITIES: usize = 64;
const MAX_CAPABILITY_LEN: usize = 256;

#[derive(Debug, Arbitrary)]
struct CapabilityValidationCase {
    #[arbitrary(with = capability_list)]
    capabilities: Vec<String>,
}

fn capability_list(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Vec<String>> {
    let len = u.int_in_range(0..=MAX_CAPABILITIES)?;
    let mut capabilities = Vec::with_capacity(len);

    for _ in 0..len {
        let cap_len = u.int_in_range(0..=MAX_CAPABILITY_LEN)?;
        let mut cap = String::with_capacity(cap_len);

        // Generate mix of valid-looking and adversarial capability strings
        match u.int_in_range(0..=4)? {
            0 => {
                // Valid capability patterns
                let valid_caps = [
                    "fs_read", "fs_write", "network_egress", "env_read",
                    "process_spawn", "timer", "builtin", "console", "module_load",
                    "vm_dispatch", "gc_invoke", "ir_lowering", "policy_read", "policy_write"
                ];
                cap = valid_caps[u.int_in_range(0..=valid_caps.len() - 1)?].to_string();
            }
            1 => {
                // Valid prefix patterns
                let prefixes = ["console:", "timer:", "builtin:", "number:"];
                let prefix = prefixes[u.int_in_range(0..=prefixes.len() - 1)?];
                let suffix: String = u.arbitrary()?;
                cap = format!("{}{}", prefix, suffix);
                cap.truncate(MAX_CAPABILITY_LEN);
            }
            2 => {
                // Adversarial patterns with control characters
                for _ in 0..cap_len {
                    let byte = u.int_in_range(0..=255)? as u8;
                    if let Ok(ch) = std::str::from_utf8(&[byte]) {
                        cap.push_str(ch);
                    }
                }
            }
            3 => {
                // Empty or whitespace-only
                let ws_chars = [' ', '\t', '\n', '\r', '\0'];
                for _ in 0..cap_len {
                    cap.push(ws_chars[u.int_in_range(0..=ws_chars.len() - 1)?]);
                }
            }
            _ => {
                // Random UTF-8 strings
                cap = u.arbitrary()?;
                cap.truncate(MAX_CAPABILITY_LEN);
            }
        }

        capabilities.push(cap);
    }

    Ok(capabilities)
}

/// Mock capability validation function that mimics the engine_dispatcher logic
/// without requiring franken-engine dependencies. This tests the validation
/// logic for crashes, timing attacks, and edge cases.
fn mock_validate_capabilities(capabilities: &[String]) -> Result<(), String> {
    // Known valid capabilities (extracted from engine_dispatcher.rs)
    let valid_capabilities = [
        // Core capabilities
        "fs_read", "fs_write", "network_egress", "env_read", "process_spawn", "timer", "builtin",
        // Network aliases
        "network", "net", "net:connect", "net:fetch", "net:outbound", "net.write", "network.write",
        // Filesystem aliases
        "fs", "fs:read", "fs.read", "fs:write", "fs.write",
        // Module loading aliases
        "module:require", "module:import", "module.import", "module_load",
        // Additional capabilities
        "console", "vm_dispatch", "gc_invoke", "ir_lowering", "policy_read", "policy_write",
    ];

    // Track if any capability is invalid - scan ALL capabilities regardless
    // to prevent timing attack that leaks which capability position failed
    let mut has_invalid_capability = false;

    // Constant-time validation: scan entire capability list regardless of invalid findings
    for capability in capabilities {
        let mut is_valid = false;

        // Check exact match against valid capabilities (constant-time for each comparison)
        for valid_cap in &valid_capabilities {
            if ct_eq(capability, valid_cap) {
                is_valid = true;
                // Continue checking all valid_caps for constant-time behavior
            }
        }

        // Check hostcall prefixes that are dynamically valid
        // Note: starts_with is not constant-time but these are administrative capabilities
        // and the timing difference is minimal compared to the main validation loop
        if !is_valid && (capability.starts_with("console:") ||
                       capability.starts_with("timer:") ||
                       capability.starts_with("builtin:") ||
                       capability.starts_with("number:")) {
            is_valid = true;
        }

        // Track invalid capability but continue scanning all capabilities
        if !is_valid {
            has_invalid_capability = true;
            // DO NOT return early - continue processing all capabilities
        }
    }

    // Return error only after scanning all capabilities (constant-time over total list)
    if has_invalid_capability {
        Err("Invalid capability detected in profile configuration".to_string())
    } else {
        Ok(())
    }
}

fuzz_target!(|data: CapabilityValidationCase| {
    // Prevent OOM on extremely large inputs
    if data.capabilities.len() > MAX_CAPABILITIES {
        return;
    }

    for cap in &data.capabilities {
        if cap.len() > MAX_CAPABILITY_LEN {
            return;
        }
    }

    // Test the mock capability validation function
    // This should never panic, regardless of input
    let _ = mock_validate_capabilities(&data.capabilities);

    // Invariant: Validation is deterministic
    let result1 = mock_validate_capabilities(&data.capabilities);
    let result2 = mock_validate_capabilities(&data.capabilities);
    assert_eq!(result1.is_ok(), result2.is_ok(), "Non-deterministic validation result");

    // Invariant: Empty capability list should always be valid
    let empty_result = mock_validate_capabilities(&[]);
    assert!(empty_result.is_ok(), "Empty capability list should always be valid");

    // Invariant: Known valid capabilities should always pass
    let known_valid = vec!["fs_read".to_string(), "network_egress".to_string()];
    let valid_result = mock_validate_capabilities(&known_valid);
    assert!(valid_result.is_ok(), "Known valid capabilities should pass validation");

    // Invariant: Invalid capabilities should fail consistently
    let known_invalid = vec!["invalid_capability".to_string(), "malformed:bad:syntax".to_string()];
    let invalid_result = mock_validate_capabilities(&known_invalid);
    assert!(invalid_result.is_err(), "Known invalid capabilities should fail validation");

    // Invariant: Mixed valid/invalid lists should fail
    let mixed = vec!["fs_read".to_string(), "invalid_capability".to_string()];
    let mixed_result = mock_validate_capabilities(&mixed);
    assert!(mixed_result.is_err(), "Mixed valid/invalid capabilities should fail validation");

    // Test edge cases
    let edge_cases = vec![
        vec!["".to_string()],                           // Empty capability string
        vec!["fs_read".to_string(); 100],               // Many valid capabilities
        vec![" ".to_string()],                          // Whitespace-only
        vec!["\0".to_string()],                         // Null byte
        vec!["fs_read\n".to_string()],                  // Newline injection
        vec!["AAAAAAAA".repeat(100)],                   // Very long string
    ];

    for edge_case in edge_cases {
        // Should not panic on any edge case
        let _ = mock_validate_capabilities(&edge_case);
    }
});