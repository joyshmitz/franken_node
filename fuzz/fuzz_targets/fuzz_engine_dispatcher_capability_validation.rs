#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::ops::engine_dispatcher::EngineDispatcher;
use libfuzzer_sys::fuzz_target;

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

    // Test the capability validation function
    // This should never panic, regardless of input
    let _ = EngineDispatcher::validate_capabilities_for_tests(&data.capabilities);

    // Invariant: Validation is deterministic
    let result1 = EngineDispatcher::validate_capabilities_for_tests(&data.capabilities);
    let result2 = EngineDispatcher::validate_capabilities_for_tests(&data.capabilities);
    assert_eq!(result1.is_ok(), result2.is_ok(), "Non-deterministic validation result");

    // Invariant: Empty capability list should always be valid
    let empty_result = EngineDispatcher::validate_capabilities_for_tests(&[]);
    assert!(empty_result.is_ok(), "Empty capability list should always be valid");

    // Invariant: Known valid capabilities should always pass
    let known_valid = vec!["fs_read".to_string(), "network_egress".to_string()];
    let valid_result = EngineDispatcher::validate_capabilities_for_tests(&known_valid);
    assert!(valid_result.is_ok(), "Known valid capabilities should pass validation");
});