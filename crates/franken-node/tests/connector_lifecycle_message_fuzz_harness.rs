//! Structure-aware fuzzing for connector lifecycle message parsing.
//!
//! Tests frame input validation, resource limit enforcement,
//! nesting depth checks, and boundary conditions following patterns
//! established in canonical_serializer_fuzz_harness.

use frankenengine_node::connector::frame_parser::{
    FrameInput, GuardrailViolation, ParserConfig, ParserError, check_batch, check_frame,
    validate_config,
};
use libfuzzer_sys::fuzz_target;

/// Seed corpus for lifecycle message frame fuzzing.
const FRAME_SEED_CORPUS: &[FrameInput] = &[
    // Valid frames within limits
    FrameInput {
        frame_id: "valid_small".to_string(),
        raw_bytes_len: 100,
        nesting_depth: 5,
        decode_cpu_ms: 10,
    },
    FrameInput {
        frame_id: "valid_large".to_string(),
        raw_bytes_len: 50_000,
        nesting_depth: 16,
        decode_cpu_ms: 80,
    },
    // Boundary condition frames - exactly at limits
    FrameInput {
        frame_id: "at_size_limit".to_string(),
        raw_bytes_len: 1_000_000, // Default max_frame_bytes
        nesting_depth: 1,
        decode_cpu_ms: 1,
    },
    FrameInput {
        frame_id: "at_depth_limit".to_string(),
        raw_bytes_len: 100,
        nesting_depth: 32, // Default max_nesting_depth
        decode_cpu_ms: 1,
    },
    FrameInput {
        frame_id: "at_cpu_limit".to_string(),
        raw_bytes_len: 100,
        nesting_depth: 1,
        decode_cpu_ms: 100, // Default max_decode_cpu_ms
    },
    // Over-limit frames - should be rejected
    FrameInput {
        frame_id: "over_size_limit".to_string(),
        raw_bytes_len: 1_000_001, // Over max_frame_bytes
        nesting_depth: 1,
        decode_cpu_ms: 1,
    },
    FrameInput {
        frame_id: "over_depth_limit".to_string(),
        raw_bytes_len: 100,
        nesting_depth: 33, // Over max_nesting_depth
        decode_cpu_ms: 1,
    },
    FrameInput {
        frame_id: "over_cpu_limit".to_string(),
        raw_bytes_len: 100,
        nesting_depth: 1,
        decode_cpu_ms: 101, // Over max_decode_cpu_ms
    },
    // Edge case frames
    FrameInput {
        frame_id: "".to_string(), // Empty frame ID
        raw_bytes_len: 0,         // Zero bytes
        nesting_depth: 0,         // Zero depth
        decode_cpu_ms: 0,         // Zero CPU
    },
    FrameInput {
        frame_id: "max_values".to_string(),
        raw_bytes_len: u64::MAX, // Maximum u64
        nesting_depth: u32::MAX, // Maximum u32
        decode_cpu_ms: u64::MAX, // Maximum u64
    },
    // Multiple violations
    FrameInput {
        frame_id: "triple_violation".to_string(),
        raw_bytes_len: u64::MAX, // Over size limit
        nesting_depth: u32::MAX, // Over depth limit
        decode_cpu_ms: u64::MAX, // Over CPU limit
    },
];

/// Configuration seed corpus for parser config fuzzing.
const CONFIG_SEED_CORPUS: &[ParserConfig] = &[
    // Default configuration
    ParserConfig {
        max_frame_bytes: 1_000_000,
        max_nesting_depth: 32,
        max_decode_cpu_ms: 100,
    },
    // Minimal valid configuration
    ParserConfig {
        max_frame_bytes: 1,
        max_nesting_depth: 1,
        max_decode_cpu_ms: 1,
    },
    // Very permissive configuration
    ParserConfig {
        max_frame_bytes: u64::MAX,
        max_nesting_depth: u32::MAX,
        max_decode_cpu_ms: u64::MAX,
    },
    // Zero value configurations (should be invalid)
    ParserConfig {
        max_frame_bytes: 0, // Invalid
        max_nesting_depth: 32,
        max_decode_cpu_ms: 100,
    },
    ParserConfig {
        max_frame_bytes: 1_000_000,
        max_nesting_depth: 0, // Actually valid (means no depth limit)
        max_decode_cpu_ms: 100,
    },
    ParserConfig {
        max_frame_bytes: 1_000_000,
        max_nesting_depth: 32,
        max_decode_cpu_ms: 0, // Invalid
    },
];

/// Frame ID injection patterns for security testing.
const MALICIOUS_FRAME_IDS: &[&str] = &[
    // Control characters
    "frame\0id",
    "frame\nid",
    "frame\rid",
    "frame\tid",
    // Unicode edge cases
    "frame\u{FEFF}id", // BOM
    "frame\u{200B}id", // Zero-width space
    "frame\u{FFFF}id", // Non-character
    // Very long IDs
    &"x".repeat(10_000),
    &"A".repeat(100_000),
    // Path traversal attempts
    "../admin",
    "../../etc/passwd",
    "..\\windows\\system32",
    // SQL injection patterns
    "'; DROP TABLE frames; --",
    "frame' OR '1'='1",
    "frame\"; DELETE FROM logs; --",
    // Command injection
    "frame`whoami`",
    "frame$(id)",
    "frame; rm -rf /",
    // JSON injection
    "frame\": {\"admin\": true}, \"",
    "frame\",\"bypass\":true,\"dummy\":\"",
    // HTML/Script injection
    "<script>alert('xss')</script>",
    "javascript:alert('xss')",
    "%3Cscript%3Ealert('xss')%3C/script%3E",
    // Empty and whitespace variations
    "",
    " ",
    "\t",
    "\n",
    "\r\n",
    "   \t\n\r   ",
];

fuzz_target!(|data: &[u8]| {
    fuzz_connector_lifecycle_messages(data);
});

fn fuzz_connector_lifecycle_messages(data: &[u8]) {
    // Test 1: Frame input parsing with boundary conditions
    test_frame_input_boundary_conditions(data);

    // Test 2: Parser configuration validation edge cases
    test_parser_config_validation(data);

    // Test 3: Batch processing with malformed frames
    test_batch_frame_processing(data);

    // Test 4: Resource limit enforcement consistency
    test_resource_limit_enforcement(data);

    // Test 5: Frame ID security validation
    test_frame_id_security(data);
}

fn test_frame_input_boundary_conditions(data: &[u8]) {
    if data.len() < 32 {
        return; // Need enough bytes to generate meaningful frame data
    }

    // Extract frame parameters from fuzzer input
    let frame_id_len = (data[0] as usize).saturating_add(1).min(data.len() / 4);
    let frame_id = if frame_id_len <= data.len() {
        String::from_utf8_lossy(&data[0..frame_id_len]).to_string()
    } else {
        "fuzz_frame".to_string()
    };

    let raw_bytes_len = if data.len() >= 8 {
        u64::from_le_bytes([
            data[frame_id_len % data.len()],
            data[(frame_id_len + 1) % data.len()],
            data[(frame_id_len + 2) % data.len()],
            data[(frame_id_len + 3) % data.len()],
            data[(frame_id_len + 4) % data.len()],
            data[(frame_id_len + 5) % data.len()],
            data[(frame_id_len + 6) % data.len()],
            data[(frame_id_len + 7) % data.len()],
        ])
    } else {
        100
    };

    let nesting_depth = if data.len() >= 12 {
        u32::from_le_bytes([
            data[(frame_id_len + 8) % data.len()],
            data[(frame_id_len + 9) % data.len()],
            data[(frame_id_len + 10) % data.len()],
            data[(frame_id_len + 11) % data.len()],
        ])
    } else {
        5
    };

    let decode_cpu_ms = if data.len() >= 20 {
        u64::from_le_bytes([
            data[(frame_id_len + 12) % data.len()],
            data[(frame_id_len + 13) % data.len()],
            data[(frame_id_len + 14) % data.len()],
            data[(frame_id_len + 15) % data.len()],
            data[(frame_id_len + 16) % data.len()],
            data[(frame_id_len + 17) % data.len()],
            data[(frame_id_len + 18) % data.len()],
            data[(frame_id_len + 19) % data.len()],
        ])
    } else {
        10
    };

    let frame = FrameInput {
        frame_id,
        raw_bytes_len,
        nesting_depth,
        decode_cpu_ms,
    };

    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T00:00:00Z";

    // Test frame validation - should never panic
    match check_frame(&frame, &config, timestamp) {
        Ok((verdict, audit)) => {
            // Verify verdict consistency
            assert_eq!(verdict.frame_id, frame.frame_id);
            assert_eq!(verdict.allowed, verdict.violations.is_empty());
            assert_eq!(verdict.resource_usage.bytes_parsed, frame.raw_bytes_len);
            assert_eq!(verdict.resource_usage.nesting_depth, frame.nesting_depth);
            assert_eq!(verdict.resource_usage.cpu_ms, frame.decode_cpu_ms);

            // Verify audit entry consistency
            assert_eq!(audit.frame_id, frame.frame_id);
            assert_eq!(audit.size, frame.raw_bytes_len);
            assert_eq!(audit.depth, frame.nesting_depth);
            assert_eq!(audit.cpu_used, frame.decode_cpu_ms);

            // Test violation logic
            let expected_size_violation = frame.raw_bytes_len > config.max_frame_bytes;
            let expected_depth_violation = frame.nesting_depth >= config.max_nesting_depth;
            let expected_cpu_violation = frame.decode_cpu_ms >= config.max_decode_cpu_ms;

            let size_violations = verdict
                .violations
                .iter()
                .filter(|v| matches!(v, GuardrailViolation::SizeExceeded { .. }))
                .count();
            let depth_violations = verdict
                .violations
                .iter()
                .filter(|v| matches!(v, GuardrailViolation::DepthExceeded { .. }))
                .count();
            let cpu_violations = verdict
                .violations
                .iter()
                .filter(|v| matches!(v, GuardrailViolation::CpuExceeded { .. }))
                .count();

            assert_eq!(size_violations, if expected_size_violation { 1 } else { 0 });
            assert_eq!(
                depth_violations,
                if expected_depth_violation { 1 } else { 0 }
            );
            assert_eq!(cpu_violations, if expected_cpu_violation { 1 } else { 0 });
        }
        Err(error) => {
            // Error should be well-formed and have valid error code
            let error_code = error.code();
            assert!(!error_code.is_empty());
            assert!(error_code.starts_with("BPG_"));

            // Error message should be displayable
            let _ = format!("{}", error);
        }
    }
}

fn test_parser_config_validation(data: &[u8]) {
    if data.len() < 24 {
        return; // Need enough bytes for three u64 values
    }

    // Generate configuration from fuzzer data
    let max_frame_bytes = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    let max_nesting_depth = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let max_decode_cpu_ms = u64::from_le_bytes([
        data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]);

    let config = ParserConfig {
        max_frame_bytes,
        max_nesting_depth,
        max_decode_cpu_ms,
    };

    // Test configuration validation
    let validation_result = validate_config(&config);

    match validation_result {
        Ok(()) => {
            // Valid configuration - test that it accepts valid frames
            let small_frame = FrameInput {
                frame_id: "valid".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 5,
                decode_cpu_ms: 10,
            };

            let _ = check_frame(&small_frame, &config, "2026-04-20T00:00:00Z");
        }
        Err(error) => {
            // Invalid configuration - should have meaningful error
            match error {
                ParserError::InvalidConfig { reason } => {
                    assert!(!reason.is_empty());

                    // Check specific invalid condition
                    if config.max_frame_bytes == 0 {
                        assert!(reason.contains("max_frame_bytes"));
                    }
                    if config.max_decode_cpu_ms == 0 {
                        assert!(reason.contains("max_decode_cpu_ms"));
                    }
                }
                _ => {
                    panic!("validate_config should only return InvalidConfig errors");
                }
            }
        }
    }
}

fn test_batch_frame_processing(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    // Create batch of frames from fuzzer input
    let frame_count = (data[0] as usize % 10).saturating_add(1); // 1-10 frames
    let mut frames = Vec::new();

    for i in 0..frame_count {
        let offset = (i * 8) % (data.len() - 7);
        let frame_id = format!("batch_frame_{}", i);

        let raw_bytes_len = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) % 2_000_000; // Keep reasonable for batch testing

        let nesting_depth = (data[offset] as u32) % 100;
        let decode_cpu_ms = (data[offset + 1] as u64) % 200;

        frames.push(FrameInput {
            frame_id,
            raw_bytes_len,
            nesting_depth,
            decode_cpu_ms,
        });
    }

    let config = ParserConfig::default_config();
    let timestamp = "2026-04-20T00:00:00Z";

    // Test batch processing
    match check_batch(&frames, &config, timestamp) {
        Ok(results) => {
            assert_eq!(results.len(), frames.len());

            for (i, (verdict, audit)) in results.iter().enumerate() {
                let frame = &frames[i];
                assert_eq!(verdict.frame_id, frame.frame_id);
                assert_eq!(audit.frame_id, frame.frame_id);

                // Test determinism: same frame should produce same result
                if let Ok((single_verdict, single_audit)) = check_frame(frame, &config, timestamp) {
                    assert_eq!(verdict.allowed, single_verdict.allowed);
                    assert_eq!(verdict.violations.len(), single_verdict.violations.len());
                    assert_eq!(audit.verdict, single_audit.verdict);
                }
            }
        }
        Err(_) => {
            // Batch processing failed - should be due to config validation
            let validation_result = validate_config(&config);
            assert!(
                validation_result.is_err(),
                "Batch failure should correspond to config validation failure"
            );
        }
    }
}

fn test_resource_limit_enforcement(data: &[u8]) {
    // Test that resource limits are consistently enforced
    for seed_frame in FRAME_SEED_CORPUS {
        let config = ParserConfig::default_config();

        if let Ok((verdict, _)) = check_frame(seed_frame, &config, "2026-04-20T00:00:00Z") {
            // Check size limit enforcement
            if seed_frame.raw_bytes_len > config.max_frame_bytes {
                assert!(
                    verdict
                        .violations
                        .iter()
                        .any(|v| matches!(v, GuardrailViolation::SizeExceeded { .. }))
                );
                assert!(!verdict.allowed);
            } else if seed_frame.raw_bytes_len <= config.max_frame_bytes {
                assert!(
                    !verdict
                        .violations
                        .iter()
                        .any(|v| matches!(v, GuardrailViolation::SizeExceeded { .. }))
                );
            }

            // Check depth limit enforcement
            if seed_frame.nesting_depth >= config.max_nesting_depth {
                assert!(
                    verdict
                        .violations
                        .iter()
                        .any(|v| matches!(v, GuardrailViolation::DepthExceeded { .. }))
                );
                assert!(!verdict.allowed);
            }

            // Check CPU limit enforcement
            if seed_frame.decode_cpu_ms >= config.max_decode_cpu_ms {
                assert!(
                    verdict
                        .violations
                        .iter()
                        .any(|v| matches!(v, GuardrailViolation::CpuExceeded { .. }))
                );
                assert!(!verdict.allowed);
            }
        }
    }
}

fn test_frame_id_security(data: &[u8]) {
    // Test frame ID handling with malicious inputs
    if let Ok(malicious_id) = std::str::from_utf8(data) {
        if malicious_id.len() > 0 && malicious_id.len() < 10_000 {
            let frame = FrameInput {
                frame_id: malicious_id.to_string(),
                raw_bytes_len: 100,
                nesting_depth: 5,
                decode_cpu_ms: 10,
            };

            let config = ParserConfig::default_config();

            // Frame processing should never panic regardless of malicious frame ID
            if let Ok((verdict, audit)) = check_frame(&frame, &config, "2026-04-20T00:00:00Z") {
                // Frame ID should be preserved exactly (no sanitization expected)
                assert_eq!(verdict.frame_id, malicious_id);
                assert_eq!(audit.frame_id, malicious_id);

                // Verdict should be consistent regardless of frame ID content
                let clean_frame = FrameInput {
                    frame_id: "clean_frame".to_string(),
                    raw_bytes_len: frame.raw_bytes_len,
                    nesting_depth: frame.nesting_depth,
                    decode_cpu_ms: frame.decode_cpu_ms,
                };

                if let Ok((clean_verdict, _)) =
                    check_frame(&clean_frame, &config, "2026-04-20T00:00:00Z")
                {
                    // Resource-based decisions should be identical
                    assert_eq!(verdict.allowed, clean_verdict.allowed);
                    assert_eq!(verdict.violations.len(), clean_verdict.violations.len());
                }
            }
        }
    }

    // Test specific malicious patterns
    for &malicious_id in MALICIOUS_FRAME_IDS {
        let frame = FrameInput {
            frame_id: malicious_id.to_string(),
            raw_bytes_len: 100,
            nesting_depth: 5,
            decode_cpu_ms: 10,
        };

        let config = ParserConfig::default_config();
        let _ = check_frame(&frame, &config, "2026-04-20T00:00:00Z");
        // Should not panic regardless of malicious ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_seed_corpus() {
        for frame in FRAME_SEED_CORPUS {
            let config = ParserConfig::default_config();
            let _ = check_frame(frame, &config, "2026-04-20T00:00:00Z");
        }
    }

    #[test]
    fn test_config_seed_corpus() {
        for config in CONFIG_SEED_CORPUS {
            let _ = validate_config(config);
        }
    }

    #[test]
    fn test_empty_input_handling() {
        fuzz_connector_lifecycle_messages(&[]);
    }

    #[test]
    fn test_malicious_frame_ids() {
        for &malicious_id in MALICIOUS_FRAME_IDS {
            let data = malicious_id.as_bytes();
            fuzz_connector_lifecycle_messages(data);
        }
    }

    #[test]
    fn test_large_input() {
        let large_data = vec![0x42; 100_000];
        fuzz_connector_lifecycle_messages(&large_data);
    }

    #[test]
    fn test_resource_limit_boundary_conditions() {
        // Test exactly at limits
        let data = [
            0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, // 1,000,000 bytes (at limit)
            0x20, 0x00, 0x00, 0x00, // 32 depth (at limit)
            0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 100 CPU ms (at limit)
        ];
        fuzz_connector_lifecycle_messages(&data);
    }
}
