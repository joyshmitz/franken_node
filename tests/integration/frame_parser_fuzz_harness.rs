//! Comprehensive fuzz testing harness for frame parser security
//!
//! Tests decode-DoS resistance, resource limit enforcement, and edge cases
//! in the bounded frame parser to ensure robust defense against malicious
//! control-channel frame inputs.

#[cfg(test)]
mod frame_parser_fuzz_tests {
    // Mock types for testing (in real implementation, import from the actual module)

    #[derive(Debug, Clone)]
    pub struct ParserConfig {
        pub max_frame_bytes: u64,
        pub max_nesting_depth: u32,
        pub max_decode_cpu_ms: u64,
    }

    impl ParserConfig {
        pub fn default_config() -> Self {
            Self {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 100,
            }
        }

        pub fn strict_config() -> Self {
            Self {
                max_frame_bytes: 1024,
                max_nesting_depth: 8,
                max_decode_cpu_ms: 10,
            }
        }

        pub fn permissive_config() -> Self {
            Self {
                max_frame_bytes: 100_000_000,
                max_nesting_depth: 1000,
                max_decode_cpu_ms: 10000,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct FrameInput {
        pub frame_id: String,
        pub raw_bytes_len: u64,
        pub nesting_depth: u32,
        pub decode_cpu_ms: u64,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum GuardrailViolation {
        SizeExceeded { actual: u64, limit: u64 },
        DepthExceeded { actual: u32, limit: u32 },
        CpuExceeded { actual: u64, limit: u64 },
        MalformedFrame { reason: String },
    }

    #[derive(Debug, Clone)]
    pub struct DecodeVerdict {
        pub frame_id: String,
        pub allowed: bool,
        pub violations: Vec<GuardrailViolation>,
        pub resource_usage: ResourceUsage,
    }

    #[derive(Debug, Clone)]
    pub struct ResourceUsage {
        pub bytes_parsed: u64,
        pub nesting_depth: u32,
        pub cpu_ms: u64,
    }

    #[derive(Debug, Clone)]
    pub struct DecodeAuditEntry {
        pub frame_id: String,
        pub size: u64,
        pub depth: u32,
        pub cpu_used: u64,
        pub size_limit: u64,
        pub depth_limit: u32,
        pub cpu_limit: u64,
        pub verdict: String,
        pub timestamp: String,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ParserError {
        SizeExceeded { frame_id: String, actual: u64, limit: u64 },
        DepthExceeded { frame_id: String, actual: u32, limit: u32 },
        CpuExceeded { frame_id: String, actual: u64, limit: u64 },
        InvalidConfig { reason: String },
        MalformedFrame { frame_id: String, reason: String },
    }

    impl ParserError {
        pub fn code(&self) -> &'static str {
            match self {
                Self::SizeExceeded { .. } => "BPG_SIZE_EXCEEDED",
                Self::DepthExceeded { .. } => "BPG_DEPTH_EXCEEDED",
                Self::CpuExceeded { .. } => "BPG_CPU_EXCEEDED",
                Self::InvalidConfig { .. } => "BPG_INVALID_CONFIG",
                Self::MalformedFrame { .. } => "BPG_MALFORMED_FRAME",
            }
        }
    }

    pub fn validate_config(config: &ParserConfig) -> Result<(), ParserError> {
        if config.max_frame_bytes == 0 {
            return Err(ParserError::InvalidConfig {
                reason: "max_frame_bytes must be > 0".into(),
            });
        }
        if config.max_nesting_depth == 0 {
            return Err(ParserError::InvalidConfig {
                reason: "max_nesting_depth must be > 0".into(),
            });
        }
        if config.max_decode_cpu_ms == 0 {
            return Err(ParserError::InvalidConfig {
                reason: "max_decode_cpu_ms must be > 0".into(),
            });
        }
        Ok(())
    }

    pub fn check_frame(
        frame: &FrameInput,
        config: &ParserConfig,
        timestamp: &str,
    ) -> Result<(DecodeVerdict, DecodeAuditEntry), ParserError> {
        validate_config(config)?;

        if frame.frame_id.is_empty() {
            return Err(ParserError::MalformedFrame {
                frame_id: "(empty)".into(),
                reason: "frame_id must not be empty".into(),
            });
        }

        let mut violations = Vec::new();

        // Check 1: size
        if frame.raw_bytes_len >= config.max_frame_bytes {
            violations.push(GuardrailViolation::SizeExceeded {
                actual: frame.raw_bytes_len,
                limit: config.max_frame_bytes,
            });
        }

        // Check 2: nesting depth
        if frame.nesting_depth >= config.max_nesting_depth {
            violations.push(GuardrailViolation::DepthExceeded {
                actual: frame.nesting_depth,
                limit: config.max_nesting_depth,
            });
        }

        // Check 3: CPU budget
        if frame.decode_cpu_ms >= config.max_decode_cpu_ms {
            violations.push(GuardrailViolation::CpuExceeded {
                actual: frame.decode_cpu_ms,
                limit: config.max_decode_cpu_ms,
            });
        }

        let allowed = violations.is_empty();

        let verdict = DecodeVerdict {
            frame_id: frame.frame_id.clone(),
            allowed,
            violations,
            resource_usage: ResourceUsage {
                bytes_parsed: frame.raw_bytes_len,
                nesting_depth: frame.nesting_depth,
                cpu_ms: frame.decode_cpu_ms,
            },
        };

        let audit = DecodeAuditEntry {
            frame_id: frame.frame_id.clone(),
            size: frame.raw_bytes_len,
            depth: frame.nesting_depth,
            cpu_used: frame.decode_cpu_ms,
            size_limit: config.max_frame_bytes,
            depth_limit: config.max_nesting_depth,
            cpu_limit: config.max_decode_cpu_ms,
            verdict: if allowed {
                "ALLOW".to_string()
            } else {
                "BLOCK".to_string()
            },
            timestamp: timestamp.to_string(),
        };

        Ok((verdict, audit))
    }

    // Fuzz test generators
    fn generate_malicious_frames() -> Vec<FrameInput> {
        vec![
            // Massive size attacks
            FrameInput {
                frame_id: "size_bomb_1".to_string(),
                raw_bytes_len: u64::MAX,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "size_bomb_2".to_string(),
                raw_bytes_len: 1_000_000_000_000, // 1TB
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            // Nesting depth attacks
            FrameInput {
                frame_id: "depth_bomb_1".to_string(),
                raw_bytes_len: 100,
                nesting_depth: u32::MAX,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "depth_bomb_2".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1_000_000,
                decode_cpu_ms: 1,
            },
            // CPU exhaustion attacks
            FrameInput {
                frame_id: "cpu_bomb_1".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: u64::MAX,
            },
            FrameInput {
                frame_id: "cpu_bomb_2".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 3_600_000, // 1 hour
            },
            // Combined attacks
            FrameInput {
                frame_id: "triple_bomb".to_string(),
                raw_bytes_len: u64::MAX,
                nesting_depth: u32::MAX,
                decode_cpu_ms: u64::MAX,
            },
            // Boundary value attacks
            FrameInput {
                frame_id: "boundary_size".to_string(),
                raw_bytes_len: 1_000_000 - 1, // Just under default limit
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "boundary_depth".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 32 - 1, // Just under default limit
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "boundary_cpu".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 100 - 1, // Just under default limit
            },
            // Zero/minimal values
            FrameInput {
                frame_id: "zero_size".to_string(),
                raw_bytes_len: 0,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "zero_depth".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 0,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "zero_cpu".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 0,
            },
            // Empty frame ID (should be caught as malformed)
            FrameInput {
                frame_id: "".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            // Special character attacks in frame ID
            FrameInput {
                frame_id: "../../etc/passwd".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "<script>alert('xss')</script>".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "\0\x01\x02\xFF".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            // Very long frame ID
            FrameInput {
                frame_id: "A".repeat(10000),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
        ]
    }

    fn generate_malicious_configs() -> Vec<ParserConfig> {
        vec![
            // Zero limits (invalid)
            ParserConfig {
                max_frame_bytes: 0,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 100,
            },
            ParserConfig {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 0,
                max_decode_cpu_ms: 100,
            },
            ParserConfig {
                max_frame_bytes: 1_000_000,
                max_nesting_depth: 32,
                max_decode_cpu_ms: 0,
            },
            // All zeros
            ParserConfig {
                max_frame_bytes: 0,
                max_nesting_depth: 0,
                max_decode_cpu_ms: 0,
            },
            // Extreme values
            ParserConfig {
                max_frame_bytes: u64::MAX,
                max_nesting_depth: u32::MAX,
                max_decode_cpu_ms: u64::MAX,
            },
            // Very small limits
            ParserConfig {
                max_frame_bytes: 1,
                max_nesting_depth: 1,
                max_decode_cpu_ms: 1,
            },
            // Asymmetric limits
            ParserConfig {
                max_frame_bytes: 1,
                max_nesting_depth: 1000,
                max_decode_cpu_ms: 10000,
            },
            ParserConfig {
                max_frame_bytes: 100_000_000,
                max_nesting_depth: 1,
                max_decode_cpu_ms: 1,
            },
        ]
    }

    #[test]
    fn test_fuzz_resource_limit_enforcement() {
        let config = ParserConfig::default_config();
        let malicious_frames = generate_malicious_frames();
        let timestamp = "2026-04-17T05:55:00Z";

        for frame in malicious_frames {
            let result = check_frame(&frame, &config, timestamp);

            match result {
                Ok((verdict, audit)) => {
                    // Verify audit trail is complete
                    assert_eq!(audit.frame_id, frame.frame_id);
                    assert_eq!(audit.size, frame.raw_bytes_len);
                    assert_eq!(audit.depth, frame.nesting_depth);
                    assert_eq!(audit.cpu_used, frame.decode_cpu_ms);
                    assert_eq!(audit.timestamp, timestamp);

                    // Verify verdict consistency
                    assert_eq!(verdict.allowed, verdict.violations.is_empty());
                    assert_eq!(verdict.frame_id, frame.frame_id);

                    // Check specific violations for extreme values
                    if frame.raw_bytes_len >= config.max_frame_bytes {
                        assert!(verdict.violations.iter().any(|v| matches!(v,
                            GuardrailViolation::SizeExceeded { actual, limit }
                            if *actual == frame.raw_bytes_len && *limit == config.max_frame_bytes
                        )), "Size violation not detected for frame {}", frame.frame_id);
                        assert!(!verdict.allowed);
                        assert_eq!(audit.verdict, "BLOCK");
                    }

                    if frame.nesting_depth >= config.max_nesting_depth {
                        assert!(verdict.violations.iter().any(|v| matches!(v,
                            GuardrailViolation::DepthExceeded { actual, limit }
                            if *actual == frame.nesting_depth && *limit == config.max_nesting_depth
                        )), "Depth violation not detected for frame {}", frame.frame_id);
                        assert!(!verdict.allowed);
                        assert_eq!(audit.verdict, "BLOCK");
                    }

                    if frame.decode_cpu_ms >= config.max_decode_cpu_ms {
                        assert!(verdict.violations.iter().any(|v| matches!(v,
                            GuardrailViolation::CpuExceeded { actual, limit }
                            if *actual == frame.decode_cpu_ms && *limit == config.max_decode_cpu_ms
                        )), "CPU violation not detected for frame {}", frame.frame_id);
                        assert!(!verdict.allowed);
                        assert_eq!(audit.verdict, "BLOCK");
                    }

                    // Verify resource usage tracking
                    assert_eq!(verdict.resource_usage.bytes_parsed, frame.raw_bytes_len);
                    assert_eq!(verdict.resource_usage.nesting_depth, frame.nesting_depth);
                    assert_eq!(verdict.resource_usage.cpu_ms, frame.decode_cpu_ms);
                },
                Err(ParserError::MalformedFrame { frame_id, reason }) => {
                    // Empty frame ID should be caught as malformed
                    if frame.frame_id.is_empty() {
                        assert_eq!(frame_id, "(empty)");
                        assert!(reason.contains("frame_id must not be empty"));
                    } else {
                        panic!("Unexpected malformed frame error for {}: {}", frame_id, reason);
                    }
                },
                Err(e) => {
                    panic!("Unexpected error for frame {}: {:?}", frame.frame_id, e);
                }
            }
        }
    }

    #[test]
    fn test_fuzz_config_validation() {
        let malicious_configs = generate_malicious_configs();
        let good_frame = FrameInput {
            frame_id: "test".to_string(),
            raw_bytes_len: 100,
            nesting_depth: 1,
            decode_cpu_ms: 1,
        };
        let timestamp = "2026-04-17T05:55:00Z";

        for config in malicious_configs {
            let result = check_frame(&good_frame, &config, timestamp);

            match result {
                Ok(_) => {
                    // Config passed validation - verify it's actually valid
                    assert!(config.max_frame_bytes > 0);
                    assert!(config.max_nesting_depth > 0);
                    assert!(config.max_decode_cpu_ms > 0);
                },
                Err(ParserError::InvalidConfig { reason }) => {
                    // Verify the error reason matches the invalid field
                    if config.max_frame_bytes == 0 {
                        assert!(reason.contains("max_frame_bytes"));
                    } else if config.max_nesting_depth == 0 {
                        assert!(reason.contains("max_nesting_depth"));
                    } else if config.max_decode_cpu_ms == 0 {
                        assert!(reason.contains("max_decode_cpu_ms"));
                    } else {
                        panic!("Invalid config error but no zero fields: {:?}", config);
                    }
                },
                Err(e) => {
                    panic!("Unexpected error for config {:?}: {:?}", config, e);
                }
            }
        }
    }

    #[test]
    fn test_fuzz_boundary_value_precision() {
        let configs = vec![
            ParserConfig::strict_config(),
            ParserConfig::default_config(),
            ParserConfig::permissive_config(),
        ];

        for config in configs {
            let timestamp = "2026-04-17T05:55:00Z";

            // Test exact boundary values
            let boundary_frames = vec![
                // Exactly at limit (should be blocked - uses >= comparison)
                FrameInput {
                    frame_id: "at_size_limit".to_string(),
                    raw_bytes_len: config.max_frame_bytes,
                    nesting_depth: 1,
                    decode_cpu_ms: 1,
                },
                FrameInput {
                    frame_id: "at_depth_limit".to_string(),
                    raw_bytes_len: 100,
                    nesting_depth: config.max_nesting_depth,
                    decode_cpu_ms: 1,
                },
                FrameInput {
                    frame_id: "at_cpu_limit".to_string(),
                    raw_bytes_len: 100,
                    nesting_depth: 1,
                    decode_cpu_ms: config.max_decode_cpu_ms,
                },
                // Just below limit (should be allowed)
                FrameInput {
                    frame_id: "below_size_limit".to_string(),
                    raw_bytes_len: config.max_frame_bytes - 1,
                    nesting_depth: 1,
                    decode_cpu_ms: 1,
                },
                FrameInput {
                    frame_id: "below_depth_limit".to_string(),
                    raw_bytes_len: 100,
                    nesting_depth: config.max_nesting_depth - 1,
                    decode_cpu_ms: 1,
                },
                FrameInput {
                    frame_id: "below_cpu_limit".to_string(),
                    raw_bytes_len: 100,
                    nesting_depth: 1,
                    decode_cpu_ms: config.max_decode_cpu_ms - 1,
                },
            ];

            for frame in boundary_frames {
                let result = check_frame(&frame, &config, timestamp);
                assert!(result.is_ok(), "Frame check failed for {}: {:?}", frame.frame_id, result);

                let (verdict, _audit) = result.unwrap();

                if frame.frame_id.starts_with("at_") {
                    // At limit should be blocked
                    assert!(!verdict.allowed, "Frame {} should be blocked (at limit)", frame.frame_id);
                    assert!(!verdict.violations.is_empty(), "Frame {} should have violations", frame.frame_id);
                } else if frame.frame_id.starts_with("below_") {
                    // Below limit should be allowed
                    assert!(verdict.allowed, "Frame {} should be allowed (below limit)", frame.frame_id);
                    assert!(verdict.violations.is_empty(), "Frame {} should have no violations", frame.frame_id);
                }
            }
        }
    }

    #[test]
    fn test_fuzz_error_code_consistency() {
        let config = ParserConfig::default_config();
        let timestamp = "2026-04-17T05:55:00Z";

        let test_cases = vec![
            (
                FrameInput {
                    frame_id: "".to_string(),
                    raw_bytes_len: 100,
                    nesting_depth: 1,
                    decode_cpu_ms: 1,
                },
                "BPG_MALFORMED_FRAME",
            ),
        ];

        for (frame, expected_code) in test_cases {
            let result = check_frame(&frame, &config, timestamp);

            match result {
                Err(error) => {
                    assert_eq!(error.code(), expected_code);
                },
                Ok(_) => {
                    panic!("Expected error for frame {}, but got success", frame.frame_id);
                }
            }
        }
    }

    #[test]
    fn test_fuzz_concurrent_processing_simulation() {
        let config = ParserConfig::default_config();
        let timestamp = "2026-04-17T05:55:00Z";

        // Simulate rapid successive frame processing
        let frames: Vec<FrameInput> = (0..1000).map(|i| {
            FrameInput {
                frame_id: format!("concurrent_frame_{}", i),
                raw_bytes_len: (i % 100) as u64 + 1,
                nesting_depth: (i % 10) as u32 + 1,
                decode_cpu_ms: (i % 5) as u64 + 1,
            }
        }).collect();

        for frame in frames {
            let result = check_frame(&frame, &config, timestamp);

            // All frames should process successfully (within limits)
            assert!(result.is_ok(), "Frame {} failed: {:?}", frame.frame_id, result);

            let (verdict, audit) = result.unwrap();

            // Verify audit integrity
            assert_eq!(audit.frame_id, frame.frame_id);
            assert_eq!(audit.size, frame.raw_bytes_len);

            // Verify verdict consistency
            assert_eq!(verdict.frame_id, frame.frame_id);
            assert_eq!(verdict.allowed, verdict.violations.is_empty());

            // These small frames should all be allowed
            assert!(verdict.allowed, "Frame {} should be allowed", frame.frame_id);
        }
    }

    #[test]
    fn test_fuzz_memory_efficiency() {
        let config = ParserConfig::default_config();
        let timestamp = "2026-04-17T05:55:00Z";

        // Test with progressively larger frame IDs to check memory handling
        for size_exp in 0..20 {
            let id_size = 1 << size_exp;
            let frame = FrameInput {
                frame_id: "X".repeat(id_size),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            };

            let result = check_frame(&frame, &config, timestamp);

            // Should handle large frame IDs gracefully
            assert!(result.is_ok(), "Failed to handle frame ID of size {}: {:?}", id_size, result);

            let (verdict, audit) = result.unwrap();

            // Verify the frame ID is preserved correctly
            assert_eq!(verdict.frame_id, frame.frame_id);
            assert_eq!(audit.frame_id, frame.frame_id);

            // Should be allowed (within resource limits)
            assert!(verdict.allowed);
        }
    }

    #[test]
    fn test_fuzz_integer_overflow_protection() {
        let config = ParserConfig {
            max_frame_bytes: u64::MAX - 1,
            max_nesting_depth: u32::MAX - 1,
            max_decode_cpu_ms: u64::MAX - 1,
        };
        let timestamp = "2026-04-17T05:55:00Z";

        let overflow_frames = vec![
            FrameInput {
                frame_id: "overflow_size".to_string(),
                raw_bytes_len: u64::MAX,
                nesting_depth: 1,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "overflow_depth".to_string(),
                raw_bytes_len: 100,
                nesting_depth: u32::MAX,
                decode_cpu_ms: 1,
            },
            FrameInput {
                frame_id: "overflow_cpu".to_string(),
                raw_bytes_len: 100,
                nesting_depth: 1,
                decode_cpu_ms: u64::MAX,
            },
        ];

        for frame in overflow_frames {
            let result = check_frame(&frame, &config, timestamp);

            // Should handle max values without panicking
            assert!(result.is_ok(), "Failed to handle max values for {}: {:?}", frame.frame_id, result);

            let (verdict, _audit) = result.unwrap();

            // Max values should exceed limits and be blocked
            assert!(!verdict.allowed, "Frame {} with max values should be blocked", frame.frame_id);
            assert!(!verdict.violations.is_empty());
        }
    }
}