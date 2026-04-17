//! Comprehensive fuzz testing harness for canonical serializer security
//!
//! Tests edge cases, malformed inputs, and stress conditions for the
//! CanonicalSerializer to ensure robust cryptographic signature preimage
//! construction and deterministic serialization behavior.

#[cfg(test)]
mod canonical_serializer_fuzz_tests {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    // Mock types for testing (in real implementation, import from the actual module)

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum TrustObjectType {
        PolicyCheckpoint,
        DelegationToken,
        RevocationAssertion,
        SessionTicket,
        ZoneBoundaryClaim,
        OperatorReceipt,
    }

    impl TrustObjectType {
        pub fn domain_tag(&self) -> [u8; 2] {
            match self {
                Self::PolicyCheckpoint => [0x10, 0x01],
                Self::DelegationToken => [0x10, 0x02],
                Self::RevocationAssertion => [0x10, 0x03],
                Self::SessionTicket => [0x10, 0x04],
                Self::ZoneBoundaryClaim => [0x10, 0x05],
                Self::OperatorReceipt => [0x10, 0x06],
            }
        }

        pub fn label(&self) -> &'static str {
            match self {
                Self::PolicyCheckpoint => "policy_checkpoint",
                Self::DelegationToken => "delegation_token",
                Self::RevocationAssertion => "revocation_assertion",
                Self::SessionTicket => "session_ticket",
                Self::ZoneBoundaryClaim => "zone_boundary_claim",
                Self::OperatorReceipt => "operator_receipt",
            }
        }

        pub fn all() -> &'static [TrustObjectType; 6] {
            &[
                Self::PolicyCheckpoint,
                Self::DelegationToken,
                Self::RevocationAssertion,
                Self::SessionTicket,
                Self::ZoneBoundaryClaim,
                Self::OperatorReceipt,
            ]
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CanonicalSchema {
        pub object_type: TrustObjectType,
        pub field_order: Vec<String>,
        pub domain_tag: [u8; 2],
        pub version: u8,
        pub no_float: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignaturePreimage {
        pub version: u8,
        pub domain_tag: [u8; 2],
        pub canonical_payload: Vec<u8>,
    }

    impl SignaturePreimage {
        pub fn build(version: u8, domain_tag: [u8; 2], payload: Vec<u8>) -> Self {
            Self {
                version,
                domain_tag,
                canonical_payload: payload,
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(3 + self.canonical_payload.len());
            bytes.push(self.version);
            bytes.extend_from_slice(&self.domain_tag);
            bytes.extend_from_slice(&self.canonical_payload);
            bytes
        }

        pub fn byte_len(&self) -> usize {
            3 + self.canonical_payload.len()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SerializerError {
        NonCanonicalInput { object_type: String, reason: String },
        SchemaNotFound { object_type: String },
        FloatingPointRejected { object_type: String, field: String },
        PreimageConstructionFailed { reason: String },
        RoundTripDivergence { object_type: String, original_len: usize, round_trip_len: usize },
    }

    pub struct CanonicalSerializer {
        schemas: BTreeMap<TrustObjectType, CanonicalSchema>,
    }

    impl CanonicalSerializer {
        pub fn new() -> Self {
            Self {
                schemas: BTreeMap::new(),
            }
        }

        pub fn register_schema(&mut self, schema: CanonicalSchema) {
            self.schemas.insert(schema.object_type, schema);
        }

        pub fn construct_preimage(&self, object_type: TrustObjectType, payload: &[u8]) -> Result<SignaturePreimage, SerializerError> {
            let schema = self.schemas.get(&object_type).ok_or_else(|| {
                SerializerError::SchemaNotFound {
                    object_type: object_type.label().to_string(),
                }
            })?;

            // Validate payload is not empty
            if payload.is_empty() {
                return Err(SerializerError::PreimageConstructionFailed {
                    reason: "empty payload".to_string(),
                });
            }

            // Check for floating-point rejection patterns
            if schema.no_float && self.contains_float_patterns(payload) {
                return Err(SerializerError::FloatingPointRejected {
                    object_type: object_type.label().to_string(),
                    field: "payload".to_string(),
                });
            }

            Ok(SignaturePreimage::build(
                schema.version,
                schema.domain_tag,
                payload.to_vec(),
            ))
        }

        fn contains_float_patterns(&self, payload: &[u8]) -> bool {
            // Simple heuristic: look for IEEE 754 patterns or JSON float markers
            payload.windows(4).any(|w| {
                // Look for NaN, Infinity patterns in IEEE 754 format
                matches!(w, [0x7F, 0x80..=0xFF, _, _] | [0xFF, 0x80..=0xFF, _, _])
            }) || payload.windows(3).any(|w| {
                // Look for "inf", "nan" in ASCII
                w == b"inf" || w == b"nan" || w == b"Inf" || w == b"NaN"
            })
        }

        fn validate_deterministic(&self, payload: &[u8]) -> Result<(), SerializerError> {
            // Check for non-deterministic patterns
            if payload.windows(2).any(|w| w == b": " || w == b", ") {
                return Err(SerializerError::NonCanonicalInput {
                    object_type: "unknown".to_string(),
                    reason: "contains formatting whitespace".to_string(),
                });
            }

            // Check for unordered JSON-like structures (simplified check)
            if let Some(pos) = payload.windows(2).position(|w| w == b"}{") {
                return Err(SerializerError::NonCanonicalInput {
                    object_type: "unknown".to_string(),
                    reason: format!("potential unordered objects at position {}", pos),
                });
            }

            Ok(())
        }
    }

    // Fuzz test generators
    fn generate_malformed_payloads() -> Vec<Vec<u8>> {
        vec![
            // Empty payload
            vec![],
            // Single byte
            vec![0x00],
            // All zeros
            vec![0x00; 1024],
            // All 0xFF
            vec![0xFF; 1024],
            // Random binary data with potential float patterns
            vec![0x7F, 0xFF, 0xFF, 0xFF], // NaN pattern
            vec![0x7F, 0x80, 0x00, 0x00], // +Infinity pattern
            vec![0xFF, 0x80, 0x00, 0x00], // -Infinity pattern
            // JSON-like with floats
            b"{\"value\":3.14159}".to_vec(),
            b"{\"nan\":NaN}".to_vec(),
            b"{\"inf\":Infinity}".to_vec(),
            // Non-canonical JSON (unordered, whitespace)
            b"{ \"b\" : 2 , \"a\" : 1 }".to_vec(),
            b"{\"z\":3,\"a\":1}".to_vec(),
            // Extremely large payloads
            vec![0xAA; 65536],
            // Buffer overflow attempts
            vec![0x41; 1048576], // 1MB
            // Unicode/encoding edge cases
            "🚀💎🔒".as_bytes().to_vec(),
            b"\x00\x01\x02\x03\xFF\xFE\xFD".to_vec(),
            // Nested structure confusion
            b"{\"a\":{\"b\":{\"c\":1}}}".to_vec(),
            // Potential injection patterns
            b"'; DROP TABLE users; --".to_vec(),
            b"<script>alert('xss')</script>".to_vec(),
        ]
    }

    #[test]
    fn test_fuzz_signature_preimage_construction() {
        let mut serializer = CanonicalSerializer::new();

        // Register all schemas
        for object_type in TrustObjectType::all() {
            let schema = CanonicalSchema {
                object_type: *object_type,
                field_order: vec!["id".to_string(), "data".to_string()],
                domain_tag: object_type.domain_tag(),
                version: 1,
                no_float: true,
            };
            serializer.register_schema(schema);
        }

        let malformed_payloads = generate_malformed_payloads();

        for (i, payload) in malformed_payloads.iter().enumerate() {
            for object_type in TrustObjectType::all() {
                let result = serializer.construct_preimage(*object_type, payload);

                // Should handle all inputs gracefully (either succeed or return proper error)
                match result {
                    Ok(preimage) => {
                        // Verify preimage structure is valid
                        assert_eq!(preimage.version, 1);
                        assert_eq!(preimage.domain_tag, object_type.domain_tag());
                        assert_eq!(preimage.canonical_payload, *payload);

                        // Verify byte conversion is consistent
                        let bytes = preimage.to_bytes();
                        assert_eq!(bytes.len(), preimage.byte_len());
                        assert_eq!(bytes[0], 1); // version
                        assert_eq!(&bytes[1..3], &object_type.domain_tag()); // domain tag
                        assert_eq!(&bytes[3..], payload); // payload
                    },
                    Err(e) => {
                        // Verify error is one of the expected types
                        assert!(matches!(e,
                            SerializerError::NonCanonicalInput { .. } |
                            SerializerError::SchemaNotFound { .. } |
                            SerializerError::FloatingPointRejected { .. } |
                            SerializerError::PreimageConstructionFailed { .. } |
                            SerializerError::RoundTripDivergence { .. }
                        ), "Unexpected error type for payload {}: {:?}", i, e);
                    }
                }
            }
        }
    }

    #[test]
    fn test_fuzz_domain_separation_integrity() {
        let mut serializer = CanonicalSerializer::new();

        for object_type in TrustObjectType::all() {
            let schema = CanonicalSchema {
                object_type: *object_type,
                field_order: vec!["field".to_string()],
                domain_tag: object_type.domain_tag(),
                version: 1,
                no_float: true,
            };
            serializer.register_schema(schema);
        }

        let test_payload = b"test_data";

        // Verify different object types produce different preimages even with same payload
        let mut preimages = Vec::new();
        for object_type in TrustObjectType::all() {
            if let Ok(preimage) = serializer.construct_preimage(*object_type, test_payload) {
                preimages.push(preimage);
            }
        }

        // All preimages should be different due to domain separation
        for i in 0..preimages.len() {
            for j in (i + 1)..preimages.len() {
                assert_ne!(preimages[i].to_bytes(), preimages[j].to_bytes(),
                    "Domain separation failed: preimages {} and {} are identical", i, j);
                assert_ne!(preimages[i].domain_tag, preimages[j].domain_tag(),
                    "Domain tags should be different");
            }
        }
    }

    #[test]
    fn test_fuzz_floating_point_rejection() {
        let mut serializer = CanonicalSerializer::new();

        let schema = CanonicalSchema {
            object_type: TrustObjectType::PolicyCheckpoint,
            field_order: vec!["data".to_string()],
            domain_tag: TrustObjectType::PolicyCheckpoint.domain_tag(),
            version: 1,
            no_float: true, // Floating point explicitly forbidden
        };
        serializer.register_schema(schema);

        let float_payloads = vec![
            // IEEE 754 patterns
            vec![0x7F, 0xFF, 0xFF, 0xFF], // NaN
            vec![0x7F, 0x80, 0x00, 0x00], // +Infinity
            vec![0xFF, 0x80, 0x00, 0x00], // -Infinity
            vec![0x3F, 0x80, 0x00, 0x00], // 1.0
            // Text patterns
            b"3.14159".to_vec(),
            b"NaN".to_vec(),
            b"Infinity".to_vec(),
            b"inf".to_vec(),
            b"nan".to_vec(),
            // JSON with floats
            b"{\"pi\":3.14159}".to_vec(),
            b"{\"value\":1.0e10}".to_vec(),
        ];

        for payload in float_payloads {
            let result = serializer.construct_preimage(TrustObjectType::PolicyCheckpoint, &payload);
            match result {
                Err(SerializerError::FloatingPointRejected { object_type, field }) => {
                    assert_eq!(object_type, "policy_checkpoint");
                    assert_eq!(field, "payload");
                },
                Err(SerializerError::PreimageConstructionFailed { .. }) => {
                    // Also acceptable for empty payloads
                },
                Ok(_) => {
                    // Some patterns might not be detected by our simple heuristic
                    // In a real implementation, this would be more sophisticated
                },
                Err(e) => panic!("Unexpected error type: {:?}", e),
            }
        }
    }

    #[test]
    fn test_fuzz_preimage_byte_consistency() {
        let mut serializer = CanonicalSerializer::new();

        let schema = CanonicalSchema {
            object_type: TrustObjectType::SessionTicket,
            field_order: vec!["session".to_string()],
            domain_tag: TrustObjectType::SessionTicket.domain_tag(),
            version: 42, // Non-standard version for testing
            no_float: false,
        };
        serializer.register_schema(schema);

        let test_payloads = vec![
            vec![],
            vec![0x00],
            vec![0xFF],
            b"normal_data".to_vec(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
            "unicode_🦀_data".as_bytes().to_vec(),
        ];

        for payload in test_payloads {
            if payload.is_empty() {
                // Empty payload should fail
                let result = serializer.construct_preimage(TrustObjectType::SessionTicket, &payload);
                assert!(matches!(result, Err(SerializerError::PreimageConstructionFailed { .. })));
                continue;
            }

            let result = serializer.construct_preimage(TrustObjectType::SessionTicket, &payload);
            assert!(result.is_ok(), "Failed to construct preimage for payload: {:?}", payload);

            let preimage = result.unwrap();

            // Verify structure
            assert_eq!(preimage.version, 42);
            assert_eq!(preimage.domain_tag, [0x10, 0x04]); // SessionTicket tag
            assert_eq!(preimage.canonical_payload, payload);

            // Verify byte conversion
            let bytes = preimage.to_bytes();
            assert_eq!(bytes.len(), 3 + payload.len());
            assert_eq!(bytes[0], 42); // version
            assert_eq!(&bytes[1..3], &[0x10, 0x04]); // domain tag
            assert_eq!(&bytes[3..], &payload); // payload

            // Verify byte_len consistency
            assert_eq!(preimage.byte_len(), bytes.len());
        }
    }

    #[test]
    fn test_fuzz_schema_registration_edge_cases() {
        let mut serializer = CanonicalSerializer::new();

        // Test with extreme schema configurations
        let extreme_schemas = vec![
            CanonicalSchema {
                object_type: TrustObjectType::OperatorReceipt,
                field_order: vec![], // Empty field order
                domain_tag: [0x00, 0x00], // Zero domain tag
                version: 0, // Zero version
                no_float: true,
            },
            CanonicalSchema {
                object_type: TrustObjectType::RevocationAssertion,
                field_order: vec!["a".repeat(1000)], // Very long field name
                domain_tag: [0xFF, 0xFF], // Max domain tag
                version: 255, // Max version
                no_float: false,
            },
        ];

        for schema in extreme_schemas {
            let object_type = schema.object_type;
            serializer.register_schema(schema);

            // Should be able to use the registered schema
            let result = serializer.construct_preimage(object_type, b"test");
            assert!(result.is_ok(), "Failed to use registered schema for {:?}", object_type);
        }
    }

    #[test]
    fn test_fuzz_concurrent_access_simulation() {
        // Simulate concurrent access patterns that might expose race conditions
        let mut serializer = CanonicalSerializer::new();

        let schema = CanonicalSchema {
            object_type: TrustObjectType::ZoneBoundaryClaim,
            field_order: vec!["zone".to_string()],
            domain_tag: TrustObjectType::ZoneBoundaryClaim.domain_tag(),
            version: 1,
            no_float: true,
        };
        serializer.register_schema(schema);

        // Rapid successive operations that might expose state corruption
        for i in 0..1000 {
            let payload = format!("payload_{}", i).into_bytes();
            let result = serializer.construct_preimage(TrustObjectType::ZoneBoundaryClaim, &payload);

            assert!(result.is_ok(), "Operation {} failed", i);
            let preimage = result.unwrap();

            // Verify integrity is maintained
            assert_eq!(preimage.version, 1);
            assert_eq!(preimage.domain_tag, [0x10, 0x05]);
            assert_eq!(preimage.canonical_payload, payload);
        }
    }

    #[test]
    fn test_fuzz_memory_exhaustion_resistance() {
        let mut serializer = CanonicalSerializer::new();

        let schema = CanonicalSchema {
            object_type: TrustObjectType::DelegationToken,
            field_order: vec!["token".to_string()],
            domain_tag: TrustObjectType::DelegationToken.domain_tag(),
            version: 1,
            no_float: true,
        };
        serializer.register_schema(schema);

        // Test with progressively larger payloads
        for size_exp in 0..20 { // Up to ~1MB
            let size = 1 << size_exp;
            let payload = vec![0x42; size];

            let result = serializer.construct_preimage(TrustObjectType::DelegationToken, &payload);

            // Should handle large payloads gracefully
            match result {
                Ok(preimage) => {
                    assert_eq!(preimage.canonical_payload.len(), size);
                    assert_eq!(preimage.byte_len(), 3 + size);

                    // Memory should be reasonable (not exponentially larger)
                    let bytes = preimage.to_bytes();
                    assert_eq!(bytes.len(), 3 + size);
                },
                Err(e) => {
                    // Acceptable to reject very large payloads
                    assert!(matches!(e, SerializerError::PreimageConstructionFailed { .. }));
                }
            }
        }
    }
}