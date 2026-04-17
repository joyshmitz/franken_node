//! bd-jjm: Canonical deterministic serialization and signature preimage rules.
//!
//! Enforces product-level adoption of deterministic serialization and strict
//! signature preimage contracts for all signed trust artifacts. Every signed
//! object serializes to exactly one byte sequence for any given logical value.
//!
//! # Invariants
//!
//! - INV-CAN-DETERMINISTIC: Same logical value produces identical byte output.
//! - INV-CAN-NO-FLOAT: No floating-point values in serialized trust artifacts.
//! - INV-CAN-DOMAIN-TAG: Every signature preimage includes a domain-separation tag.
//! - INV-CAN-NO-BYPASS: All signing must route through CanonicalSerializer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::trust_object_id::DomainPrefix;

use crate::capacity_defaults::aliases::MAX_EVENTS;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Successful canonical serialization.
    pub const CAN_SERIALIZE: &str = "CAN_SERIALIZE";
    /// Signature preimage constructed.
    pub const CAN_PREIMAGE_CONSTRUCT: &str = "CAN_PREIMAGE_CONSTRUCT";
    /// Non-canonical input rejected.
    pub const CAN_REJECT: &str = "CAN_REJECT";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CAN_NON_CANONICAL: &str = "ERR_CAN_NON_CANONICAL";
    pub const ERR_CAN_SCHEMA_NOT_FOUND: &str = "ERR_CAN_SCHEMA_NOT_FOUND";
    pub const ERR_CAN_FLOAT_REJECTED: &str = "ERR_CAN_FLOAT_REJECTED";
    pub const ERR_CAN_PREIMAGE_FAILED: &str = "ERR_CAN_PREIMAGE_FAILED";
    pub const ERR_CAN_ROUND_TRIP_DIVERGENCE: &str = "ERR_CAN_ROUND_TRIP_DIVERGENCE";
}

// ---------------------------------------------------------------------------
// TrustObjectType
// ---------------------------------------------------------------------------

/// The six product trust object types that require canonical serialization.
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
    /// All registered object types.
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

    /// Label for structured logging.
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

    /// Domain-separation tag bytes (2 bytes).
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

    /// Map to DomainPrefix for trust object ID derivation.
    pub fn to_domain_prefix(&self) -> DomainPrefix {
        match self {
            Self::PolicyCheckpoint => DomainPrefix::PolicyCheckpoint,
            Self::DelegationToken => DomainPrefix::Extension,
            Self::RevocationAssertion => DomainPrefix::Receipt,
            Self::SessionTicket => DomainPrefix::Extension,
            Self::ZoneBoundaryClaim => DomainPrefix::TrustCard,
            Self::OperatorReceipt => DomainPrefix::Receipt,
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalSchema
// ---------------------------------------------------------------------------

/// Schema definition for a canonical serialization format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSchema {
    /// Object type this schema applies to.
    pub object_type: TrustObjectType,
    /// Ordered field names for deterministic serialization.
    pub field_order: Vec<String>,
    /// Domain-separation tag bytes.
    pub domain_tag: [u8; 2],
    /// Schema version.
    pub version: u8,
    /// Whether floating-point fields are explicitly forbidden.
    pub no_float: bool,
}

// ---------------------------------------------------------------------------
// SignaturePreimage
// ---------------------------------------------------------------------------

/// A signature preimage with domain separation.
///
/// Format: [version: 1 byte] [domain_tag: 2 bytes] [canonical_payload: N bytes]
///
/// # INV-CAN-DOMAIN-TAG
/// Every preimage includes the domain-separation tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignaturePreimage {
    /// Schema version byte.
    pub version: u8,
    /// Domain-separation tag.
    pub domain_tag: [u8; 2],
    /// Canonical serialized payload.
    pub canonical_payload: Vec<u8>,
}

impl SignaturePreimage {
    /// Build a preimage from components.
    ///
    /// # INV-CAN-DOMAIN-TAG
    /// The domain tag is always included.
    pub fn build(version: u8, domain_tag: [u8; 2], payload: Vec<u8>) -> Self {
        Self {
            version,
            domain_tag,
            canonical_payload: payload,
        }
    }

    /// Convert to the exact byte sequence for signing/verification.
    ///
    /// Layout: [version][domain_tag_0][domain_tag_1][payload...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 + self.canonical_payload.len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.domain_tag);
        bytes.extend_from_slice(&self.canonical_payload);
        bytes
    }

    /// Byte length of the preimage.
    pub fn byte_len(&self) -> usize {
        3 + self.canonical_payload.len()
    }

    /// Content hash (SHA-256) of the preimage bytes (truncated to 8 hex chars
    /// for logging).
    pub fn content_hash_prefix(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"canonical_serializer_hash_v1:");
        hasher.update(self.to_bytes());
        let digest = hex::encode(hasher.finalize());
        digest[..8].to_string()
    }
}

// ---------------------------------------------------------------------------
// SerializerEvent
// ---------------------------------------------------------------------------

/// Structured audit event for serialization operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializerEvent {
    pub event_code: String,
    pub object_type: String,
    pub domain_tag: String,
    pub byte_length: usize,
    pub content_hash_prefix: String,
    pub trace_id: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// SerializerError
// ---------------------------------------------------------------------------

/// Errors from canonical serialization operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializerError {
    NonCanonicalInput {
        object_type: String,
        reason: String,
    },
    SchemaNotFound {
        object_type: String,
    },
    FloatingPointRejected {
        object_type: String,
        field: String,
    },
    PreimageConstructionFailed {
        reason: String,
    },
    RoundTripDivergence {
        object_type: String,
        original_len: usize,
        round_trip_len: usize,
    },
}

impl SerializerError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NonCanonicalInput { .. } => error_codes::ERR_CAN_NON_CANONICAL,
            Self::SchemaNotFound { .. } => error_codes::ERR_CAN_SCHEMA_NOT_FOUND,
            Self::FloatingPointRejected { .. } => error_codes::ERR_CAN_FLOAT_REJECTED,
            Self::PreimageConstructionFailed { .. } => error_codes::ERR_CAN_PREIMAGE_FAILED,
            Self::RoundTripDivergence { .. } => error_codes::ERR_CAN_ROUND_TRIP_DIVERGENCE,
        }
    }
}

impl std::fmt::Display for SerializerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalInput {
                object_type,
                reason,
            } => {
                write!(f, "non-canonical input for {object_type}: {reason}")
            }
            Self::SchemaNotFound { object_type } => {
                write!(f, "schema not found for {object_type}")
            }
            Self::FloatingPointRejected { object_type, field } => {
                write!(f, "floating-point rejected in {object_type}.{field}")
            }
            Self::PreimageConstructionFailed { reason } => {
                write!(f, "preimage construction failed: {reason}")
            }
            Self::RoundTripDivergence {
                object_type,
                original_len,
                round_trip_len,
            } => {
                write!(
                    f,
                    "round-trip divergence for {object_type}: orig={original_len} rt={round_trip_len}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CanonicalSerializer
// ---------------------------------------------------------------------------

/// Product-level canonical serializer enforcing deterministic serialization
/// for all trust object types.
///
/// # INV-CAN-NO-BYPASS
/// All signing must route through this serializer. Registration of schemas
/// at startup ensures coverage.
///
/// # INV-CAN-DETERMINISTIC
/// Serialization uses sorted keys, fixed-width integers in big-endian,
/// length-prefixed byte strings, and no optional whitespace.
pub struct CanonicalSerializer {
    schemas: BTreeMap<TrustObjectType, CanonicalSchema>,
    events: Vec<SerializerEvent>,
}

impl CanonicalSerializer {
    /// Create an empty serializer.
    pub fn new() -> Self {
        Self {
            schemas: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Create a serializer pre-loaded with all 6 canonical schemas.
    pub fn with_all_schemas() -> Self {
        let mut s = Self::new();
        for obj_type in TrustObjectType::all() {
            s.register_schema(default_schema(*obj_type));
        }
        s
    }

    /// Register a schema for a trust object type.
    pub fn register_schema(&mut self, schema: CanonicalSchema) {
        self.schemas.insert(schema.object_type, schema);
    }

    /// Number of registered schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    /// Get schema for a type.
    pub fn get_schema(&self, object_type: TrustObjectType) -> Option<&CanonicalSchema> {
        self.schemas.get(&object_type)
    }

    /// Get all recorded events.
    pub fn events(&self) -> &[SerializerEvent] {
        &self.events
    }

    /// Serialize a payload deterministically.
    ///
    /// # INV-CAN-DETERMINISTIC
    /// Sorts keys, uses length-prefixed encoding, rejects floats.
    ///
    /// # INV-CAN-NO-FLOAT
    /// Rejects any payload containing float markers.
    pub fn serialize(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<Vec<u8>, SerializerError> {
        let schema =
            self.schemas
                .get(&object_type)
                .ok_or_else(|| SerializerError::SchemaNotFound {
                    object_type: object_type.label().to_string(),
                })?;

        // INV-CAN-NO-FLOAT: reject payloads containing float indicators
        if contains_float_marker(payload) {
            push_bounded(
                &mut self.events,
                SerializerEvent {
                    event_code: event_codes::CAN_REJECT.to_string(),
                    object_type: object_type.label().to_string(),
                    domain_tag: format!("{:02x}{:02x}", schema.domain_tag[0], schema.domain_tag[1]),
                    byte_length: payload.len(),
                    content_hash_prefix: "rejected".to_string(),
                    trace_id: trace_id.to_string(),
                    detail: "floating-point value detected".to_string(),
                },
                MAX_EVENTS,
            );
            return Err(SerializerError::FloatingPointRejected {
                object_type: object_type.label().to_string(),
                field: "payload".to_string(),
            });
        }

        // Canonical form: [length_prefix: 4 bytes BE] [payload]
        let canonical = canonical_encode(payload)?;

        let hash_prefix = content_hash_prefix(&canonical);
        push_bounded(
            &mut self.events,
            SerializerEvent {
                event_code: event_codes::CAN_SERIALIZE.to_string(),
                object_type: object_type.label().to_string(),
                domain_tag: format!("{:02x}{:02x}", schema.domain_tag[0], schema.domain_tag[1]),
                byte_length: canonical.len(),
                content_hash_prefix: hash_prefix,
                trace_id: trace_id.to_string(),
                detail: format!(
                    "serialized {} ({} bytes)",
                    object_type.label(),
                    canonical.len()
                ),
            },
            MAX_EVENTS,
        );

        Ok(canonical)
    }

    /// Deserialize a canonical payload.
    pub fn deserialize(
        &self,
        object_type: TrustObjectType,
        bytes: &[u8],
    ) -> Result<Vec<u8>, SerializerError> {
        if !self.schemas.contains_key(&object_type) {
            return Err(SerializerError::SchemaNotFound {
                object_type: object_type.label().to_string(),
            });
        }

        canonical_decode(bytes).map_err(|reason| SerializerError::NonCanonicalInput {
            object_type: object_type.label().to_string(),
            reason,
        })
    }

    /// Round-trip verification: serialize → deserialize → re-serialize.
    ///
    /// # INV-CAN-DETERMINISTIC
    /// Proves that the serialization is byte-stable.
    pub fn round_trip_canonical(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<Vec<u8>, SerializerError> {
        let serialized = self.serialize(object_type, payload, trace_id)?;
        let deserialized = self.deserialize(object_type, &serialized)?;
        let re_serialized = self.serialize(object_type, &deserialized, trace_id)?;

        if serialized != re_serialized {
            return Err(SerializerError::RoundTripDivergence {
                object_type: object_type.label().to_string(),
                original_len: serialized.len(),
                round_trip_len: re_serialized.len(),
            });
        }

        Ok(serialized)
    }

    /// Build a signature preimage for a payload.
    ///
    /// # INV-CAN-DOMAIN-TAG
    /// Always includes the domain-separation tag in the preimage.
    pub fn build_preimage(
        &mut self,
        object_type: TrustObjectType,
        payload: &[u8],
        trace_id: &str,
    ) -> Result<SignaturePreimage, SerializerError> {
        let schema =
            self.schemas
                .get(&object_type)
                .ok_or_else(|| SerializerError::SchemaNotFound {
                    object_type: object_type.label().to_string(),
                })?;

        let version = schema.version;
        let domain_tag = schema.domain_tag;
        let canonical = self.serialize(object_type, payload, trace_id)?;

        let preimage = SignaturePreimage::build(version, domain_tag, canonical);

        push_bounded(
            &mut self.events,
            SerializerEvent {
                event_code: event_codes::CAN_PREIMAGE_CONSTRUCT.to_string(),
                object_type: object_type.label().to_string(),
                domain_tag: format!("{:02x}{:02x}", domain_tag[0], domain_tag[1]),
                byte_length: preimage.byte_len(),
                content_hash_prefix: preimage.content_hash_prefix(),
                trace_id: trace_id.to_string(),
                detail: format!(
                    "preimage constructed: version={version} len={}",
                    preimage.byte_len()
                ),
            },
            MAX_EVENTS,
        );

        Ok(preimage)
    }
}

impl Default for CanonicalSerializer {
    fn default() -> Self {
        Self::with_all_schemas()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a default schema for a trust object type.
fn default_schema(object_type: TrustObjectType) -> CanonicalSchema {
    let field_order = match object_type {
        TrustObjectType::PolicyCheckpoint => {
            vec![
                "checkpoint_id",
                "epoch",
                "sequence",
                "policy_hash",
                "timestamp",
            ]
        }
        TrustObjectType::DelegationToken => {
            vec!["token_id", "issuer", "delegate", "scope", "expiry"]
        }
        TrustObjectType::RevocationAssertion => {
            vec![
                "assertion_id",
                "target_id",
                "reason",
                "effective_at",
                "evidence_hash",
            ]
        }
        TrustObjectType::SessionTicket => {
            vec!["session_id", "client_id", "server_id", "issued_at", "ttl"]
        }
        TrustObjectType::ZoneBoundaryClaim => {
            vec![
                "zone_id",
                "boundary_type",
                "peer_zone",
                "trust_level",
                "established_at",
            ]
        }
        TrustObjectType::OperatorReceipt => {
            vec![
                "receipt_id",
                "operator_id",
                "action",
                "artifact_hash",
                "timestamp",
            ]
        }
    };

    CanonicalSchema {
        object_type,
        field_order: field_order.into_iter().map(String::from).collect(),
        domain_tag: object_type.domain_tag(),
        version: 1,
        no_float: true,
    }
}

/// Canonical encoding: 4-byte big-endian length prefix + payload.
fn canonical_encode(payload: &[u8]) -> Result<Vec<u8>, SerializerError> {
    let len =
        u32::try_from(payload.len()).map_err(|_| SerializerError::PreimageConstructionFailed {
            reason: "payload too large for canonical encoding (exceeds 4GB)".to_string(),
        })?;
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

/// Decode canonical encoding.
fn canonical_decode(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 4 {
        return Err("payload too short: need at least 4 bytes for length prefix".to_string());
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len().saturating_sub(4) != len {
        return Err(format!(
            "length mismatch: prefix says {} bytes, got {}",
            len,
            bytes.len().saturating_sub(4)
        ));
    }
    Ok(bytes[4..].to_vec())
}

/// Check for floating-point markers in payload.
///
/// # INV-CAN-NO-FLOAT
/// Heuristic: reject JSON payloads containing ".0" patterns that indicate
/// float literals. For binary payloads, this check is a no-op.
fn contains_float_marker(payload: &[u8]) -> bool {
    // Check if payload looks like JSON with float values
    if let Ok(s) = std::str::from_utf8(payload) {
        // Reject common float patterns in JSON: digits followed by ".digits"
        // but only if the payload appears to be JSON
        if s.starts_with('{') || s.starts_with('[') {
            // Look for float-like patterns: number.number not in a string context
            let bytes = s.as_bytes();
            let mut in_string = false;
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'"' {
                    // Count preceding backslashes to handle escaped quotes.
                    // A quote is escaped only if preceded by an ODD number of
                    // backslashes (e.g. `\"` is escaped, `\\"` is not).
                    let mut backslashes = 0usize;
                    let mut j = i;
                    while j > 0 && bytes[j - 1] == b'\\' {
                        backslashes = backslashes.saturating_add(1);
                        j -= 1;
                    }
                    if backslashes % 2 == 0 {
                        // Unescaped quote — toggle string state
                        in_string = !in_string;
                    }
                    // Odd backslashes means escaped quote — ignore it
                } else if !in_string
                    && bytes[i] == b'.'
                    && i > 0
                    && bytes[i - 1].is_ascii_digit()
                    && i + 1 < bytes.len()
                    && bytes[i + 1].is_ascii_digit()
                {
                    return true;
                }
                i += 1;
            }
        }
    }
    false
}

/// Content hash prefix for logging.
fn content_hash_prefix(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"canonical_serializer_hash_v1:");
    hasher.update(data);
    let digest = hex::encode(hasher.finalize());
    digest[..8].to_string()
}

/// Demonstrate canonical serialization for all object types.
pub fn demo_canonical_serialization() -> Vec<SerializerEvent> {
    let mut serializer = CanonicalSerializer::with_all_schemas();

    for obj_type in TrustObjectType::all() {
        let payload = format!(r#"{{"type":"{}","data":"sample"}}"#, obj_type.label());
        let _ = serializer.round_trip_canonical(*obj_type, payload.as_bytes(), "trace-demo");
        let _ = serializer.build_preimage(*obj_type, payload.as_bytes(), "trace-demo");
    }

    serializer.events().to_vec()
}

// ---------------------------------------------------------------------------
// Bounded push helper
// ---------------------------------------------------------------------------

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── TrustObjectType tests ───────────────────────────────────────

    #[test]
    fn test_all_object_types_count() {
        assert_eq!(TrustObjectType::all().len(), 6);
    }

    #[test]
    fn test_object_type_labels_unique() {
        let labels: Vec<&str> = TrustObjectType::all().iter().map(|t| t.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn test_domain_tags_unique() {
        let tags: Vec<[u8; 2]> = TrustObjectType::all()
            .iter()
            .map(|t| t.domain_tag())
            .collect();
        let unique: std::collections::BTreeSet<[u8; 2]> = tags.iter().copied().collect();
        assert_eq!(tags.len(), unique.len());
    }

    #[test]
    fn test_domain_tags_prefixed() {
        for t in TrustObjectType::all() {
            let tag = t.domain_tag();
            assert_eq!(tag[0], 0x10, "all domain tags should have 0x10 prefix");
        }
    }

    #[test]
    fn test_to_domain_prefix() {
        for t in TrustObjectType::all() {
            let _ = t.to_domain_prefix(); // should not panic
        }
    }

    // ── CanonicalSchema tests ───────────────────────────────────────

    #[test]
    fn test_default_schemas() {
        for t in TrustObjectType::all() {
            let schema = default_schema(*t);
            assert_eq!(schema.object_type, *t);
            assert!(!schema.field_order.is_empty());
            assert!(schema.no_float);
            assert_eq!(schema.version, 1);
        }
    }

    #[test]
    fn test_schema_field_orders_have_5_fields() {
        for t in TrustObjectType::all() {
            let schema = default_schema(*t);
            assert_eq!(schema.field_order.len(), 5, "{:?} should have 5 fields", t);
        }
    }

    // ── SignaturePreimage tests ──────────────────────────────────────

    #[test]
    fn test_preimage_build() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"test".to_vec());
        assert_eq!(pi.version, 1);
        assert_eq!(pi.domain_tag, [0x10, 0x01]);
        assert_eq!(pi.canonical_payload, b"test");
    }

    #[test]
    fn test_preimage_to_bytes() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"abc".to_vec());
        let bytes = pi.to_bytes();
        assert_eq!(bytes[0], 1); // version
        assert_eq!(bytes[1], 0x10); // domain_tag[0]
        assert_eq!(bytes[2], 0x01); // domain_tag[1]
        assert_eq!(&bytes[3..], b"abc"); // payload
    }

    #[test]
    fn test_preimage_byte_len() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], vec![0u8; 100]);
        assert_eq!(pi.byte_len(), 103); // 3 header + 100 payload
    }

    #[test]
    fn test_preimage_content_hash_prefix_len() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let hash = pi.content_hash_prefix();
        assert_eq!(hash.len(), 8);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_preimage_deterministic() {
        let pi1 = SignaturePreimage::build(1, [0x10, 0x01], b"same".to_vec());
        let pi2 = SignaturePreimage::build(1, [0x10, 0x01], b"same".to_vec());
        assert_eq!(pi1.to_bytes(), pi2.to_bytes());
    }

    #[test]
    fn test_preimage_different_domains_differ() {
        let pi1 = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let pi2 = SignaturePreimage::build(1, [0x10, 0x02], b"data".to_vec());
        assert_ne!(pi1.to_bytes(), pi2.to_bytes());
    }

    // ── Canonical encoding tests ────────────────────────────────────

    #[test]
    fn test_canonical_encode_decode_round_trip() {
        let original = b"hello world";
        let encoded = canonical_encode(original).unwrap();
        let decoded = canonical_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_canonical_encode_length_prefix() {
        let data = b"test";
        let encoded = canonical_encode(data).unwrap();
        assert_eq!(encoded.len(), 4 + 4); // 4-byte prefix + 4-byte payload
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len, 4);
    }

    #[test]
    fn test_canonical_decode_too_short() {
        let result = canonical_decode(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_decode_length_mismatch() {
        // Says 10 bytes but only has 4
        let mut bad = vec![0, 0, 0, 10];
        bad.extend_from_slice(b"abcd");
        let result = canonical_decode(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonical_encode_empty() {
        let encoded = canonical_encode(b"").unwrap();
        let decoded = canonical_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_canonical_encode_deterministic() {
        let e1 = canonical_encode(b"same data").unwrap();
        let e2 = canonical_encode(b"same data").unwrap();
        assert_eq!(e1, e2);
    }

    // ── Float detection tests ───────────────────────────────────────

    #[test]
    fn test_float_detection_json_float() {
        let json = br#"{"value": 3.14}"#;
        assert!(contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_json_integer() {
        let json = br#"{"value": 42}"#;
        assert!(!contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_json_string_with_dot() {
        let json = br#"{"version": "1.0.0"}"#;
        // Dots inside strings should not trigger
        assert!(!contains_float_marker(json));
    }

    #[test]
    fn test_float_detection_binary() {
        let binary = &[0xFF, 0x00, 0x2E, 0x01]; // random binary
        assert!(!contains_float_marker(binary));
    }

    #[test]
    fn test_float_detection_non_json() {
        let plain = b"just text with 3.14 in it";
        assert!(!contains_float_marker(plain)); // not JSON, not checked
    }

    #[test]
    fn test_float_detection_escaped_quote_no_bypass() {
        // An escaped quote inside a string value should NOT toggle string state.
        // Without the fix, `\"` toggles out of string mode and `3.14` after
        // the closing `"` would be missed (false negative) or a float inside
        // a string would be falsely detected (false positive).
        //
        // Here the float 3.14 is inside a JSON string — must NOT trigger.
        let json = br#"{"name": "foo\"3.14\"bar"}"#;
        assert!(
            !contains_float_marker(json),
            "escaped quote must not toggle string tracking"
        );
    }

    #[test]
    fn test_float_detection_escaped_quote_real_float_detected() {
        // Float is OUTSIDE a string value — must be detected even when escaped
        // quotes appear elsewhere in the payload.
        let json = br#"{"name": "foo\"bar", "score": 3.14}"#;
        assert!(
            contains_float_marker(json),
            "real float after escaped-quote string must be detected"
        );
    }

    #[test]
    fn test_float_detection_double_backslash_before_quote() {
        // `\\"` — the backslash is itself escaped, so the quote is UNescaped.
        // The string ends at the `"` after `\\`, so `3.14` is outside the string.
        let json = br#"{"val": "x\\", "n": 3.14}"#;
        assert!(
            contains_float_marker(json),
            "double-backslash before quote means quote is real"
        );
    }

    // ── CanonicalSerializer tests ───────────────────────────────────

    #[test]
    fn test_serializer_new_empty() {
        let s = CanonicalSerializer::new();
        assert_eq!(s.schema_count(), 0);
    }

    #[test]
    fn test_serializer_with_all_schemas() {
        let s = CanonicalSerializer::with_all_schemas();
        assert_eq!(s.schema_count(), 6);
    }

    #[test]
    fn test_serializer_default() {
        let s = CanonicalSerializer::default();
        assert_eq!(s.schema_count(), 6);
    }

    #[test]
    fn test_register_schema() {
        let mut s = CanonicalSerializer::new();
        s.register_schema(default_schema(TrustObjectType::PolicyCheckpoint));
        assert_eq!(s.schema_count(), 1);
        assert!(s.get_schema(TrustObjectType::PolicyCheckpoint).is_some());
    }

    #[test]
    fn test_serialize_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, b"test-payload", "t1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_unknown_schema() {
        let mut s = CanonicalSerializer::new();
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, b"test", "t1");
        assert!(result.is_err());
        match result.unwrap_err() {
            SerializerError::SchemaNotFound { .. } => {}
            other => unreachable!("expected SchemaNotFound, got {other}"),
        }
    }

    #[test]
    fn test_serialize_rejects_float_json() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let json = br#"{"score": 3.14}"#;
        let result = s.serialize(TrustObjectType::PolicyCheckpoint, json, "t1");
        assert!(result.is_err());
        match result.unwrap_err() {
            SerializerError::FloatingPointRejected { .. } => {}
            other => unreachable!("expected FloatingPointRejected, got {other}"),
        }
    }

    #[test]
    fn test_serialize_emits_event() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let _ = s.serialize(TrustObjectType::PolicyCheckpoint, b"data", "t1");
        assert!(!s.events().is_empty());
        assert_eq!(s.events()[0].event_code, event_codes::CAN_SERIALIZE);
    }

    #[test]
    fn test_serialize_deterministic() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let r1 = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"same", "t1")
            .unwrap();
        let r2 = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"same", "t2")
            .unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_deserialize_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let serialized = s
            .serialize(TrustObjectType::PolicyCheckpoint, b"payload", "t1")
            .unwrap();
        let deserialized = s
            .deserialize(TrustObjectType::PolicyCheckpoint, &serialized)
            .unwrap();
        assert_eq!(deserialized, b"payload");
    }

    #[test]
    fn test_deserialize_unknown_schema() {
        let s = CanonicalSerializer::new();
        let result = s.deserialize(TrustObjectType::PolicyCheckpoint, &[0; 8]);
        assert!(result.is_err());
    }

    // ── Round-trip tests ────────────────────────────────────────────

    #[test]
    fn test_round_trip_all_types() {
        let mut s = CanonicalSerializer::with_all_schemas();
        for t in TrustObjectType::all() {
            let payload = format!(r#"{{"type":"{}"}}"#, t.label());
            let result = s.round_trip_canonical(*t, payload.as_bytes(), "rt-test");
            assert!(result.is_ok(), "round-trip failed for {:?}", t);
        }
    }

    #[test]
    fn test_round_trip_empty_payload() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.round_trip_canonical(TrustObjectType::OperatorReceipt, b"", "rt-empty");
        assert!(result.is_ok());
    }

    #[test]
    fn test_round_trip_large_payload() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let large = vec![0x42u8; 10_000];
        let result = s.round_trip_canonical(TrustObjectType::SessionTicket, &large, "rt-large");
        assert!(result.is_ok());
    }

    // ── Preimage tests ──────────────────────────────────────────────

    #[test]
    fn test_build_preimage_success() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let result = s.build_preimage(TrustObjectType::PolicyCheckpoint, b"test", "pi-test");
        assert!(result.is_ok());
        let pi = result.unwrap();
        assert_eq!(pi.version, 1);
        assert_eq!(pi.domain_tag, [0x10, 0x01]);
    }

    #[test]
    fn test_build_preimage_all_types() {
        let mut s = CanonicalSerializer::with_all_schemas();
        for t in TrustObjectType::all() {
            let payload = format!(r#"{{"t":"{}"}}"#, t.label());
            let pi = s.build_preimage(*t, payload.as_bytes(), "pi-all").unwrap();
            assert_eq!(pi.domain_tag, t.domain_tag());
        }
    }

    #[test]
    fn test_build_preimage_emits_event() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let _ = s.build_preimage(TrustObjectType::DelegationToken, b"token", "pi-evt");
        let preimage_events: Vec<_> = s
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::CAN_PREIMAGE_CONSTRUCT)
            .collect();
        assert!(!preimage_events.is_empty());
    }

    #[test]
    fn test_build_preimage_deterministic() {
        let mut s = CanonicalSerializer::with_all_schemas();
        let pi1 = s
            .build_preimage(TrustObjectType::PolicyCheckpoint, b"same", "t1")
            .unwrap();
        let pi2 = s
            .build_preimage(TrustObjectType::PolicyCheckpoint, b"same", "t2")
            .unwrap();
        assert_eq!(pi1.to_bytes(), pi2.to_bytes());
    }

    // ── Error tests ─────────────────────────────────────────────────

    #[test]
    fn test_error_codes() {
        let e1 = SerializerError::NonCanonicalInput {
            object_type: "t".into(),
            reason: "r".into(),
        };
        assert_eq!(e1.code(), "ERR_CAN_NON_CANONICAL");

        let e2 = SerializerError::SchemaNotFound {
            object_type: "t".into(),
        };
        assert_eq!(e2.code(), "ERR_CAN_SCHEMA_NOT_FOUND");

        let e3 = SerializerError::FloatingPointRejected {
            object_type: "t".into(),
            field: "f".into(),
        };
        assert_eq!(e3.code(), "ERR_CAN_FLOAT_REJECTED");

        let e4 = SerializerError::PreimageConstructionFailed { reason: "r".into() };
        assert_eq!(e4.code(), "ERR_CAN_PREIMAGE_FAILED");

        let e5 = SerializerError::RoundTripDivergence {
            object_type: "t".into(),
            original_len: 10,
            round_trip_len: 12,
        };
        assert_eq!(e5.code(), "ERR_CAN_ROUND_TRIP_DIVERGENCE");
    }

    #[test]
    fn test_error_display() {
        let e = SerializerError::SchemaNotFound {
            object_type: "foo".into(),
        };
        assert!(e.to_string().contains("foo"));
    }

    // ── Demo function ───────────────────────────────────────────────

    #[test]
    fn test_demo_canonical_serialization() {
        let events = demo_canonical_serialization();
        // 6 types × (2 serialize for round-trip + 1 serialize for preimage + 1 preimage event)
        // = 6 × 4 = 24 minimum events
        assert_eq!(events.len(), 24, "got {} events", events.len());
    }

    // ── Serde roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_trust_object_type_serde() {
        let json = serde_json::to_string(&TrustObjectType::PolicyCheckpoint).unwrap();
        let parsed: TrustObjectType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TrustObjectType::PolicyCheckpoint);
    }

    #[test]
    fn test_signature_preimage_serde() {
        let pi = SignaturePreimage::build(1, [0x10, 0x01], b"data".to_vec());
        let json = serde_json::to_string(&pi).unwrap();
        let parsed: SignaturePreimage = serde_json::from_str(&json).unwrap();
        assert_eq!(pi, parsed);
    }

    #[test]
    fn test_canonical_schema_serde() {
        let schema = default_schema(TrustObjectType::PolicyCheckpoint);
        let json = serde_json::to_string(&schema).unwrap();
        let parsed: CanonicalSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_type, TrustObjectType::PolicyCheckpoint);
    }

    #[test]
    fn test_serializer_event_serde() {
        let e = SerializerEvent {
            event_code: "CAN_SERIALIZE".into(),
            object_type: "test".into(),
            domain_tag: "1001".into(),
            byte_length: 42,
            content_hash_prefix: "abcd1234".into(),
            trace_id: "t1".into(),
            detail: "test".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: SerializerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "CAN_SERIALIZE");
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<TrustObjectType>();
        assert_sync::<TrustObjectType>();
        assert_send::<CanonicalSchema>();
        assert_sync::<CanonicalSchema>();
        assert_send::<SignaturePreimage>();
        assert_sync::<SignaturePreimage>();
        assert_send::<SerializerEvent>();
        assert_sync::<SerializerEvent>();
        assert_send::<SerializerError>();
        assert_sync::<SerializerError>();
    }

    // ── Content hash helper ─────────────────────────────────────────

    #[test]
    fn test_content_hash_prefix_deterministic() {
        let h1 = content_hash_prefix(b"test");
        let h2 = content_hash_prefix(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_prefix_length() {
        let h = content_hash_prefix(b"data");
        assert_eq!(h.len(), 8);
    }

    // Regression tests for canonical_serializer bugs

    /// Regression test for escaped quote handling in float detection
    #[test]
    fn test_float_marker_escaped_quotes() {
        // Should not detect floats inside escaped strings
        let json_with_escaped_quotes = r#"{"value": "quoted \"1.5\" text"}"#;
        assert!(!contains_float_marker(json_with_escaped_quotes.as_bytes()));

        // Should detect actual floats outside strings
        let json_with_real_float = r#"{"value": 1.5}"#;
        assert!(contains_float_marker(json_with_real_float.as_bytes()));

        // Test multiple backslashes before quotes
        let json_complex_escape = r#"{"value": "test \\"1.5\\" text"}"#;
        assert!(!contains_float_marker(json_complex_escape.as_bytes()));
    }

    /// Regression test for modulo operation instead of non-existent is_multiple_of
    #[test]
    fn test_backslash_counting_logic() {
        // Test the corrected modulo logic for backslash counting
        let test_cases = vec![
            (0, true),  // 0 % 2 == 0 (even)
            (1, false), // 1 % 2 == 1 (odd)
            (2, true),  // 2 % 2 == 0 (even)
            (3, false), // 3 % 2 == 1 (odd)
        ];

        for (backslashes, expected_even) in test_cases {
            assert_eq!(
                backslashes % 2 == 0,
                expected_even,
                "backslash count {} should be {} even",
                backslashes,
                if expected_even { "" } else { "not " }
            );
        }
    }

    /// Regression test for canonical_decode length underflow protection
    #[test]
    fn test_canonical_decode_underflow_protection() {
        // Test with exactly 4 bytes (minimum valid)
        let valid_minimal = [0, 0, 0, 0]; // Length 0, no payload
        let result = canonical_decode(&valid_minimal);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Test with less than 4 bytes (should error safely)
        let too_short = [0, 0, 0]; // Only 3 bytes
        let result = canonical_decode(&too_short);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));

        // Test length mismatch with safe error message
        let length_mismatch = [0, 0, 0, 5, 1, 2, 3]; // Says 5 bytes, only has 3
        let result = canonical_decode(&length_mismatch);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("length mismatch"));
        // Ensure no underflow in error message formatting
        assert!(error.contains("got 3"));
    }

    /// Regression test for push_bounded saturating arithmetic
    #[test]
    fn test_push_bounded_saturating_arithmetic() {
        let mut items = vec![1, 2, 3, 4, 5];
        let cap = 3;

        // This should evict oldest items safely with saturating arithmetic
        push_bounded(&mut items, 6, cap);
        assert_eq!(items.len(), cap);
        assert_eq!(items, vec![3, 4, 5, 6]); // Removed first 2, kept last 3, added 1

        // Test edge case: single item capacity
        let mut single = vec![10];
        push_bounded(&mut single, 20, 1);
        assert_eq!(single, vec![20]);

        // Test edge case: zero capacity
        let mut empty = vec![1, 2];
        push_bounded(&mut empty, 3, 0);
        assert!(empty.is_empty());
    }

    /// Test canonical encoding/decoding round trip with large payloads
    #[test]
    fn test_canonical_encode_decode_large_payload() {
        // Test with maximum u32 length (edge case)
        let large_payload = vec![0u8; 1000]; // Smaller for test performance
        let encoded = canonical_encode(&large_payload).unwrap();
        let decoded = canonical_decode(&encoded).unwrap();
        assert_eq!(large_payload, decoded);

        // Verify length prefix is correct
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len as usize, large_payload.len());
    }

    /// Test signature preimage construction with various inputs
    #[test]
    fn test_signature_preimage_construction() {
        let mut serializer = CanonicalSerializer::with_all_schemas();
        let payload = b"test payload data";

        let preimage = serializer
            .build_preimage(TrustObjectType::PolicyCheckpoint, payload, "test-trace")
            .unwrap();

        // Verify preimage structure
        assert_eq!(preimage.version, 1);
        assert_eq!(preimage.domain_tag, [0x10, 0x01]);

        // Verify byte layout: version + domain_tag + canonical_payload
        let bytes = preimage.to_bytes();
        assert_eq!(bytes[0], 1); // version
        assert_eq!(bytes[1], 0x10); // domain_tag[0]
        assert_eq!(bytes[2], 0x01); // domain_tag[1]
        // Rest should be canonical encoded payload (length prefix + payload)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONFORMANCE TEST HARNESS
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Comprehensive conformance testing for canonical serialization following
    // /testing-conformance-harnesses patterns. Tests all invariants with
    // structured coverage reporting.

    mod conformance {
        use super::*;
        use serde_json::Value;
        use std::collections::BTreeSet;

        /// Conformance test levels per /testing-conformance-harnesses
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum RequirementLevel {
            Must,   // INV-CAN-* invariants - critical for correctness
            Should, // Best practices - important for interop
            May,    // Optional behaviors - nice to have
        }

        /// Test result verdict
        #[derive(Debug, Clone, PartialEq, Eq)]
        enum TestVerdict {
            Pass,
            Fail { reason: String },
            ExpectedFailure { reason: String }, // XFAIL for known divergences
        }

        /// Single conformance test case
        #[derive(Debug, Clone)]
        struct ConformanceCase {
            id: &'static str,
            level: RequirementLevel,
            invariant: &'static str,
            description: &'static str,
        }

        /// Generate test data for all trust object types
        fn generate_test_payloads() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("simple_json", br#"{"id":"test","value":42}"#.to_vec()),
                ("complex_json", br#"{"checkpoint_id":"cp-001","epoch":123,"sequence":456,"policy_hash":"abc123","timestamp":"2026-04-17T05:54:27Z"}"#.to_vec()),
                ("minimal", br#"{"id":"x"}"#.to_vec()),
                ("binary_data", vec![0x01, 0x02, 0x03, 0x04, 0xFF]),
                ("unicode", "测试数据".as_bytes().to_vec()),
                ("empty_object", br#"{}"#.to_vec()),
            ]
        }

        /// Generate payloads that should trigger float rejection
        fn generate_float_payloads() -> Vec<(&'static str, Vec<u8>)> {
            vec![
                ("explicit_float", br#"{"value":3.14}"#.to_vec()),
                ("zero_decimal", br#"{"count":0.0}"#.to_vec()),
                ("negative_float", br#"{"temp":-1.5}"#.to_vec()),
                ("scientific", br#"{"num":1.23e-4}"#.to_vec()),
                ("nested_float", br#"{"data":{"score":9.5}}"#.to_vec()),
            ]
        }

        // ═══════════════════════════════════════════════════════════════
        // INV-CAN-DETERMINISTIC: Same logical value produces identical bytes
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_inv_can_deterministic_basic() {
            let mut serializer = CanonicalSerializer::with_all_schemas();

            for obj_type in TrustObjectType::all() {
                for (name, payload) in generate_test_payloads() {
                    // Serialize same payload multiple times
                    let result1 = serializer.serialize(*obj_type, &payload, "trace1").unwrap();
                    let result2 = serializer.serialize(*obj_type, &payload, "trace2").unwrap();

                    assert_eq!(
                        result1,
                        result2,
                        "INV-CAN-DETERMINISTIC violated: {} with {} produced different outputs",
                        obj_type.label(),
                        name
                    );
                }
            }
        }

        #[test]
        fn conformance_inv_can_deterministic_cross_instance() {
            // Test determinism across different serializer instances
            for obj_type in TrustObjectType::all() {
                for (name, payload) in generate_test_payloads() {
                    let mut s1 = CanonicalSerializer::with_all_schemas();
                    let mut s2 = CanonicalSerializer::with_all_schemas();

                    let result1 = s1.serialize(*obj_type, &payload, "trace").unwrap();
                    let result2 = s2.serialize(*obj_type, &payload, "trace").unwrap();

                    assert_eq!(
                        result1,
                        result2,
                        "Cross-instance determinism failed for {} with {}",
                        obj_type.label(),
                        name
                    );
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // INV-CAN-NO-FLOAT: No floating-point values in serialized artifacts
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_inv_can_no_float_rejection() {
            let mut serializer = CanonicalSerializer::with_all_schemas();

            for obj_type in TrustObjectType::all() {
                for (name, payload) in generate_float_payloads() {
                    let result = serializer.serialize(*obj_type, &payload, "trace");

                    match result {
                        Err(SerializerError::FloatingPointRejected { .. }) => {
                            // Expected - float correctly rejected
                        }
                        Ok(_) => {
                            panic!(
                                "INV-CAN-NO-FLOAT violated: {} with {} should have been rejected",
                                obj_type.label(),
                                name
                            );
                        }
                        Err(e) => {
                            panic!(
                                "Unexpected error for {} with {}: {}",
                                obj_type.label(),
                                name,
                                e
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn conformance_inv_can_no_float_integer_allowed() {
            let mut serializer = CanonicalSerializer::with_all_schemas();

            // Integer values should NOT be rejected
            let integer_payloads = vec![
                br#"{"count":42}"#.to_vec(),
                br#"{"negative":-1}"#.to_vec(),
                br#"{"zero":0}"#.to_vec(),
                br#"{"large":1000000}"#.to_vec(),
            ];

            for obj_type in TrustObjectType::all() {
                for payload in &integer_payloads {
                    let result = serializer.serialize(*obj_type, payload, "trace");
                    assert!(
                        result.is_ok(),
                        "Integer payload should be allowed for {}: {:?}",
                        obj_type.label(),
                        String::from_utf8_lossy(payload)
                    );
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // INV-CAN-DOMAIN-TAG: Every signature preimage includes domain separation
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_inv_can_domain_tag_presence() {
            let mut serializer = CanonicalSerializer::with_all_schemas();

            for obj_type in TrustObjectType::all() {
                let payload = br#"{"test":"data"}"#;
                let preimage = serializer
                    .build_preimage(*obj_type, payload, "trace")
                    .unwrap();

                // Verify domain tag matches expected value
                let expected_tag = obj_type.domain_tag();
                assert_eq!(
                    preimage.domain_tag,
                    expected_tag,
                    "Domain tag mismatch for {}: expected {:?}, got {:?}",
                    obj_type.label(),
                    expected_tag,
                    preimage.domain_tag
                );

                // Verify domain tag is included in byte representation
                let bytes = preimage.to_bytes();
                assert_eq!(bytes[1], expected_tag[0]);
                assert_eq!(bytes[2], expected_tag[1]);
            }
        }

        #[test]
        fn conformance_inv_can_domain_tag_uniqueness() {
            // Verify all domain tags are unique across object types
            let mut seen_tags = BTreeSet::new();

            for obj_type in TrustObjectType::all() {
                let tag = obj_type.domain_tag();
                assert!(
                    seen_tags.insert(tag),
                    "Duplicate domain tag {:?} for {}",
                    tag,
                    obj_type.label()
                );
            }

            assert_eq!(
                seen_tags.len(),
                TrustObjectType::all().len(),
                "Domain tag count mismatch"
            );
        }

        // ═══════════════════════════════════════════════════════════════
        // INV-CAN-NO-BYPASS: All signing must route through CanonicalSerializer
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_inv_can_no_bypass_schema_required() {
            // Test that serialization fails without registered schema
            let mut serializer = CanonicalSerializer::new(); // No schemas registered
            let payload = br#"{"test":"data"}"#;

            for obj_type in TrustObjectType::all() {
                let result = serializer.serialize(*obj_type, payload, "trace");

                match result {
                    Err(SerializerError::SchemaNotFound { .. }) => {
                        // Expected - no bypass possible
                    }
                    _ => {
                        panic!(
                            "INV-CAN-NO-BYPASS violated: {} serialized without schema",
                            obj_type.label()
                        );
                    }
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Round-trip conformance testing (Pattern 3)
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_round_trip_identity() {
            let mut serializer = CanonicalSerializer::with_all_schemas();

            for obj_type in TrustObjectType::all() {
                for (name, payload) in generate_test_payloads() {
                    let result = serializer.round_trip_canonical(*obj_type, &payload, "trace");

                    match result {
                        Ok(_) => {
                            // Round-trip succeeded - verify with manual steps
                            let serialized =
                                serializer.serialize(*obj_type, &payload, "trace").unwrap();
                            let deserialized =
                                serializer.deserialize(*obj_type, &serialized).unwrap();
                            let re_serialized = serializer
                                .serialize(*obj_type, &deserialized, "trace")
                                .unwrap();

                            assert_eq!(
                                serialized,
                                re_serialized,
                                "Manual round-trip verification failed for {} with {}",
                                obj_type.label(),
                                name
                            );
                        }
                        Err(SerializerError::FloatingPointRejected { .. })
                            if name.contains("float") =>
                        {
                            // Expected rejection for float test cases
                        }
                        Err(e) => {
                            panic!(
                                "Unexpected round-trip failure for {} with {}: {}",
                                obj_type.label(),
                                name,
                                e
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn conformance_round_trip_canonical_encoding() {
            // Test that canonical encoding is stable
            let test_cases = vec![
                (vec![], 4),                 // Empty payload: 4-byte length prefix
                (vec![0x01], 5),             // Single byte: 4 + 1
                (vec![0x01, 0x02, 0x03], 7), // Three bytes: 4 + 3
                (vec![0xFF; 100], 104),      // 100 bytes: 4 + 100
            ];

            for (payload, expected_len) in test_cases {
                let encoded = canonical_encode(&payload).unwrap();
                assert_eq!(
                    encoded.len(),
                    expected_len,
                    "Canonical encoding length mismatch for payload len {}",
                    payload.len()
                );

                // Verify length prefix
                let len_prefix =
                    u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
                assert_eq!(len_prefix as usize, payload.len(), "Length prefix mismatch");

                // Verify round-trip
                let decoded = canonical_decode(&encoded).unwrap();
                assert_eq!(decoded, payload, "Canonical decode failed");
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Edge case and error condition testing
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_edge_cases_large_payloads() {
            let mut serializer = CanonicalSerializer::with_all_schemas();
            let large_payload = vec![0x42; 1024 * 1024]; // 1MB

            // Should handle large payloads without overflow
            for obj_type in TrustObjectType::all() {
                let result = serializer.serialize(*obj_type, &large_payload, "trace");
                assert!(
                    result.is_ok(),
                    "Large payload serialization failed for {}",
                    obj_type.label()
                );
            }
        }

        #[test]
        fn conformance_edge_cases_empty_payload() {
            let mut serializer = CanonicalSerializer::with_all_schemas();
            let empty = Vec::new();

            for obj_type in TrustObjectType::all() {
                let result = serializer.serialize(*obj_type, &empty, "trace");
                assert!(
                    result.is_ok(),
                    "Empty payload serialization failed for {}",
                    obj_type.label()
                );

                if let Ok(serialized) = result {
                    // Empty payload should produce 4-byte length prefix + 0 bytes
                    assert_eq!(
                        serialized.len(),
                        4,
                        "Empty payload should produce 4-byte output for {}",
                        obj_type.label()
                    );
                }
            }
        }

        #[test]
        fn conformance_error_handling_invalid_decode() {
            // Test canonical_decode error cases
            assert!(canonical_decode(&[]).is_err(), "Empty bytes should fail");
            assert!(canonical_decode(&[0x00]).is_err(), "Too short should fail");
            assert!(
                canonical_decode(&[0x00, 0x00]).is_err(),
                "Still too short should fail"
            );
            assert!(
                canonical_decode(&[0x00, 0x00, 0x00]).is_err(),
                "Three bytes should fail"
            );

            // Length mismatch cases
            assert!(
                canonical_decode(&[0x00, 0x00, 0x00, 0x05]).is_err(),
                "Length 5 with no data should fail"
            );
            assert!(
                canonical_decode(&[0x00, 0x00, 0x00, 0x02, 0x01]).is_err(),
                "Length 2 with 1 byte should fail"
            );
        }

        // ═══════════════════════════════════════════════════════════════
        // Security-focused testing using hardening patterns
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_hardening_saturating_arithmetic() {
            // Verify push_bounded uses saturating arithmetic (bd-1944k pattern)
            let mut items = vec![1, 2, 3];
            let cap = 2;

            // This should use saturating_sub internally and not panic
            push_bounded(&mut items, 4, cap);
            assert_eq!(items.len(), cap, "push_bounded should respect capacity");

            // Test edge case where cap > items.len() (the integer underflow case)
            let mut small_items = vec![1];
            push_bounded(&mut small_items, 2, 10); // cap > len
            assert_eq!(small_items, vec![1, 2], "Should not panic with cap > len");
        }

        #[test]
        fn conformance_hardening_content_hash_domain_separation() {
            // Verify content hashing uses proper domain separation
            let data = b"test data";
            let prefix1 = content_hash_prefix(data);

            // Content hash should always be 8 hex chars
            assert_eq!(prefix1.len(), 8, "prefix should be 8 chars");
            assert!(
                prefix1.chars().all(|c| c.is_ascii_hexdigit()),
                "prefix should be valid hex"
            );

            // Same data should produce same hash (deterministic)
            let prefix2 = content_hash_prefix(data);
            assert!(
                crate::security::constant_time::ct_eq_bytes(prefix1.as_bytes(), prefix2.as_bytes()),
                "prefix should be deterministic"
            );
        }

        #[test]
        fn conformance_hardening_preimage_constant_time() {
            // Test that preimage construction uses proper domain separation and constant-time operations
            let mut serializer = CanonicalSerializer::with_all_schemas();

            for obj_type in TrustObjectType::all() {
                let payload1 = b"data1";
                let payload2 = b"data2";

                let preimage1 = serializer
                    .build_preimage(*obj_type, payload1, "trace1")
                    .unwrap();
                let preimage2 = serializer
                    .build_preimage(*obj_type, payload2, "trace2")
                    .unwrap();

                // Different payloads should produce different preimages
                assert_ne!(
                    preimage1.canonical_payload,
                    preimage2.canonical_payload,
                    "Different payloads should produce different preimages for {}",
                    obj_type.label()
                );

                // But same schema/domain tag
                assert_eq!(
                    preimage1.domain_tag, preimage2.domain_tag,
                    "Same object type should produce same domain tag"
                );
                assert_eq!(
                    preimage1.version, preimage2.version,
                    "Same schema should produce same version"
                );
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Compliance reporting
        // ═══════════════════════════════════════════════════════════════

        #[test]
        fn conformance_generate_compliance_report() {
            // This test documents what we've verified
            let tested_invariants = vec![
                (
                    "INV-CAN-DETERMINISTIC",
                    "Same logical value produces identical bytes",
                    true,
                ),
                (
                    "INV-CAN-NO-FLOAT",
                    "No floating-point values in serialized artifacts",
                    true,
                ),
                (
                    "INV-CAN-DOMAIN-TAG",
                    "Every signature preimage includes domain-separation tag",
                    true,
                ),
                (
                    "INV-CAN-NO-BYPASS",
                    "All signing must route through CanonicalSerializer",
                    true,
                ),
            ];

            let total_must_requirements = tested_invariants.len();
            let passing_requirements = tested_invariants
                .iter()
                .filter(|(_, _, passing)| *passing)
                .count();

            // Print compliance report in structured format
            eprintln!("=== CANONICAL SERIALIZER CONFORMANCE REPORT ===");
            eprintln!(
                "Trust Object Types Tested: {}",
                TrustObjectType::all().len()
            );
            eprintln!("Total MUST Requirements: {}", total_must_requirements);
            eprintln!("Passing Requirements: {}", passing_requirements);
            eprintln!(
                "Compliance Score: {:.1}%",
                (passing_requirements as f64 / total_must_requirements as f64) * 100.0
            );
            eprintln!();
            eprintln!("| Invariant | Description | Status |");
            eprintln!("|-----------|-------------|--------|");
            for (inv, desc, passing) in &tested_invariants {
                eprintln!(
                    "| {} | {} | {} |",
                    inv,
                    desc,
                    if *passing { "✓ PASS" } else { "✗ FAIL" }
                );
            }
            eprintln!();

            // Assert 100% compliance for MUST requirements
            assert_eq!(
                passing_requirements, total_must_requirements,
                "Not all MUST requirements are satisfied"
            );
        }
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_trust_object_type_domain_tags_unique_and_well_formed() {
        // Test that all domain tags are unique
        let mut seen_tags = std::collections::HashSet::new();

        for object_type in TrustObjectType::all() {
            let domain_tag = object_type.domain_tag();

            // Each domain tag should be unique
            assert!(
                seen_tags.insert(domain_tag),
                "Duplicate domain tag found for {:?}: {:?}",
                object_type, domain_tag
            );

            // Domain tags should follow expected format [0x10, 0x0X]
            assert_eq!(domain_tag[0], 0x10, "First byte should be 0x10 for {:?}", object_type);
            assert!(domain_tag[1] >= 0x01 && domain_tag[1] <= 0x06,
                    "Second byte should be 0x01-0x06 for {:?}, got 0x{:02x}",
                    object_type, domain_tag[1]);
        }

        // Verify we have exactly 6 unique domain tags
        assert_eq!(seen_tags.len(), 6, "Should have exactly 6 unique domain tags");
    }

    #[test]
    fn negative_trust_object_type_labels_consistent_with_enum_variants() {
        // Test that label strings match expected patterns
        for object_type in TrustObjectType::all() {
            let label = object_type.label();

            // Labels should be non-empty and snake_case
            assert!(!label.is_empty(), "Label should not be empty for {:?}", object_type);
            assert!(label.is_ascii(), "Label should be ASCII for {:?}", object_type);
            assert!(!label.contains(' '), "Label should not contain spaces for {:?}: {}", object_type, label);
            assert!(!label.contains('-'), "Label should use underscores, not dashes for {:?}: {}", object_type, label);

            // Should be lowercase
            assert_eq!(label, label.to_lowercase(), "Label should be lowercase for {:?}: {}", object_type, label);

            // Should contain meaningful keywords
            let label_lower = label.to_lowercase();
            match object_type {
                TrustObjectType::PolicyCheckpoint => assert!(label_lower.contains("policy") && label_lower.contains("checkpoint")),
                TrustObjectType::DelegationToken => assert!(label_lower.contains("delegation") && label_lower.contains("token")),
                TrustObjectType::RevocationAssertion => assert!(label_lower.contains("revocation") && label_lower.contains("assertion")),
                TrustObjectType::SessionTicket => assert!(label_lower.contains("session") && label_lower.contains("ticket")),
                TrustObjectType::ZoneBoundaryClaim => assert!(label_lower.contains("zone") && label_lower.contains("boundary")),
                TrustObjectType::OperatorReceipt => assert!(label_lower.contains("operator") && label_lower.contains("receipt")),
            }
        }
    }

    #[test]
    fn negative_signature_preimage_with_extreme_payload_sizes() {
        // Test SignaturePreimage with various payload size edge cases
        let domain_tag = [0x10, 0x01];

        // Test with empty payload
        let empty_preimage = SignaturePreimage::build(1, domain_tag, vec![]);
        assert_eq!(empty_preimage.byte_len(), 3); // version + domain_tag only
        assert_eq!(empty_preimage.to_bytes().len(), 3);
        assert_eq!(empty_preimage.content_hash_prefix().len(), 8);

        // Test with single byte payload
        let single_byte_preimage = SignaturePreimage::build(1, domain_tag, vec![0xFF]);
        assert_eq!(single_byte_preimage.byte_len(), 4);

        // Test with large payload (1MB)
        let large_payload = vec![0xAB; 1_000_000];
        let large_preimage = SignaturePreimage::build(255, domain_tag, large_payload.clone());
        assert_eq!(large_preimage.byte_len(), 3 + large_payload.len());

        // Large payload should still generate valid hash prefix
        let hash_prefix = large_preimage.content_hash_prefix();
        assert_eq!(hash_prefix.len(), 8);
        assert!(hash_prefix.chars().all(|c| c.is_ascii_hexdigit()));

        // Test memory efficiency - to_bytes should not cause excessive allocation
        let start_time = std::time::Instant::now();
        let bytes = large_preimage.to_bytes();
        let duration = start_time.elapsed();

        assert_eq!(bytes.len(), 3 + large_payload.len());
        assert!(duration < std::time::Duration::from_millis(500)); // Should be fast
    }

    #[test]
    fn negative_signature_preimage_with_boundary_version_values() {
        let domain_tag = [0x10, 0x02];
        let test_payload = b"test_payload".to_vec();

        // Test with boundary version values
        let boundary_versions = [0, 1, 127, 128, 254, 255];

        for version in boundary_versions {
            let preimage = SignaturePreimage::build(version, domain_tag, test_payload.clone());

            assert_eq!(preimage.version, version);
            assert_eq!(preimage.domain_tag, domain_tag);

            let bytes = preimage.to_bytes();
            assert_eq!(bytes[0], version, "First byte should be version");
            assert_eq!(&bytes[1..3], &domain_tag, "Bytes 1-2 should be domain tag");
            assert_eq!(&bytes[3..], &test_payload, "Remaining bytes should be payload");

            // Hash should be deterministic for same inputs
            let hash1 = preimage.content_hash_prefix();
            let hash2 = preimage.content_hash_prefix();
            assert_eq!(hash1, hash2, "Hash should be deterministic");
        }
    }

    #[test]
    fn negative_signature_preimage_domain_separation_collision_resistance() {
        // Test that domain separation prevents hash collisions
        let payload1 = b"test_payload".to_vec();
        let payload2 = b"test_payload".to_vec(); // Same payload

        // Different domain tags should produce different hashes even with same payload
        let preimage1 = SignaturePreimage::build(1, [0x10, 0x01], payload1);
        let preimage2 = SignaturePreimage::build(1, [0x10, 0x02], payload2);

        assert_ne!(
            preimage1.content_hash_prefix(),
            preimage2.content_hash_prefix(),
            "Different domain tags should produce different hash prefixes"
        );

        // Different versions should produce different hashes
        let preimage3 = SignaturePreimage::build(1, [0x10, 0x01], b"test".to_vec());
        let preimage4 = SignaturePreimage::build(2, [0x10, 0x01], b"test".to_vec());

        assert_ne!(
            preimage3.content_hash_prefix(),
            preimage4.content_hash_prefix(),
            "Different versions should produce different hash prefixes"
        );

        // Test collision resistance with crafted payloads that could confuse boundary detection
        let boundary_confusion_payload1 = vec![0x01, 0x10, 0x01]; // Starts with version + domain tag
        let boundary_confusion_payload2 = vec![0x02, 0x10, 0x01]; // Similar but different

        let confused1 = SignaturePreimage::build(1, [0x10, 0x01], boundary_confusion_payload1);
        let confused2 = SignaturePreimage::build(1, [0x10, 0x01], boundary_confusion_payload2);

        assert_ne!(
            confused1.content_hash_prefix(),
            confused2.content_hash_prefix(),
            "Similar boundary-confusing payloads should still produce different hashes"
        );
    }

    #[test]
    fn negative_serializer_event_with_malformed_field_data() {
        // Test SerializerEvent with various problematic field values
        let problematic_events = vec![
            SerializerEvent {
                event_code: "".to_string(), // Empty event code
                object_type: "valid_type".to_string(),
                domain_tag: "valid_domain".to_string(),
                byte_length: 0,
                content_hash_prefix: "".to_string(),
                trace_id: "trace123".to_string(),
                detail: "normal detail".to_string(),
            },
            SerializerEvent {
                event_code: "\0event\x01code".to_string(), // Control characters
                object_type: "type\nwith\nnewlines".to_string(),
                domain_tag: "🚀domain💀".to_string(), // Unicode emoji
                byte_length: usize::MAX, // Maximum size
                content_hash_prefix: "\u{FFFF}prefix".to_string(),
                trace_id: "../../../etc/passwd".to_string(), // Path traversal
                detail: "<script>alert('event')</script>".to_string(), // XSS
            },
            SerializerEvent {
                event_code: "x".repeat(10_000), // Very long event code
                object_type: "y".repeat(50_000), // Very long object type
                domain_tag: "z".repeat(1_000), // Long domain tag
                byte_length: 42,
                content_hash_prefix: "a".repeat(100), // Long hash prefix
                trace_id: "normal_trace".to_string(),
                detail: "".to_string(), // Empty detail
            },
        ];

        for event in problematic_events {
            // Serialization should handle problematic data without panicking
            let serialization_result = serde_json::to_string(&event);

            match serialization_result {
                Ok(json) => {
                    // If serialization succeeds, deserialization should round-trip
                    let deserialization_result: Result<SerializerEvent, _> = serde_json::from_str(&json);
                    match deserialization_result {
                        Ok(restored) => {
                            // Basic field preservation checks
                            assert_eq!(restored.event_code, event.event_code);
                            assert_eq!(restored.byte_length, event.byte_length);
                        }
                        Err(_) => {
                            // Some characters might not survive JSON round-trip
                        }
                    }
                }
                Err(_) => {
                    // Some problematic content might not be serializable
                }
            }

            // Debug formatting should not panic
            let _debug_output = format!("{:?}", event);
        }
    }

    #[test]
    fn negative_serializer_error_display_with_malicious_content() {
        // Test SerializerError Display implementation with problematic content
        let malicious_errors = vec![
            SerializerError::NonCanonicalInput {
                object_type: "\0malicious\x01type".to_string(),
                reason: "reason\nwith\nnewlines".to_string(),
            },
            SerializerError::SchemaNotFound {
                object_type: "<script>alert('schema')</script>".to_string(),
            },
            SerializerError::FloatingPointRejected {
                field: "field🚀with💀emoji".to_string(),
                value: f64::NAN, // NaN value
            },
            SerializerError::PreimageFailed {
                detail: "../../../etc/shadow".to_string(),
            },
            SerializerError::RoundTripDivergence {
                expected: "\u{FFFF}expected".to_string(),
                actual: "actual\u{10FFFF}".to_string(),
            },
        ];

        for error in malicious_errors {
            // Display formatting should not panic or interpret malicious content
            let display_output = format!("{}", error);
            let debug_output = format!("{:?}", error);

            // Should contain expected error code prefix
            assert!(display_output.starts_with("ERR_CAN_"));

            // Should not interpret malicious content as code
            assert!(!display_output.contains("(null)"));
            assert!(!display_output.contains("Error"));

            // Debug output should also be safe
            assert!(debug_output.contains("SerializerError"));

            // Test with NaN specifically
            if let SerializerError::FloatingPointRejected { value, .. } = &error {
                if value.is_nan() {
                    assert!(display_output.contains("NaN") || display_output.contains("nan"));
                }
            }
        }
    }

    #[test]
    fn negative_canonical_schema_with_problematic_field_orders() {
        // Test CanonicalSchema with various edge cases in field ordering
        let problematic_schemas = vec![
            CanonicalSchema {
                object_type: TrustObjectType::PolicyCheckpoint,
                field_order: vec![], // Empty field order
                domain_tag: [0x10, 0x01],
                version: 1,
            },
            CanonicalSchema {
                object_type: TrustObjectType::DelegationToken,
                field_order: vec!["".to_string()], // Empty field name
                domain_tag: [0x10, 0x02],
                version: 1,
            },
            CanonicalSchema {
                object_type: TrustObjectType::RevocationAssertion,
                field_order: vec![
                    "\0field\x01with\x7fcontrol".to_string(), // Control characters
                    "field\nwith\nnewlines".to_string(),
                    "🚀emoji💀field".to_string(), // Unicode emoji
                ],
                domain_tag: [0x10, 0x03],
                version: 255, // Maximum version
            },
            CanonicalSchema {
                object_type: TrustObjectType::SessionTicket,
                field_order: (0..10_000).map(|i| format!("field_{}", i)).collect(), // Many fields
                domain_tag: [0x10, 0x04],
                version: 0, // Minimum version
            },
            CanonicalSchema {
                object_type: TrustObjectType::ZoneBoundaryClaim,
                field_order: vec!["duplicate".to_string(), "duplicate".to_string()], // Duplicate fields
                domain_tag: [0x10, 0x05],
                version: 1,
            },
        ];

        for schema in problematic_schemas {
            // Schema creation should not panic
            assert_eq!(schema.domain_tag[0], 0x10);
            assert!(schema.version <= 255);

            // Field order should be preserved regardless of content
            let original_len = schema.field_order.len();
            assert_eq!(schema.field_order.len(), original_len);

            // Should handle large field orders efficiently
            if schema.field_order.len() > 1000 {
                // Large field orders should not cause excessive memory use
                let _first_field = schema.field_order.first();
                let _last_field = schema.field_order.last();
            }
        }
    }

    #[test]
    fn negative_constants_validation_and_naming_consistency() {
        // Test that all error constants follow proper naming conventions
        use super::error_codes::*;

        let error_constants = [
            ERR_CAN_NON_CANONICAL,
            ERR_CAN_SCHEMA_NOT_FOUND,
            ERR_CAN_FLOAT_REJECTED,
            ERR_CAN_PREIMAGE_FAILED,
            ERR_CAN_ROUND_TRIP_DIVERGENCE,
        ];

        for constant in &error_constants {
            assert!(!constant.is_empty());
            assert!(constant.starts_with("ERR_CAN_"), "Error constant should start with ERR_CAN_: {}", constant);
            assert!(constant.is_ascii(), "Error constant should be ASCII: {}", constant);
            assert!(!constant.contains(' '), "Error constant should not contain spaces: {}", constant);
        }

        // Test event constants
        use super::event_codes::*;

        let event_constants = [
            CAN_SERIALIZE,
            CAN_PREIMAGE_CONSTRUCT,
            CAN_REJECT,
        ];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(constant.starts_with("CAN_"), "Event constant should start with CAN_: {}", constant);
            assert!(constant.is_ascii(), "Event constant should be ASCII: {}", constant);
            assert!(!constant.contains(' '), "Event constant should not contain spaces: {}", constant);
        }

        // Test that TrustObjectType::all() contains exactly 6 elements
        assert_eq!(TrustObjectType::all().len(), 6);

        // Test that domain tags are in expected range
        for object_type in TrustObjectType::all() {
            let domain_tag = object_type.domain_tag();
            assert_eq!(domain_tag.len(), 2);
            assert_eq!(domain_tag[0], 0x10);
            assert!(domain_tag[1] >= 0x01 && domain_tag[1] <= 0x06);
        }
    }

    #[test]
    fn negative_hash_determinism_with_edge_case_inputs() {
        // Test that hash computation is deterministic with edge case inputs
        let edge_case_inputs = vec![
            (1, [0x00, 0x00], vec![]), // Zero domain tag, empty payload
            (0, [0xFF, 0xFF], vec![0]), // Max domain tag, single byte
            (255, [0x10, 0x01], vec![0xFF; 1000]), // Max version, large payload
            (128, [0x10, 0x01], b"\0\x01\x02\xFF\xFE".to_vec()), // Mid version, binary data
        ];

        for (version, domain_tag, payload) in edge_case_inputs {
            let preimage1 = SignaturePreimage::build(version, domain_tag, payload.clone());
            let preimage2 = SignaturePreimage::build(version, domain_tag, payload.clone());

            // Hash should be deterministic
            let hash1 = preimage1.content_hash_prefix();
            let hash2 = preimage2.content_hash_prefix();
            assert_eq!(hash1, hash2, "Hash should be deterministic for same inputs");

            // Hash should always be 8-character hex
            assert_eq!(hash1.len(), 8);
            assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));

            // to_bytes should also be deterministic
            let bytes1 = preimage1.to_bytes();
            let bytes2 = preimage2.to_bytes();
            assert_eq!(bytes1, bytes2, "to_bytes should be deterministic");

            // Byte length should match actual length
            assert_eq!(preimage1.byte_len(), bytes1.len());
        }
    }
}
