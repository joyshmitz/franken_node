//! Deterministic regression tests for the live canonical serializer contract.
//!
//! The older TrustCard/RemoteCap/EvidenceEntry golden module had drifted away
//! from the actual `TrustObjectType` surface and referenced `.golden` files
//! that are not checked in. These tests assert the authoritative six-object
//! contract directly so integration targets compile and validate the current
//! serializer behavior.

use frankenengine_node::connector::canonical_serializer::{CanonicalSerializer, TrustObjectType};
use serde_json::{Value, json};

struct CanonicalCase {
    object_type: TrustObjectType,
    value: Value,
    expected_payload: &'static str,
}

fn canonical_cases() -> Vec<CanonicalCase> {
    vec![
        CanonicalCase {
            object_type: TrustObjectType::PolicyCheckpoint,
            value: json!({
                "checkpoint_id": "cp-001",
                "epoch": 1,
                "sequence": 1,
                "policy_hash": "sha256:policy",
                "timestamp": "2026-04-21T00:00:00Z"
            }),
            expected_payload: "{\"checkpoint_id\":\"cp-001\",\"epoch\":1,\"sequence\":1,\"policy_hash\":\"sha256:policy\",\"timestamp\":\"2026-04-21T00:00:00Z\"}",
        },
        CanonicalCase {
            object_type: TrustObjectType::DelegationToken,
            value: json!({
                "token_id": "tok-001",
                "issuer": "issuer-a",
                "delegate": "delegate-b",
                "scope": "read:fleet",
                "expiry": 4102444800_u64
            }),
            expected_payload: "{\"token_id\":\"tok-001\",\"issuer\":\"issuer-a\",\"delegate\":\"delegate-b\",\"scope\":\"read:fleet\",\"expiry\":4102444800}",
        },
        CanonicalCase {
            object_type: TrustObjectType::RevocationAssertion,
            value: json!({
                "assertion_id": "rev-001",
                "target_id": "tok-001",
                "reason": "compromise",
                "effective_at": "2026-04-21T00:00:00Z",
                "evidence_hash": "sha256:evidence"
            }),
            expected_payload: "{\"assertion_id\":\"rev-001\",\"target_id\":\"tok-001\",\"reason\":\"compromise\",\"effective_at\":\"2026-04-21T00:00:00Z\",\"evidence_hash\":\"sha256:evidence\"}",
        },
        CanonicalCase {
            object_type: TrustObjectType::SessionTicket,
            value: json!({
                "session_id": "sess-001",
                "client_id": "client-a",
                "server_id": "server-b",
                "issued_at": "2026-04-21T00:00:00Z",
                "ttl": 300
            }),
            expected_payload: "{\"session_id\":\"sess-001\",\"client_id\":\"client-a\",\"server_id\":\"server-b\",\"issued_at\":\"2026-04-21T00:00:00Z\",\"ttl\":300}",
        },
        CanonicalCase {
            object_type: TrustObjectType::ZoneBoundaryClaim,
            value: json!({
                "zone_id": "zone-a",
                "boundary_type": "trust",
                "peer_zone": "zone-b",
                "trust_level": "strict",
                "established_at": "2026-04-21T00:00:00Z"
            }),
            expected_payload: "{\"zone_id\":\"zone-a\",\"boundary_type\":\"trust\",\"peer_zone\":\"zone-b\",\"trust_level\":\"strict\",\"established_at\":\"2026-04-21T00:00:00Z\"}",
        },
        CanonicalCase {
            object_type: TrustObjectType::OperatorReceipt,
            value: json!({
                "receipt_id": "rec-001",
                "operator_id": "operator-a",
                "action": "approve",
                "artifact_hash": "sha256:artifact",
                "timestamp": "2026-04-21T00:00:00Z"
            }),
            expected_payload: "{\"receipt_id\":\"rec-001\",\"operator_id\":\"operator-a\",\"action\":\"approve\",\"artifact_hash\":\"sha256:artifact\",\"timestamp\":\"2026-04-21T00:00:00Z\"}",
        },
    ]
}

fn encoded_length(bytes: &[u8]) -> usize {
    usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .expect("length prefix should fit usize")
}

#[test]
fn canonical_serializer_live_contract_payloads_are_deterministic() {
    let mut serializer = CanonicalSerializer::with_all_schemas();

    for case in canonical_cases() {
        let first = serializer
            .serialize_value(case.object_type, &case.value, "trace-one")
            .expect("first serialization should succeed");
        let second = serializer
            .serialize_value(case.object_type, &case.value, "trace-two")
            .expect("second serialization should succeed");

        assert_eq!(
            first,
            second,
            "{} serialization should be deterministic",
            case.object_type.label()
        );
        assert_eq!(
            encoded_length(&first),
            first.len().saturating_sub(4),
            "{} canonical encoding should use a correct length prefix",
            case.object_type.label()
        );

        let payload = serializer
            .deserialize(case.object_type, &first)
            .expect("deserialization should succeed");
        let payload = String::from_utf8(payload).expect("canonical payload should be UTF-8 JSON");

        assert_eq!(
            payload,
            case.expected_payload,
            "{} payload should follow the live schema field order",
            case.object_type.label()
        );
    }
}

#[test]
fn canonical_serializer_registered_type_order_matches_live_cases() {
    let expected = canonical_cases()
        .into_iter()
        .map(|case| case.object_type.label())
        .collect::<Vec<_>>();
    let actual = TrustObjectType::all()
        .iter()
        .map(TrustObjectType::label)
        .collect::<Vec<_>>();

    assert_eq!(
        actual, expected,
        "test cases should cover each registered trust object type in contract order"
    );
}

#[test]
fn canonical_serializer_events_record_live_contract_metadata() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let cases = canonical_cases();
    let mut expected_lengths = Vec::with_capacity(cases.len());

    for case in &cases {
        let trace_id = format!("event-trace-{}", case.object_type.label());
        let bytes = serializer
            .serialize_value(case.object_type, &case.value, &trace_id)
            .expect("event serialization should succeed");
        expected_lengths.push(bytes.len());
    }

    let events = serializer.events();
    assert_eq!(
        events.len(),
        cases.len(),
        "serializer should record one event per serialization"
    );

    for ((event, case), expected_length) in events.iter().zip(cases.iter()).zip(expected_lengths) {
        let domain_tag = case.object_type.domain_tag();

        assert_eq!(event.event_code, "CAN_SERIALIZE");
        assert_eq!(event.object_type, case.object_type.label());
        assert_eq!(
            event.domain_tag,
            format!("{:02x}{:02x}", domain_tag[0], domain_tag[1])
        );
        assert_eq!(event.byte_length, expected_length);
        assert_eq!(
            event.trace_id,
            format!("event-trace-{}", case.object_type.label())
        );
        assert_eq!(event.content_hash_prefix.len(), 8);
        assert!(
            event
                .content_hash_prefix
                .chars()
                .all(|ch| ch.is_ascii_hexdigit()),
            "content hash prefixes should stay hex-encoded"
        );
        assert!(
            event.detail.contains(case.object_type.label()),
            "event detail should name the serialized object"
        );
    }
}
