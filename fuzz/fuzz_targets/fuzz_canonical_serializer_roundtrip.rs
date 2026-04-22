#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::connector::canonical_serializer::{
    canonical_serialization_round_trips, CanonicalSerializationRequest, CanonicalSerializer,
    TrustObjectType,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_RAW_JSON_BYTES: usize = 64 * 1024;
const MAX_STRING_BYTES: usize = 256;

fuzz_target!(|input: FuzzInput| {
    fuzz_structured_payload(&input);
    fuzz_raw_json_payload(&input.raw_json, input.object_type.into());
});

fn fuzz_structured_payload(input: &FuzzInput) {
    let object_type = input.object_type.into();
    let payload = canonical_payload_for_type(object_type, input);
    let Ok(payload_bytes) = serde_json::to_vec(&payload) else {
        return;
    };

    let mut serializer = CanonicalSerializer::with_all_schemas();
    let Ok(serialized) =
        serializer.round_trip_canonical(object_type, &payload_bytes, "fuzz-canonical-roundtrip")
    else {
        return;
    };

    let decoded = serializer
        .deserialize(object_type, &serialized)
        .expect("serializer-produced canonical bytes must deserialize");
    let reserialized = serializer
        .round_trip_canonical(object_type, &decoded, "fuzz-canonical-roundtrip-repeat")
        .expect("serializer-decoded payload must reserialize");
    assert_eq!(serialized, reserialized);

    let preimage = serializer
        .build_preimage(object_type, &payload_bytes, "fuzz-canonical-preimage")
        .expect("valid canonical payload must build preimage");
    assert_eq!(preimage.domain_tag, object_type.domain_tag());
    assert_eq!(preimage.canonical_payload, serialized);

    let request = CanonicalSerializationRequest {
        object_type,
        payload: &payload_bytes,
        trace_id: "fuzz-canonical-batch",
    };
    let batch = canonical_serialization_round_trips(&[request])
        .expect("batch path must accept individually valid canonical payload");
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].canonical_payload, reserialized);
}

fn fuzz_raw_json_payload(bytes: &[u8], object_type: TrustObjectType) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let mut first = CanonicalSerializer::with_all_schemas();
    let Ok(serialized) = first.round_trip_canonical(object_type, bytes, "fuzz-raw-first") else {
        return;
    };

    let mut second = CanonicalSerializer::with_all_schemas();
    let serialized_again = second
        .round_trip_canonical(object_type, bytes, "fuzz-raw-second")
        .expect("canonical serializer must be deterministic for accepted raw payloads");
    assert_eq!(serialized, serialized_again);

    let decoded = first
        .deserialize(object_type, &serialized)
        .expect("accepted canonical bytes must deserialize");
    let recoded = second
        .round_trip_canonical(object_type, &decoded, "fuzz-raw-recoded")
        .expect("decoded accepted payload must remain canonical");
    assert_eq!(serialized, recoded);
}

fn canonical_payload_for_type(object_type: TrustObjectType, input: &FuzzInput) -> Value {
    let text = bounded_string(&input.text);
    let alt = bounded_string(&input.alt_text);
    let hash = format!("sha256:{:064x}", input.hash_seed);
    let timestamp = "2026-04-21T00:00:00Z";

    match object_type {
        TrustObjectType::PolicyCheckpoint => json!({
            "checkpoint_id": format!("cp-{text}"),
            "epoch": bounded_u64(input.numbers.first().copied().unwrap_or_default()),
            "sequence": bounded_u64(input.numbers.get(1).copied().unwrap_or_default()),
            "policy_hash": hash,
            "timestamp": timestamp,
        }),
        TrustObjectType::DelegationToken => json!({
            "token_id": format!("tok-{text}"),
            "issuer": format!("issuer-{alt}"),
            "delegate": format!("delegate-{text}"),
            "scope": format!("scope:{alt}"),
            "expiry": 4_102_444_800_u64.saturating_add(input.hash_seed % 1024),
        }),
        TrustObjectType::RevocationAssertion => json!({
            "assertion_id": format!("rev-{text}"),
            "target_id": format!("target-{alt}"),
            "reason": format!("reason-{text}"),
            "effective_at": timestamp,
            "evidence_hash": hash,
        }),
        TrustObjectType::SessionTicket => json!({
            "session_id": format!("sess-{text}"),
            "client_id": format!("client-{alt}"),
            "server_id": format!("server-{text}"),
            "issued_at": timestamp,
            "ttl": bounded_u64(input.numbers.get(2).copied().unwrap_or(300)),
        }),
        TrustObjectType::ZoneBoundaryClaim => json!({
            "zone_id": format!("zone-{text}"),
            "boundary_type": format!("boundary-{alt}"),
            "peer_zone": format!("peer-{text}"),
            "trust_level": trust_level(input.selector),
            "established_at": timestamp,
        }),
        TrustObjectType::OperatorReceipt => json!({
            "receipt_id": format!("rec-{text}"),
            "operator_id": format!("operator-{alt}"),
            "action": format!("action-{text}"),
            "artifact_hash": hash,
            "timestamp": timestamp,
        }),
    }
}

fn bounded_string(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_STRING_BYTES)
        .collect();
    if out.is_empty() {
        out.push('x');
    }
    out
}

fn bounded_u64(value: u64) -> u64 {
    value % 1_000_000
}

fn trust_level(selector: u8) -> &'static str {
    match selector % 4 {
        0 => "strict",
        1 => "balanced",
        2 => "legacy-risky",
        _ => "quarantined",
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    object_type: FuzzObjectType,
    text: String,
    alt_text: String,
    numbers: Vec<u64>,
    hash_seed: u64,
    selector: u8,
    raw_json: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzObjectType {
    PolicyCheckpoint,
    DelegationToken,
    RevocationAssertion,
    SessionTicket,
    ZoneBoundaryClaim,
    OperatorReceipt,
}

impl From<FuzzObjectType> for TrustObjectType {
    fn from(value: FuzzObjectType) -> Self {
        match value {
            FuzzObjectType::PolicyCheckpoint => Self::PolicyCheckpoint,
            FuzzObjectType::DelegationToken => Self::DelegationToken,
            FuzzObjectType::RevocationAssertion => Self::RevocationAssertion,
            FuzzObjectType::SessionTicket => Self::SessionTicket,
            FuzzObjectType::ZoneBoundaryClaim => Self::ZoneBoundaryClaim,
            FuzzObjectType::OperatorReceipt => Self::OperatorReceipt,
        }
    }
}
