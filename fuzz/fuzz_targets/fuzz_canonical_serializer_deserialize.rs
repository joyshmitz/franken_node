#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::connector::canonical_serializer::{
    CanonicalSerializer, TrustObjectType,
};
use libfuzzer_sys::fuzz_target;

const MAX_CANONICAL_BYTES: usize = 256 * 1024;

fuzz_target!(|input: FuzzInput| {
    let object_type = input.object_type.into();
    fuzz_raw_deserialize(object_type, &input.raw_bytes);
    fuzz_prefix_synthesis(object_type, &input.payload);
});

fn fuzz_raw_deserialize(object_type: TrustObjectType, bytes: &[u8]) {
    if bytes.len() > MAX_CANONICAL_BYTES {
        return;
    }

    let mut serializer = CanonicalSerializer::with_all_schemas();
    let Ok(decoded) = serializer.deserialize(object_type, bytes) else {
        return;
    };

    let Ok(len) = u32::try_from(decoded.len()) else {
        return;
    };
    let mut reconstructed = Vec::with_capacity(4 + decoded.len());
    reconstructed.extend_from_slice(&len.to_be_bytes());
    reconstructed.extend_from_slice(&decoded);
    assert_eq!(reconstructed, bytes);

    if let Ok(canonical) =
        serializer.round_trip_canonical(object_type, &decoded, "fuzz-deserialize-roundtrip")
    {
        let decoded_again = serializer
            .deserialize(object_type, &canonical)
            .expect("serializer-produced canonical bytes must deserialize");
        assert_eq!(decoded_again, decoded);
    }
}

fn fuzz_prefix_synthesis(object_type: TrustObjectType, payload: &[u8]) {
    if payload.len() > MAX_CANONICAL_BYTES.saturating_sub(4) {
        return;
    }
    let Ok(len) = u32::try_from(payload.len()) else {
        return;
    };

    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(payload);

    let serializer = CanonicalSerializer::with_all_schemas();
    let decoded = serializer
        .deserialize(object_type, &encoded)
        .expect("synthetic canonical length prefix must decode");
    assert_eq!(decoded, payload);
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    object_type: FuzzObjectType,
    raw_bytes: Vec<u8>,
    payload: Vec<u8>,
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
