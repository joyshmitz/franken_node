#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::api::fleet_quarantine::{
    canonical_decision_receipt_payload_hash, sign_decision_receipt,
    verify_decision_receipt_signature_with_trust_roots, DecisionReceipt, DecisionReceiptPayload,
    FleetDecisionTrustRoot,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_RAW_JSON_LEN: usize = 16 * 1024;
const MAX_TEXT_LEN: usize = 96;
const FUZZ_KEY_BYTES: [u8; 32] = [0x5a; 32];

fuzz_target!(|input: FuzzInput| {
    let (base_receipt, trust_root) = signed_reconcile_fixture();

    match input {
        FuzzInput::Structured(case) => {
            fuzz_structured_receipt_case(case, &base_receipt, &trust_root)
        }
        FuzzInput::RawJson(bytes) => fuzz_raw_receipt_json(&bytes, &trust_root),
    }
});

fn fuzz_structured_receipt_case(
    case: ReceiptCase,
    base_receipt: &DecisionReceipt,
    trust_root: &FleetDecisionTrustRoot,
) {
    let Ok(mut value) = serde_json::to_value(base_receipt) else {
        return;
    };

    apply_mutation(&mut value, case.mutation);
    if case.add_unknown_top_level_field {
        set_top_level_string(
            &mut value,
            "unknown_fleet_decision_field",
            "ignored-extension-field",
        );
    }

    let json = if case.pretty_json {
        serde_json::to_vec_pretty(&value)
    } else {
        serde_json::to_vec(&value)
    };
    let Ok(json) = json else {
        return;
    };

    let Ok(parsed) = serde_json::from_slice::<DecisionReceipt>(&json) else {
        return;
    };
    let verified = verify_decision_receipt_signature_with_trust_roots(
        &parsed,
        std::slice::from_ref(trust_root),
    );

    if parsed == *base_receipt {
        assert!(
            verified,
            "unmodified signed fleet reconcile receipt must verify"
        );
        assert_verified_receipt_invariants(&parsed, trust_root);
    } else {
        assert!(
            !verified,
            "tampered fleet reconcile decision receipt unexpectedly verified"
        );
    }
}

fn fuzz_raw_receipt_json(bytes: &[u8], trust_root: &FleetDecisionTrustRoot) {
    if bytes.len() > MAX_RAW_JSON_LEN {
        return;
    }

    let Ok(parsed) = serde_json::from_slice::<DecisionReceipt>(bytes) else {
        return;
    };
    let verified = verify_decision_receipt_signature_with_trust_roots(
        &parsed,
        std::slice::from_ref(trust_root),
    );
    if verified {
        assert_verified_receipt_invariants(&parsed, trust_root);
    }

    if let Ok(roundtrip) = serde_json::to_vec(&parsed) {
        if let Ok(decoded) = serde_json::from_slice::<DecisionReceipt>(&roundtrip) {
            assert_eq!(
                parsed, decoded,
                "accepted receipt JSON must round-trip exactly"
            );
        }
    }
}

fn signed_reconcile_fixture() -> (DecisionReceipt, FleetDecisionTrustRoot) {
    let signing_key = SigningKey::from_bytes(&FUZZ_KEY_BYTES);
    let payload = DecisionReceiptPayload::reconcile();
    let operation_id = "fuzz-reconcile-operation-0001".to_string();
    let receipt_id = "fuzz-reconcile-receipt-0001".to_string();
    let issuer = "fleet-control-plane-fuzz".to_string();
    let issued_at = "2026-04-23T00:00:00Z".to_string();
    let zone_id = "all".to_string();
    let payload_hash = canonical_decision_receipt_payload_hash(
        &operation_id,
        &issuer,
        &zone_id,
        &issued_at,
        &payload,
    );
    let mut receipt = DecisionReceipt {
        operation_id,
        receipt_id,
        issuer,
        issued_at,
        zone_id,
        payload_hash,
        decision_payload: payload,
        signature: None,
    };
    receipt.signature = Some(sign_decision_receipt(
        &receipt,
        &signing_key,
        "fuzz-fixture-key",
        "fleet-control-plane",
    ));
    let trust_root = FleetDecisionTrustRoot::from_verifying_key(&signing_key.verifying_key());
    (receipt, trust_root)
}

fn assert_verified_receipt_invariants(
    receipt: &DecisionReceipt,
    trust_root: &FleetDecisionTrustRoot,
) {
    let expected_payload_hash = canonical_decision_receipt_payload_hash(
        &receipt.operation_id,
        &receipt.issuer,
        &receipt.zone_id,
        &receipt.issued_at,
        &receipt.decision_payload,
    );
    assert_eq!(
        receipt.payload_hash, expected_payload_hash,
        "verified receipt must bind the canonical decision payload hash"
    );

    let signature = receipt
        .signature
        .as_ref()
        .expect("verified receipt must have a signature");
    assert_eq!(signature.algorithm, "ed25519");
    assert_eq!(signature.trust_scope, "fleet_decision");
    assert_eq!(signature.key_id, trust_root.key_id);
    assert_eq!(signature.public_key_hex, trust_root.public_key_hex);
    assert_eq!(signature.signed_payload_sha256.len(), 64);
    assert_eq!(signature.signature_hex.len(), 128);
}

fn apply_mutation(value: &mut Value, mutation: ReceiptMutation) {
    match mutation {
        ReceiptMutation::None => {}
        ReceiptMutation::OperationId(text) => {
            set_top_level_string(value, "operation_id", &bounded_text(text))
        }
        ReceiptMutation::ReceiptId(text) => {
            set_top_level_string(value, "receipt_id", &bounded_text(text))
        }
        ReceiptMutation::Issuer(text) => set_top_level_string(value, "issuer", &bounded_text(text)),
        ReceiptMutation::IssuedAt(text) => {
            set_top_level_string(value, "issued_at", &bounded_text(text))
        }
        ReceiptMutation::ZoneId(text) => {
            set_top_level_string(value, "zone_id", &bounded_text(text))
        }
        ReceiptMutation::PayloadHash(text) => {
            set_top_level_string(value, "payload_hash", &bounded_text(text))
        }
        ReceiptMutation::PayloadActionType(text) => {
            set_decision_payload_string(value, "action_type", &bounded_text(text));
        }
        ReceiptMutation::PayloadReason(text) => {
            set_decision_payload_string(value, "reason", &bounded_text(text));
        }
        ReceiptMutation::PayloadEventCode(text) => {
            set_decision_payload_string(value, "event_code", &bounded_text(text));
        }
        ReceiptMutation::ScopeZone(text) => set_scope_string(value, "zone_id", &bounded_text(text)),
        ReceiptMutation::ScopeTenant(text) => {
            set_scope_string(value, "tenant_id", &bounded_text(text))
        }
        ReceiptMutation::AffectedNodes(count) => set_scope_number(value, "affected_nodes", count),
        ReceiptMutation::SignatureAlgorithm(text) => {
            set_signature_string(value, "algorithm", &bounded_text(text));
        }
        ReceiptMutation::SignatureKeyId(text) => {
            set_signature_string(value, "key_id", &bounded_text(text))
        }
        ReceiptMutation::SignaturePublicKeyHex(text) => {
            set_signature_string(value, "public_key_hex", &bounded_text(text));
        }
        ReceiptMutation::SignaturePayloadHash(text) => {
            set_signature_string(value, "signed_payload_sha256", &bounded_text(text));
        }
        ReceiptMutation::SignatureHex(text) => {
            set_signature_string(value, "signature_hex", &bounded_text(text));
        }
        ReceiptMutation::SignatureTrustScope(text) => {
            set_signature_string(value, "trust_scope", &bounded_text(text));
        }
        ReceiptMutation::MissingSignature => {
            if let Some(object) = value.as_object_mut() {
                object.remove("signature");
            }
        }
        ReceiptMutation::NullSignature => {
            if let Some(object) = value.as_object_mut() {
                object.insert("signature".to_string(), Value::Null);
            }
        }
    }
}

fn set_top_level_string(value: &mut Value, field: &str, replacement: &str) {
    if let Some(object) = value.as_object_mut() {
        object.insert(field.to_string(), Value::String(replacement.to_string()));
    }
}

fn set_decision_payload_string(value: &mut Value, field: &str, replacement: &str) {
    let Some(payload) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("decision_payload"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    payload.insert(field.to_string(), Value::String(replacement.to_string()));
}

fn set_scope_string(value: &mut Value, field: &str, replacement: &str) {
    let Some(scope) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("decision_payload"))
        .and_then(Value::as_object_mut)
        .and_then(|payload| payload.get_mut("scope"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    scope.insert(field.to_string(), Value::String(replacement.to_string()));
}

fn set_scope_number(value: &mut Value, field: &str, replacement: u32) {
    let Some(scope) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("decision_payload"))
        .and_then(Value::as_object_mut)
        .and_then(|payload| payload.get_mut("scope"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    scope.insert(field.to_string(), Value::from(replacement));
}

fn set_signature_string(value: &mut Value, field: &str, replacement: &str) {
    let Some(signature) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("signature"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    signature.insert(field.to_string(), Value::String(replacement.to_string()));
}

fn bounded_text(text: String) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_LEN)
        .collect()
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Structured(ReceiptCase),
    RawJson(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct ReceiptCase {
    mutation: ReceiptMutation,
    add_unknown_top_level_field: bool,
    pretty_json: bool,
}

#[derive(Arbitrary, Debug)]
enum ReceiptMutation {
    None,
    OperationId(String),
    ReceiptId(String),
    Issuer(String),
    IssuedAt(String),
    ZoneId(String),
    PayloadHash(String),
    PayloadActionType(String),
    PayloadReason(String),
    PayloadEventCode(String),
    ScopeZone(String),
    ScopeTenant(String),
    AffectedNodes(u32),
    SignatureAlgorithm(String),
    SignatureKeyId(String),
    SignaturePublicKeyHex(String),
    SignaturePayloadHash(String),
    SignatureHex(String),
    SignatureTrustScope(String),
    MissingSignature,
    NullSignature,
}
