use std::error::Error;

use frankenengine_node::security::decision_receipt::{
    Decision, Receipt, ReceiptQuery, export_receipts_cbor, import_receipts_cbor, sign_receipt,
    verify_receipt,
};
use frankenengine_node::supply_chain::artifact_signing::{
    ArtifactSigningError, generate_artifact_signing_key, sign_bytes, signing_key_from_seed_bytes,
    signing_key_from_seed_hex, verify_signature,
};
use serde_json::json;

#[test]
fn generated_artifact_signing_key_signs_and_verifies() -> Result<(), Box<dyn Error>> {
    let signing_key = generate_artifact_signing_key();
    let payload = b"artifact-signing-key-loading";
    let signature = sign_bytes(&signing_key, payload);

    verify_signature(&signing_key.verifying_key(), payload, &signature)?;

    Ok(())
}

#[test]
fn configured_seed_hex_matches_seed_bytes() -> Result<(), Box<dyn Error>> {
    let seed = [31_u8; 32];
    let from_bytes = signing_key_from_seed_bytes(&seed)?;
    let from_hex = signing_key_from_seed_hex(&format!("hex:{}", hex::encode(seed)))?;

    assert_eq!(
        from_bytes.verifying_key().as_bytes(),
        from_hex.verifying_key().as_bytes()
    );

    Ok(())
}

#[test]
fn configured_key_loader_rejects_malformed_material() {
    assert!(matches!(
        signing_key_from_seed_bytes(&[1_u8; 31]),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_bytes(&[1_u8; 33]),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_hex("not-hex"),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
    assert!(matches!(
        signing_key_from_seed_hex(&hex::encode([1_u8; 31])),
        Err(ArtifactSigningError::SigningKeyInvalid { .. })
    ));
}

#[test]
fn decision_receipts_sign_with_configured_key_material() -> Result<(), Box<dyn Error>> {
    let signing_key = generate_artifact_signing_key();
    let receipt = Receipt::new(
        "quarantine",
        "control-plane@prod",
        &json!({"target":"node-a","policy":"strict"}),
        &json!({"status":"accepted"}),
        Decision::Approved,
        "policy gate evaluated",
        vec!["ledger-001".to_string()],
        vec!["rule-A".to_string()],
        0.91,
        "franken-node trust release --incident INC-001",
    )?;

    let signed = sign_receipt(&receipt, &signing_key)?;
    let verified = verify_receipt(&signed, &signing_key.verifying_key())?;

    assert!(verified);

    Ok(())
}

#[test]
fn decision_receipt_cbor_preserves_confidence_bit_pattern() -> Result<(), Box<dyn Error>> {
    let signing_key = generate_artifact_signing_key();
    let confidence_bits = 0x3fcd_1d1d_1d1d_1d1e_u64;
    let receipt = Receipt::new(
        "quarantine",
        "control-plane@prod",
        &json!({"target":"node-a","policy":"strict"}),
        &json!({"status":"accepted"}),
        Decision::Approved,
        "policy gate evaluated",
        vec!["ledger-001".to_string()],
        vec!["rule-A".to_string()],
        f64::from_bits(confidence_bits),
        "franken-node trust release --incident INC-001",
    )?;

    let signed = sign_receipt(&receipt, &signing_key)?;
    let encoded = export_receipts_cbor(&[signed], &ReceiptQuery::default())?;
    let decoded = import_receipts_cbor(&encoded)?;

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].receipt.confidence.to_bits(), confidence_bits);

    Ok(())
}
