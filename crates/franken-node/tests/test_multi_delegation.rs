use frankenengine_node::control_plane::audience_token::{
    ActionScope, AudienceBoundToken, TokenChain, TokenId, TokenValidator,
};

use ed25519_dalek::{Signer, SigningKey};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[14_u8; 32])
}

fn sign_token(token: &mut AudienceBoundToken) {
    token.signature = hex::encode(signing_key().sign(&token.signature_preimage()).to_bytes());
}

fn token_validator(epoch_id: u64) -> TokenValidator {
    TokenValidator::new(epoch_id).with_trusted_issuer_key("issuer", signing_key().verifying_key())
}

#[test]
fn test_multi_delegation() {
    let now_ms = 1000;

    let mut root = AudienceBoundToken {
        token_id: TokenId("root".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceX".into(), "ServiceY".into()],
        capabilities: vec![ActionScope::Migrate].into_iter().collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-A".into(),
        parent_token_hash: None,
        signature: String::new(),
        max_delegation_depth: 5,
    };
    sign_token(&mut root);

    let mut token_b = AudienceBoundToken {
        token_id: TokenId("B".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceX".into()],
        capabilities: vec![ActionScope::Migrate].into_iter().collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-B".into(),
        parent_token_hash: Some(root.hash()),
        signature: String::new(),
        max_delegation_depth: 4,
    };
    sign_token(&mut token_b);

    let mut token_d = AudienceBoundToken {
        token_id: TokenId("D".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceY".into()],
        capabilities: vec![ActionScope::Migrate].into_iter().collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-D".into(),
        parent_token_hash: Some(root.hash()),
        signature: String::new(),
        max_delegation_depth: 4,
    };
    sign_token(&mut token_d);

    let mut chain_ab = TokenChain::new(root.clone()).unwrap();
    chain_ab.append(token_b.clone()).unwrap();

    let mut chain_ad = TokenChain::new(root.clone()).unwrap();
    chain_ad.append(token_d.clone()).unwrap();

    let mut validator = token_validator(1);

    // X uses A -> B
    let res = validator.verify_chain(&chain_ab, "ServiceX", now_ms, "trace-1");
    assert!(res.is_ok(), "X should pass");

    // Y uses A -> D
    let res2 = validator.verify_chain(&chain_ad, "ServiceY", now_ms, "trace-2");
    assert!(
        res2.is_ok(),
        "Y should pass, but will fail if nonce-A is recorded!"
    );
}
