use frankenengine_node::control_plane::audience_token::{
    ActionScope, AudienceBoundToken, TokenChain, TokenId, TokenValidator,
};

#[test]
fn test_multi_delegation() {
    let now_ms = 1000;

    let root = AudienceBoundToken {
        token_id: TokenId("root".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceX".into(), "ServiceY".into()],
        capabilities: vec![
            ActionScope::Migrate,
        ]
        .into_iter()
        .collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-A".into(),
        parent_token_hash: None,
        signature: "sig-A".into(),
        max_delegation_depth: 5,
    };

    let token_b = AudienceBoundToken {
        token_id: TokenId("B".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceX".into()],
        capabilities: vec![ActionScope::Migrate].into_iter().collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-B".into(),
        parent_token_hash: Some(root.hash()),
        signature: "sig-B".into(),
        max_delegation_depth: 4,
    };

    let token_d = AudienceBoundToken {
        token_id: TokenId("D".into()),
        issuer: "issuer".into(),
        audience: vec!["ServiceY".into()],
        capabilities: vec![ActionScope::Migrate].into_iter().collect(),
        issued_at: now_ms,
        expires_at: now_ms + 10000,
        nonce: "nonce-D".into(),
        parent_token_hash: Some(root.hash()),
        signature: "sig-D".into(),
        max_delegation_depth: 4,
    };

    let mut chain_ab = TokenChain::new(root.clone()).unwrap();
    chain_ab.append(token_b.clone()).unwrap();

    let mut chain_ad = TokenChain::new(root.clone()).unwrap();
    chain_ad.append(token_d.clone()).unwrap();

    let mut validator = TokenValidator::new(1);

    // X uses A -> B
    let res = validator.verify_chain(&chain_ab, "ServiceX", now_ms, "trace-1");
    assert!(res.is_ok(), "X should pass");

    // Y uses A -> D
    let res2 = validator.verify_chain(&chain_ad, "ServiceY", now_ms, "trace-2");
    assert!(res2.is_ok(), "Y should pass, but will fail if nonce-A is recorded!");
}
