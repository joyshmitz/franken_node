//! Threshold signature verification security tests (bd-35q1).
//!
//! Verifies quorum enforcement, partial rejection, duplicate handling,
//! unknown signer rejection, and stable failure reasons.

use frankenengine_node::security::threshold_sig::*;

fn keys(n: u32) -> Vec<SignerKey> {
    (0..n)
        .map(|i| SignerKey {
            key_id: format!("signer-{i}"),
            public_key_hex: format!("pubkey_{i:04x}"),
        })
        .collect()
}

fn config(k: u32, n: u32) -> ThresholdConfig {
    ThresholdConfig {
        threshold: k,
        total_signers: n,
        signer_keys: keys(n),
    }
}

fn artifact_with_sigs(cfg: &ThresholdConfig, hash: &str, count: usize) -> PublicationArtifact {
    PublicationArtifact {
        artifact_id: "art-test".into(),
        connector_id: "conn-test".into(),
        content_hash: hash.to_string(),
        signatures: cfg.signer_keys.iter().take(count).map(|k| sign(k, hash)).collect(),
    }
}

#[test]
fn quorum_met_admits() {
    let cfg = config(2, 3);
    let art = artifact_with_sigs(&cfg, "h1", 2);
    let result = verify_threshold(&cfg, &art, "t1", "ts");
    assert!(result.verified);
}

#[test]
fn partial_set_rejected() {
    let cfg = config(2, 3);
    let art = artifact_with_sigs(&cfg, "h2", 1);
    let result = verify_threshold(&cfg, &art, "t2", "ts");
    assert!(!result.verified);
}

#[test]
fn empty_set_rejected() {
    let cfg = config(2, 3);
    let art = artifact_with_sigs(&cfg, "h3", 0);
    let result = verify_threshold(&cfg, &art, "t3", "ts");
    assert!(!result.verified);
}

#[test]
fn unknown_signer_ignored() {
    let cfg = config(2, 3);
    let mut art = artifact_with_sigs(&cfg, "h4", 1);
    art.signatures.push(PartialSignature {
        signer_id: "rogue".into(),
        key_id: "rogue-key".into(),
        signature_hex: "0000000000000000".into(),
    });
    let result = verify_threshold(&cfg, &art, "t4", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 1);
}

#[test]
fn invalid_sig_ignored() {
    let cfg = config(2, 3);
    let mut art = artifact_with_sigs(&cfg, "h5", 1);
    art.signatures.push(PartialSignature {
        signer_id: "signer-1".into(),
        key_id: "signer-1".into(),
        signature_hex: "ffffffffffffffff".into(),
    });
    let result = verify_threshold(&cfg, &art, "t5", "ts");
    assert!(!result.verified);
}

#[test]
fn duplicate_counted_once() {
    let cfg = config(2, 3);
    let mut art = artifact_with_sigs(&cfg, "h6", 1);
    art.signatures.push(sign(&cfg.signer_keys[0], "h6"));
    let result = verify_threshold(&cfg, &art, "t6", "ts");
    assert!(!result.verified);
    assert_eq!(result.valid_signatures, 1);
}

#[test]
fn failure_reason_is_stable() {
    let cfg = config(3, 3);
    let art = artifact_with_sigs(&cfg, "h7", 1);
    let r1 = verify_threshold(&cfg, &art, "t7a", "ts");
    let r2 = verify_threshold(&cfg, &art, "t7b", "ts");
    assert_eq!(r1.failure_reason, r2.failure_reason);
}

#[test]
fn trace_id_preserved() {
    let cfg = config(1, 3);
    let art = artifact_with_sigs(&cfg, "h8", 1);
    let result = verify_threshold(&cfg, &art, "trace-abc", "ts");
    assert_eq!(result.trace_id, "trace-abc");
}

#[test]
fn invalid_config_rejected() {
    let mut cfg = config(5, 3);
    cfg.threshold = 5;
    let art = artifact_with_sigs(&config(2, 3), "h9", 2);
    let result = verify_threshold(&cfg, &art, "t9", "ts");
    assert!(!result.verified);
}
