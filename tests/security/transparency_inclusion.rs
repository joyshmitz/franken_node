//! Transparency log inclusion proof security tests (bd-1z9s).
//!
//! Verifies that install/update fails without valid inclusion proof,
//! log roots must be pinned, and verification is deterministic.

use frankenengine_node::supply_chain::transparency_verifier::*;

fn pinned_policy(root: &str) -> TransparencyPolicy {
    TransparencyPolicy {
        required: true,
        pinned_roots: vec![LogRoot {
            tree_size: 4,
            root_hash: root.to_string(),
        }],
    }
}

#[test]
fn install_fails_without_proof() {
    let policy = TransparencyPolicy {
        required: true,
        pinned_roots: vec![],
    };
    let receipt = verify_inclusion(&policy, None, "hash", "c1", "a1", "t1", "ts");
    assert!(!receipt.verified);
    assert_eq!(receipt.failure_reason, Some(ProofFailure::ProofMissing));
}

#[test]
fn install_succeeds_with_valid_proof() {
    let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
    let policy = pinned_policy(&root);
    let receipt = verify_inclusion(
        &policy, Some(&proofs[0]), &proofs[0].leaf_hash,
        "c1", "a1", "t2", "ts",
    );
    assert!(receipt.verified);
}

#[test]
fn update_fails_with_unpinned_root() {
    let (_, proofs) = build_test_tree(&["a", "b", "c", "d"]);
    let policy = pinned_policy("wrong_root");
    let receipt = verify_inclusion(
        &policy, Some(&proofs[0]), &proofs[0].leaf_hash,
        "c1", "a1", "t3", "ts",
    );
    assert!(!receipt.verified);
    assert!(matches!(receipt.failure_reason, Some(ProofFailure::RootNotPinned { .. })));
}

#[test]
fn leaf_mismatch_blocks_install() {
    let (root, proofs) = build_test_tree(&["a", "b"]);
    let policy = pinned_policy(&root);
    let receipt = verify_inclusion(
        &policy, Some(&proofs[0]), "wrong_hash",
        "c1", "a1", "t4", "ts",
    );
    assert!(!receipt.verified);
    assert!(matches!(receipt.failure_reason, Some(ProofFailure::LeafMismatch { .. })));
}

#[test]
fn tampered_path_fails() {
    let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
    let policy = pinned_policy(&root);
    let mut bad_proof = proofs[0].clone();
    bad_proof.audit_path[0] = "tampered".into();
    let receipt = verify_inclusion(
        &policy, Some(&bad_proof), &bad_proof.leaf_hash,
        "c1", "a1", "t5", "ts",
    );
    assert!(!receipt.verified);
}

#[test]
fn verification_replayable() {
    let (root, proofs) = build_test_tree(&["a", "b"]);
    let policy = pinned_policy(&root);
    let r1 = verify_inclusion(
        &policy, Some(&proofs[0]), &proofs[0].leaf_hash,
        "c1", "a1", "t6a", "ts",
    );
    let r2 = verify_inclusion(
        &policy, Some(&proofs[0]), &proofs[0].leaf_hash,
        "c1", "a1", "t6b", "ts",
    );
    assert_eq!(r1.verified, r2.verified);
}

#[test]
fn optional_proof_passes_when_absent() {
    let policy = TransparencyPolicy {
        required: false,
        pinned_roots: vec![],
    };
    let receipt = verify_inclusion(&policy, None, "hash", "c1", "a1", "t7", "ts");
    assert!(receipt.verified);
}

#[test]
fn trace_id_preserved() {
    let (root, proofs) = build_test_tree(&["a", "b"]);
    let policy = pinned_policy(&root);
    let receipt = verify_inclusion(
        &policy, Some(&proofs[0]), &proofs[0].leaf_hash,
        "c1", "a1", "trace-xyz", "ts",
    );
    assert_eq!(receipt.trace_id, "trace-xyz");
}
