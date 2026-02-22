//! Conformance tests for bd-3g4k: VEF receipt-chain integrity contract.
//!
//! These tests validate deterministic chain linkage, checkpoint reproducibility,
//! fail-closed tamper detection, and crash-recovery semantics.

#[path = "../../crates/franken-node/src/connector/vef_execution_receipt.rs"]
pub mod vef_execution_receipt;

pub mod connector {
    pub use super::vef_execution_receipt;
}

#[path = "../../crates/franken-node/src/vef/receipt_chain.rs"]
mod receipt_chain;

#[cfg(test)]
mod tests {
    use super::connector::vef_execution_receipt::{ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION};
    use super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use std::collections::BTreeMap;

    fn receipt(action: ExecutionActionType, n: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());
        capability_context.insert("capability".to_string(), format!("cap-{n}"));
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type: action,
            capability_context,
            actor_identity: format!("actor-{n}"),
            artifact_identity: format!("artifact-{n}"),
            policy_snapshot_hash: format!("sha256:{n:064x}"),
            timestamp_millis: 1_700_100_000_000 + n,
            sequence_number: n,
            witness_references: vec!["w1".to_string(), "w2".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    #[test]
    fn deterministic_chain_hashes_across_rebuilds() {
        let cfg = ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        };
        let mut a = ReceiptChain::new(cfg);
        let mut b = ReceiptChain::new(cfg);

        for n in 0..4 {
            a.append(receipt(ExecutionActionType::NetworkAccess, n), 1_700_100_000_000 + n, "trace-a")
                .unwrap();
            b.append(receipt(ExecutionActionType::NetworkAccess, n), 1_700_100_000_000 + n, "trace-b")
                .unwrap();
        }

        assert_eq!(a.entries(), b.entries());
        assert_eq!(a.checkpoints(), b.checkpoints());
    }

    #[test]
    fn checkpoint_reproducibility_holds() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for n in 0..4 {
            chain
                .append(
                    receipt(ExecutionActionType::FilesystemOperation, n),
                    1_700_100_010_000 + n,
                    "trace-checkpoint",
                )
                .unwrap();
        }
        let first = chain.checkpoints().to_vec();
        let resumed = ReceiptChain::resume_from_snapshot(
            chain.config,
            chain.entries().to_vec(),
            first.clone(),
        )
        .unwrap();
        assert_eq!(resumed.checkpoints(), first.as_slice());
    }

    #[test]
    fn tampered_entry_is_rejected_fail_closed() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for n in 0..3 {
            chain
                .append(
                    receipt(ExecutionActionType::ProcessSpawn, n),
                    1_700_100_020_000 + n,
                    "trace-tamper",
                )
                .unwrap();
        }
        let mut tampered = chain.entries().to_vec();
        tampered[1].receipt.actor_identity = "rogue-actor".to_string();
        let err = ReceiptChain::verify_entries_and_checkpoints(&tampered, chain.checkpoints())
            .unwrap_err();
        assert_eq!(err.code, "ERR-VEF-CHAIN-TAMPER");
    }

    #[test]
    fn resume_after_checkpoint_preserves_integrity() {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for n in 0..5 {
            chain
                .append(
                    receipt(ExecutionActionType::SecretAccess, n),
                    1_700_100_030_000 + n,
                    "trace-resume",
                )
                .unwrap();
        }
        let recovered = ReceiptChain::resume_from_snapshot(
            chain.config,
            chain.entries().to_vec(),
            chain.checkpoints().to_vec(),
        )
        .unwrap();
        recovered.verify_integrity().unwrap();
    }
}
