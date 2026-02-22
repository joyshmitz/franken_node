#[path = "../src/connector/vef_execution_receipt.rs"]
pub mod vef_execution_receipt;

mod connector {
    pub use super::vef_execution_receipt;
}

#[path = "../src/vef/receipt_chain.rs"]
mod receipt_chain;

#[path = "../src/vef/proof_scheduler.rs"]
mod proof_scheduler;

#[path = "../src/vef/proof_service.rs"]
mod proof_service;

#[cfg(test)]
mod tests {
    use super::proof_scheduler::{SchedulerPolicy, VefProofScheduler};
    use super::proof_service::{
        ProofBackendId, ProofInputEnvelope, ProofServiceConfig, VefProofService, error_codes,
    };
    use super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use super::vef_execution_receipt::{
        ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;

    fn receipt(action_type: ExecutionActionType, n: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());
        capability_context.insert("capability".to_string(), format!("capability-{n}"));
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type,
            capability_context,
            actor_identity: format!("actor-{n}"),
            artifact_identity: format!("artifact-{n}"),
            policy_snapshot_hash: format!("sha256:{n:064x}"),
            timestamp_millis: 1_706_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["w-a".to_string(), "w-b".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    fn build_input() -> ProofInputEnvelope {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for (idx, action) in [
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
        ]
        .into_iter()
        .enumerate()
        {
            chain
                .append(
                    receipt(action, idx as u64),
                    1_706_000_100_000 + idx as u64,
                    "trace-test",
                )
                .expect("append receipt");
        }

        let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
            max_receipts_per_window: 2,
            ..SchedulerPolicy::default()
        });
        let windows = scheduler
            .select_windows(
                chain.entries(),
                chain.checkpoints(),
                1_706_000_200_000,
                "trace-test",
            )
            .expect("select windows");
        let queued = scheduler
            .enqueue_windows(&windows, 1_706_000_200_010)
            .expect("queue windows");
        let window = windows[0].clone();
        let job = scheduler
            .jobs()
            .get(&queued[0])
            .expect("job exists")
            .clone();

        ProofInputEnvelope::from_scheduler_job(
            &job,
            &window,
            chain.entries(),
            chain.checkpoints(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            vec!["predicate.window.coverage".to_string()],
            BTreeMap::new(),
        )
        .expect("build proof input")
    }

    #[test]
    fn proof_service_round_trip_default_backend() {
        let input = build_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let proof = service
            .generate_proof(&input, None, 1_706_000_300_000)
            .expect("generate proof");
        service.verify_proof(&input, &proof).expect("verify proof");
    }

    #[test]
    fn proof_service_backend_swap_keeps_verification_semantics() {
        let input = build_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());

        let proof_a = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_706_000_300_100,
            )
            .expect("proof A");
        let proof_b = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_706_000_300_200,
            )
            .expect("proof B");

        assert_ne!(proof_a.proof_material, proof_b.proof_material);
        service.verify_proof(&input, &proof_a).expect("verify A");
        service.verify_proof(&input, &proof_b).expect("verify B");
    }

    #[test]
    fn proof_service_classifies_timeout_failure() {
        let mut input = build_input();
        input
            .metadata
            .insert("simulate_failure".to_string(), "timeout".to_string());
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let err = service
            .generate_proof(&input, None, 1_706_000_300_300)
            .expect_err("timeout should fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_TIMEOUT);
    }
}
