use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use frankenengine_node::vef::proof_verifier::{
    ComplianceProof, PolicyPredicate, VerificationGate, VerificationGateConfig, VerificationRequest,
};

const NOW: u64 = 1_701_000_000_000;

fn predicate() -> PolicyPredicate {
    PolicyPredicate {
        predicate_id: "pred-net-001".to_string(),
        action_class: "network_access".to_string(),
        max_proof_age_millis: 600_000,
        min_confidence: 90,
        require_witnesses: true,
        min_witness_count: 2,
        policy_version_hash: "sha256:policy-v1".to_string(),
    }
}

fn proof(index: usize) -> ComplianceProof {
    ComplianceProof {
        proof_id: format!("proof-{index:03}"),
        action_class: "network_access".to_string(),
        proof_hash: format!("sha256:abc123-{index:03}"),
        confidence: 95,
        generated_at_millis: NOW - 60_000,
        expires_at_millis: NOW + 600_000,
        witness_references: vec!["w-a".to_string(), "w-b".to_string(), "w-c".to_string()],
        policy_version_hash: "sha256:policy-v1".to_string(),
        trace_id: format!("trace-test-{index:03}"),
    }
}

fn request(index: usize) -> VerificationRequest {
    let proof = proof(index);
    VerificationRequest {
        request_id: format!("req-{}", proof.proof_id),
        trace_id: proof.trace_id.clone(),
        proof,
        now_millis: NOW,
    }
}

fn gate() -> VerificationGate {
    let mut gate = VerificationGate::new(VerificationGateConfig::default());
    gate.register_predicate(predicate());
    gate
}

fn benchmark_verification_gate_batch(c: &mut Criterion) {
    let requests = (0..64).map(request).collect::<Vec<_>>();

    c.bench_function("verification_gate_batch_allow", |b| {
        b.iter_batched(
            gate,
            |mut gate| {
                let reports = gate.verify_batch(black_box(&requests));
                black_box(reports);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_verification_gate_batch);
criterion_main!(benches);
