//! Runnable metamorphic relations for the claims compiler and scoreboard.

use frankenengine_node::claims::claim_compiler::{
    ClaimCompiler, CompilationResult, CompiledContract, CompilerConfig, ExternalClaim,
    ScoreboardConfig, ScoreboardPipeline, ScoreboardRejectionReason, ScoreboardSnapshot,
    ScoreboardUpdateResult, make_test_claim,
};

type TestResult = Result<(), String>;

#[derive(Clone, Copy)]
struct MetamorphicRelation {
    name: &'static str,
    pattern: &'static str,
    fault_sensitivity: u8,
    independence: u8,
    cost: u8,
    exercise: fn() -> TestResult,
}

const RELATIONS: &[MetamorphicRelation] = &[
    MetamorphicRelation {
        name: "normalization equivalence",
        pattern: "equivalence",
        fault_sensitivity: 4,
        independence: 4,
        cost: 2,
        exercise: mr_normalization_equivalence,
    },
    MetamorphicRelation {
        name: "freshness monotonicity",
        pattern: "inclusive/exclusive",
        fault_sensitivity: 5,
        independence: 4,
        cost: 2,
        exercise: mr_freshness_monotonicity,
    },
    MetamorphicRelation {
        name: "publish snapshot consistency",
        pattern: "equivalence",
        fault_sensitivity: 4,
        independence: 5,
        cost: 2,
        exercise: mr_publish_snapshot_consistency,
    },
];

#[test]
fn claims_compiler_metamorphic_relations_are_runnable() -> TestResult {
    let mut failures = Vec::new();

    for relation in RELATIONS {
        if relation.pattern.trim().is_empty() {
            failures.push(format!("{}: missing MR pattern", relation.name));
            continue;
        }

        let score =
            u16::from(relation.fault_sensitivity).saturating_mul(u16::from(relation.independence));
        let min_score = u16::from(relation.cost).saturating_mul(2);
        if score < min_score {
            failures.push(format!(
                "{}: MR score too weak: sensitivity={} independence={} cost={}",
                relation.name, relation.fault_sensitivity, relation.independence, relation.cost
            ));
            continue;
        }

        if let Err(error) = (relation.exercise)() {
            failures.push(format!("{}: {error}", relation.name));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("claims compiler MR failures: {failures:?}"))
    }
}

fn mr_normalization_equivalence() -> TestResult {
    let base = ExternalClaim {
        claim_id: "mr-normalized".to_string(),
        claim_text: "Normalization-preserving claim".to_string(),
        evidence_uris: vec![
            "https://evidence.example.com/mr-normalized".to_string(),
            "urn:claims:mr-normalized".to_string(),
        ],
        source_id: "claims-source".to_string(),
    };
    let transformed = ExternalClaim {
        source_id: " \tclaims-source\n ".to_string(),
        evidence_uris: vec![
            "  https://evidence.example.com/mr-normalized\t".to_string(),
            "\nurn:claims:mr-normalized  ".to_string(),
        ],
        ..base.clone()
    };
    let compiler = compiler_at(10_000);
    let base_contract = compiled_contract_from(&compiler, &base, "base normalized claim")?;
    let transformed_contract =
        compiled_contract_from(&compiler, &transformed, "transformed normalized claim")?;

    assert_eq_string(
        base_contract.source_id.as_str(),
        transformed_contract.source_id.as_str(),
        "normalized source id",
    )?;
    if base_contract.evidence_uris != transformed_contract.evidence_uris {
        return Err(format!(
            "normalized evidence URIs diverged: base={:?} transformed={:?}",
            base_contract.evidence_uris, transformed_contract.evidence_uris
        ));
    }
    assert_eq_string(
        base_contract.contract_digest.as_str(),
        transformed_contract.contract_digest.as_str(),
        "normalized contract digest",
    )?;
    assert_eq_string(
        base_contract.signature.as_str(),
        transformed_contract.signature.as_str(),
        "normalized signature",
    )
}

fn mr_freshness_monotonicity() -> TestResult {
    let contract = compiled_contract("mr-freshness", 10_000)?;

    assert_published(
        scoreboard_at(69_999).publish("snap-fresh-before", std::slice::from_ref(&contract)),
        1,
        "one millisecond before freshness boundary",
    )?;
    assert_snapshot_some(
        scoreboard_at(69_999).build_snapshot("snap-fresh-before", std::slice::from_ref(&contract)),
        1,
        "snapshot before freshness boundary",
    )?;

    for (now_epoch_ms, label) in [
        (70_000, "exact freshness boundary"),
        (70_001, "after freshness boundary"),
    ] {
        assert_scoreboard_rejected(
            scoreboard_at(now_epoch_ms).publish("snap-stale", std::slice::from_ref(&contract)),
            ScoreboardRejectionReason::StaleEvidence,
            label,
        )?;
        assert_snapshot_none(
            scoreboard_at(now_epoch_ms)
                .build_snapshot("snap-stale", std::slice::from_ref(&contract)),
            label,
        )?;
    }

    Ok(())
}

fn mr_publish_snapshot_consistency() -> TestResult {
    let fresh_one = vec![compiled_contract("mr-consistency-one", 20_000)?];
    assert_publish_snapshot_consistent(
        scoreboard_at(20_000),
        "snap-consistency-one",
        &fresh_one,
        ExpectedConsistency::Accept { entry_count: 1 },
    )?;

    let fresh_two = vec![
        compiled_contract("mr-consistency-a", 20_000)?,
        compiled_contract("mr-consistency-b", 20_000)?,
    ];
    assert_publish_snapshot_consistent(
        scoreboard_at(20_000),
        "snap-consistency-two",
        &fresh_two,
        ExpectedConsistency::Accept { entry_count: 2 },
    )?;

    let empty: Vec<CompiledContract> = Vec::new();
    assert_publish_snapshot_consistent(
        scoreboard_at(20_000),
        "snap-consistency-empty",
        &empty,
        ExpectedConsistency::Accept { entry_count: 0 },
    )?;

    let mut tampered = compiled_contract("mr-consistency-tampered", 20_000)?;
    tampered.signature.clear();
    assert_publish_snapshot_consistent(
        scoreboard_at(20_000),
        "snap-consistency-tampered",
        &[tampered],
        ExpectedConsistency::Reject {
            reason: ScoreboardRejectionReason::SignatureInvalid,
        },
    )?;

    assert_publish_snapshot_consistent(
        limited_scoreboard_at(20_000, 1),
        "snap-consistency-rate",
        &fresh_two,
        ExpectedConsistency::Reject {
            reason: ScoreboardRejectionReason::RateLimited,
        },
    )
}

enum ExpectedConsistency {
    Accept { entry_count: usize },
    Reject { reason: ScoreboardRejectionReason },
}

fn assert_publish_snapshot_consistent(
    scoreboard: ScoreboardPipeline,
    snapshot_id: &str,
    contracts: &[CompiledContract],
    expected: ExpectedConsistency,
) -> TestResult {
    let publish = scoreboard.publish(snapshot_id, contracts);
    let snapshot = scoreboard.build_snapshot(snapshot_id, contracts);

    match expected {
        ExpectedConsistency::Accept { entry_count } => {
            assert_published(publish, entry_count, snapshot_id)?;
            assert_snapshot_some(snapshot, entry_count, snapshot_id)
        }
        ExpectedConsistency::Reject { reason } => {
            assert_scoreboard_rejected(publish, reason, snapshot_id)?;
            assert_snapshot_none(snapshot, snapshot_id)
        }
    }
}

fn compiler_at(now_epoch_ms: u64) -> ClaimCompiler {
    ClaimCompiler::new(CompilerConfig::new(
        "claims-mr-signer",
        "claims-mr-material",
        now_epoch_ms,
    ))
}

fn scoreboard_at(now_epoch_ms: u64) -> ScoreboardPipeline {
    ScoreboardPipeline::new(ScoreboardConfig::new(
        "claims-mr-signer",
        "claims-mr-material",
        now_epoch_ms,
        60_000,
    ))
}

fn limited_scoreboard_at(now_epoch_ms: u64, max_contracts: usize) -> ScoreboardPipeline {
    ScoreboardPipeline::new(
        ScoreboardConfig::new(
            "claims-mr-signer",
            "claims-mr-material",
            now_epoch_ms,
            60_000,
        )
        .with_max_contracts_per_publish(max_contracts),
    )
}

fn compiled_contract(
    claim_id: &str,
    compiled_at_epoch_ms: u64,
) -> Result<CompiledContract, String> {
    let claim = make_test_claim(claim_id, "claims-mr-source");
    compiled_contract_from(
        &compiler_at(compiled_at_epoch_ms),
        &claim,
        "compiled contract fixture",
    )
}

fn compiled_contract_from(
    compiler: &ClaimCompiler,
    claim: &ExternalClaim,
    context: &str,
) -> Result<CompiledContract, String> {
    match compiler.compile(claim) {
        CompilationResult::Compiled { contract, .. } => Ok(contract),
        CompilationResult::Rejected {
            reason, error_code, ..
        } => Err(format!(
            "{context}: expected compiled contract, got {reason:?}/{error_code}"
        )),
    }
}

fn assert_published(
    result: ScoreboardUpdateResult,
    expected_entry_count: usize,
    context: &str,
) -> TestResult {
    match result {
        ScoreboardUpdateResult::Published { entry_count, .. }
            if entry_count == expected_entry_count =>
        {
            Ok(())
        }
        ScoreboardUpdateResult::Published { entry_count, .. } => Err(format!(
            "{context}: expected {expected_entry_count} entries, got {entry_count}"
        )),
        ScoreboardUpdateResult::Rejected { reason, error_code } => Err(format!(
            "{context}: expected published snapshot, got {reason:?}/{error_code}"
        )),
    }
}

fn assert_scoreboard_rejected(
    result: ScoreboardUpdateResult,
    expected_reason: ScoreboardRejectionReason,
    context: &str,
) -> TestResult {
    match result {
        ScoreboardUpdateResult::Rejected { reason, .. } if reason == expected_reason => Ok(()),
        ScoreboardUpdateResult::Rejected { reason, error_code } => Err(format!(
            "{context}: expected {expected_reason:?}, got {reason:?}/{error_code}"
        )),
        ScoreboardUpdateResult::Published { entry_count, .. } => Err(format!(
            "{context}: expected rejection {expected_reason:?}, got published {entry_count} entries"
        )),
    }
}

fn assert_snapshot_some(
    snapshot: Option<ScoreboardSnapshot>,
    expected_entry_count: usize,
    context: &str,
) -> TestResult {
    let snapshot =
        snapshot.ok_or_else(|| format!("{context}: expected snapshot build to succeed"))?;
    if snapshot.entries.len() == expected_entry_count {
        Ok(())
    } else {
        Err(format!(
            "{context}: expected snapshot with {expected_entry_count} entries, got {}",
            snapshot.entries.len()
        ))
    }
}

fn assert_snapshot_none(snapshot: Option<ScoreboardSnapshot>, context: &str) -> TestResult {
    if snapshot.is_none() {
        Ok(())
    } else {
        Err(format!("{context}: expected snapshot build to reject"))
    }
}

fn assert_eq_string(actual: &str, expected: &str, label: &str) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected `{expected}`, got `{actual}`"))
    }
}
