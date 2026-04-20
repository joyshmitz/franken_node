use super::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleError, fixture_incident_events,
    generate_replay_bundle, replay_bundle_adversarial_fuzz_one,
    replay_bundle_batch_adversarial_fuzz_one,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayBundleAdversarialExpectedError {
    NegativeCastOffset,
    ZeroLengthChunk,
    DuplicateBundleId,
    TrailingGarbage,
    TruncatedFinalChunk,
    TimestampInFuture,
    BundleIdMismatch,
}

impl ReplayBundleAdversarialExpectedError {
    #[must_use]
    pub fn matches_error(self, error: &ReplayBundleError) -> bool {
        matches!(
            (self, error),
            (
                Self::NegativeCastOffset,
                ReplayBundleError::NegativeCastOffset { path, value },
            ) if path == "$.chunks[0].chunk_index" && *value == -1
        ) || matches!(
            (self, error),
            (
                Self::ZeroLengthChunk,
                ReplayBundleError::ZeroLengthChunk { chunk_index: 0 },
            )
        ) || matches!(
            (self, error),
            (
                Self::DuplicateBundleId,
                ReplayBundleError::DuplicateBundleId { .. },
            )
        ) || matches!(
            (self, error),
            (Self::TrailingGarbage, ReplayBundleError::TrailingGarbage)
        ) || matches!(
            (self, error),
            (
                Self::TruncatedFinalChunk,
                ReplayBundleError::TruncatedFinalChunk,
            )
        ) || matches!(
            (self, error),
            (
                Self::TimestampInFuture,
                ReplayBundleError::TimestampInFuture { path, timestamp },
            ) if path == "$.created_at" && timestamp.starts_with("9999-12-31T23:59:59")
        ) || matches!(
            (self, error),
            (Self::BundleIdMismatch, ReplayBundleError::BundleIdMismatch,)
        )
    }
}

#[derive(Debug, Clone)]
pub enum ReplayBundleAdversarialTarget {
    Single(Vec<u8>),
    Batch(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ReplayBundleAdversarialCase {
    pub name: &'static str,
    pub target: ReplayBundleAdversarialTarget,
    pub expected_error: ReplayBundleAdversarialExpectedError,
}

impl ReplayBundleAdversarialCase {
    pub fn run(&self) -> Result<(), ReplayBundleError> {
        match &self.target {
            ReplayBundleAdversarialTarget::Single(input) => {
                replay_bundle_adversarial_fuzz_one(input)
            }
            ReplayBundleAdversarialTarget::Batch(input) => {
                replay_bundle_batch_adversarial_fuzz_one(input)
            }
        }
    }
}

#[must_use]
pub fn replay_bundle_adversarial_fuzz_corpus() -> Vec<ReplayBundleAdversarialCase> {
    let negative_offset = {
        let bundle = fixture_bundle("INC-FUZZ-NEGATIVE-OFFSET");
        let mut value = bundle_value(&bundle);
        value["chunks"][0]["chunk_index"] = json!(-1);
        ReplayBundleAdversarialCase {
            name: "negative_cast_offsets",
            target: ReplayBundleAdversarialTarget::Single(json_bytes(&value)),
            expected_error: ReplayBundleAdversarialExpectedError::NegativeCastOffset,
        }
    };

    let zero_length_chunk = {
        let bundle = fixture_bundle("INC-FUZZ-ZERO-CHUNK");
        let mut value = bundle_value(&bundle);
        value["chunks"][0]["event_count"] = json!(0);
        value["chunks"][0]["events"] = json!([]);
        ReplayBundleAdversarialCase {
            name: "zero_length_chunks",
            target: ReplayBundleAdversarialTarget::Single(json_bytes(&value)),
            expected_error: ReplayBundleAdversarialExpectedError::ZeroLengthChunk,
        }
    };

    let duplicate_bundle_ids = {
        let bundle = fixture_bundle("INC-FUZZ-DUPLICATE-ID");
        ReplayBundleAdversarialCase {
            name: "duplicated_bundle_ids",
            target: ReplayBundleAdversarialTarget::Batch(
                serde_json::to_vec(&vec![bundle.clone(), bundle]).expect("bundle batch bytes"),
            ),
            expected_error: ReplayBundleAdversarialExpectedError::DuplicateBundleId,
        }
    };

    let trailing_garbage = {
        let bundle = fixture_bundle("INC-FUZZ-TRAILING-GARBAGE");
        let mut input = bundle_bytes(&bundle);
        input.extend_from_slice(b"\n{\"garbage\":true}");
        ReplayBundleAdversarialCase {
            name: "trailing_garbage",
            target: ReplayBundleAdversarialTarget::Single(input),
            expected_error: ReplayBundleAdversarialExpectedError::TrailingGarbage,
        }
    };

    let truncated_final_chunk = {
        let bundle = fixture_bundle("INC-FUZZ-TRUNCATED-FINAL-CHUNK");
        let mut input = bundle_bytes(&bundle);
        input.truncate(input.len().saturating_sub(1));
        ReplayBundleAdversarialCase {
            name: "truncated_final_chunk",
            target: ReplayBundleAdversarialTarget::Single(input),
            expected_error: ReplayBundleAdversarialExpectedError::TruncatedFinalChunk,
        }
    };

    let timestamp_in_future = {
        let events = vec![RawEvent::new(
            "9999-12-31T23:59:59.000000Z",
            EventType::StateChange,
            json!({"future": true}),
        )];
        let bundle = generate_replay_bundle("INC-FUZZ-FUTURE-TIMESTAMP", &events)
            .expect("future-timestamp bundle corpus");
        ReplayBundleAdversarialCase {
            name: "timestamp_in_future",
            target: ReplayBundleAdversarialTarget::Single(bundle_bytes(&bundle)),
            expected_error: ReplayBundleAdversarialExpectedError::TimestampInFuture,
        }
    };

    let bundle_id_mismatch = {
        let bundle = fixture_bundle("INC-FUZZ-BUNDLE-ID-MISMATCH");
        let mut value = bundle_value(&bundle);
        value["bundle_id"] = json!(Uuid::nil().to_string());
        ReplayBundleAdversarialCase {
            name: "bundle_id_recomputed_hash_mismatch",
            target: ReplayBundleAdversarialTarget::Single(json_bytes(&value)),
            expected_error: ReplayBundleAdversarialExpectedError::BundleIdMismatch,
        }
    };

    vec![
        negative_offset,
        zero_length_chunk,
        duplicate_bundle_ids,
        trailing_garbage,
        truncated_final_chunk,
        timestamp_in_future,
        bundle_id_mismatch,
    ]
}

fn fixture_bundle(incident_id: &str) -> ReplayBundle {
    generate_replay_bundle(incident_id, &fixture_incident_events(incident_id))
        .expect("fixture bundle")
}

fn bundle_value(bundle: &ReplayBundle) -> Value {
    serde_json::to_value(bundle).expect("bundle json value")
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("fuzz corpus bytes")
}

fn bundle_bytes(bundle: &ReplayBundle) -> Vec<u8> {
    serde_json::to_vec(bundle).expect("bundle bytes")
}
