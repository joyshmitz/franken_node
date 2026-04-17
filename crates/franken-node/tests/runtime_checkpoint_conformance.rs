use std::collections::BTreeMap;

use frankenengine_node::runtime::bounded_mask::{CancellationState, CapabilityContext};
use frankenengine_node::runtime::checkpoint::{
    CHECKPOINT_CONTRACT_VIOLATION, CHECKPOINT_DECISION_STREAM_APPEND,
    CHECKPOINT_HASH_CHAIN_FAILURE, CHECKPOINT_IDEMPOTENT_REUSE, CHECKPOINT_MISSING,
    CHECKPOINT_RESTORE, CHECKPOINT_SAVE, CheckpointBackend, CheckpointContract, CheckpointError,
    CheckpointRecord, CheckpointWriter, FN_CK_001_CHECKPOINT_SAVE, FN_CK_002_CHECKPOINT_RESTORE,
    FN_CK_003_HASH_CHAIN_FAILURE, FN_CK_005_IDEMPOTENT_REUSE, FN_CK_007_CONTRACT_VIOLATION,
    FN_CK_008_DECISION_STREAM_APPEND,
};
use frankenengine_node::security::constant_time::ct_eq;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeProgress {
    phase: String,
    cursor: u64,
    flags: BTreeMap<String, bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StringCursorProgress {
    cursor: String,
}

#[derive(Debug, Clone, Default)]
struct ConformanceCheckpointBackend {
    records: BTreeMap<String, Vec<CheckpointRecord>>,
    fail_next_save: Option<String>,
    fail_loads: Option<String>,
}

impl ConformanceCheckpointBackend {
    fn fail_next_save(&mut self, detail: impl Into<String>) {
        self.fail_next_save = Some(detail.into());
    }

    fn fail_loads(&mut self, detail: impl Into<String>) {
        self.fail_loads = Some(detail.into());
    }

    fn record_count(&self, orchestration_id: &str) -> usize {
        self.records
            .get(orchestration_id)
            .map(Vec::len)
            .unwrap_or(0)
    }

    fn corrupt_progress_state_json(
        &mut self,
        orchestration_id: &str,
        index: usize,
        replacement_json: &str,
    ) {
        if let Some(records) = self.records.get_mut(orchestration_id)
            && let Some(record) = records.get_mut(index)
        {
            record.progress_state_json = replacement_json.to_string();
        }
    }

    fn corrupt_previous_checkpoint_hash(
        &mut self,
        orchestration_id: &str,
        index: usize,
        replacement_hash: Option<&str>,
    ) {
        if let Some(records) = self.records.get_mut(orchestration_id)
            && let Some(record) = records.get_mut(index)
        {
            record.previous_checkpoint_hash = replacement_hash.map(ToString::to_string);
        }
    }
}

impl CheckpointBackend for ConformanceCheckpointBackend {
    fn save(&mut self, record: CheckpointRecord) -> Result<bool, CheckpointError> {
        if let Some(detail) = self.fail_next_save.take() {
            return Err(CheckpointError::Backend(detail));
        }

        let records = self
            .records
            .entry(record.orchestration_id.clone())
            .or_default();
        if records
            .iter()
            .any(|existing| ct_eq(&existing.checkpoint_id, &record.checkpoint_id))
        {
            return Ok(false);
        }
        records.push(record);
        Ok(true)
    }

    fn load_all(&self, orchestration_id: &str) -> Result<Vec<CheckpointRecord>, CheckpointError> {
        if let Some(detail) = self.fail_loads.as_ref() {
            return Err(CheckpointError::Backend(detail.clone()));
        }
        Ok(self
            .records
            .get(orchestration_id)
            .cloned()
            .unwrap_or_default())
    }
}

fn cx() -> CapabilityContext {
    CapabilityContext::new("cx-runtime-checkpoint-conformance", "runtime-operator")
}

fn progress(phase: &str, cursor: u64) -> RuntimeProgress {
    RuntimeProgress {
        phase: phase.to_string(),
        cursor,
        flags: BTreeMap::from([
            ("checkpointed".to_string(), true),
            ("restored".to_string(), false),
        ]),
    }
}

fn new_writer() -> CheckpointWriter<ConformanceCheckpointBackend> {
    CheckpointWriter::new(ConformanceCheckpointBackend::default())
}

fn save_progress(
    writer: &mut CheckpointWriter<ConformanceCheckpointBackend>,
    cancel: &mut CancellationState,
    orchestration_id: &str,
    iteration: u64,
    epoch: u64,
    state: &RuntimeProgress,
) -> String {
    writer
        .save_checkpoint(
            &cx(),
            cancel,
            "trace-runtime-checkpoint-conformance",
            orchestration_id,
            iteration,
            epoch,
            state,
        )
        .expect("checkpoint save should succeed")
}

fn assert_digest_eq(left: &str, right: &str) {
    assert!(ct_eq(left, right), "expected checkpoint digests to match");
}

fn assert_digest_ne(left: &str, right: &str) {
    assert!(!ct_eq(left, right), "expected checkpoint digests to differ");
}

#[test]
fn save_then_restore_round_trips_latest_runtime_state() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let state = progress("scan", 100);

    let checkpoint_id = save_progress(&mut writer, &mut cancel, "orch-roundtrip", 100, 7, &state);
    let restored = writer
        .restore_checkpoint::<RuntimeProgress>("trace-roundtrip", "orch-roundtrip")
        .expect("restore should not fail")
        .expect("checkpoint should exist");

    assert_digest_eq(&restored.meta.checkpoint_id, &checkpoint_id);
    assert_eq!(restored.meta.orchestration_id, "orch-roundtrip");
    assert_eq!(restored.meta.iteration_count, 100);
    assert_eq!(restored.meta.epoch, 7);
    assert_eq!(restored.state, state);
    assert!(
        writer
            .decision_stream()
            .iter()
            .any(|event| event.event_code == FN_CK_001_CHECKPOINT_SAVE
                && event.event_name == CHECKPOINT_SAVE
                && event.contract_status == "saved")
    );
}

#[test]
fn list_returns_checkpoint_metadata_in_save_order_with_hash_chain_links() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let first = save_progress(
        &mut writer,
        &mut cancel,
        "orch-list-order",
        10,
        1,
        &progress("scan", 10),
    );
    let second = save_progress(
        &mut writer,
        &mut cancel,
        "orch-list-order",
        20,
        1,
        &progress("plan", 20),
    );
    let third = save_progress(
        &mut writer,
        &mut cancel,
        "orch-list-order",
        30,
        1,
        &progress("apply", 30),
    );

    let list = writer
        .list_checkpoints("orch-list-order")
        .expect("list should succeed");

    assert_eq!(list.len(), 3);
    assert_eq!(
        list.iter()
            .map(|meta| meta.iteration_count)
            .collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
    assert!(list[0].previous_checkpoint_hash.is_none());
    assert_digest_eq(
        list[1]
            .previous_checkpoint_hash
            .as_deref()
            .expect("second checkpoint should link to first"),
        &first,
    );
    assert_digest_eq(
        list[2]
            .previous_checkpoint_hash
            .as_deref()
            .expect("third checkpoint should link to second"),
        &second,
    );
    assert_digest_eq(&list[2].checkpoint_id, &third);
}

#[test]
fn repeated_identical_save_is_idempotent_and_does_not_duplicate_list_entries() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let state = progress("scan", 42);

    let first = save_progress(&mut writer, &mut cancel, "orch-idempotent", 42, 3, &state);
    let second = save_progress(&mut writer, &mut cancel, "orch-idempotent", 42, 3, &state);
    let list = writer
        .list_checkpoints("orch-idempotent")
        .expect("list should succeed");

    assert_digest_eq(&first, &second);
    assert_eq!(list.len(), 1);
    assert!(
        writer
            .decision_stream()
            .iter()
            .any(|event| event.event_code == FN_CK_005_IDEMPOTENT_REUSE
                && event.event_name == CHECKPOINT_IDEMPOTENT_REUSE
                && event.contract_status == "idempotent")
    );
    assert!(
        writer
            .decision_stream()
            .iter()
            .any(|event| event.event_code == FN_CK_008_DECISION_STREAM_APPEND
                && event.event_name == CHECKPOINT_DECISION_STREAM_APPEND)
    );
}

#[test]
fn same_logical_position_with_changed_state_is_rejected() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    save_progress(
        &mut writer,
        &mut cancel,
        "orch-duplicate-position",
        5,
        1,
        &progress("scan", 5),
    );

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-duplicate-position",
            "orch-duplicate-position",
            5,
            1,
            &progress("changed", 5),
        )
        .expect_err("changed state at same logical position should fail");

    assert!(matches!(
        err,
        CheckpointError::HashChainViolation { ref reason, .. }
            if reason.contains("duplicate_logical_position")
    ));
    assert_eq!(writer.backend().record_count("orch-duplicate-position"), 1);
}

#[test]
fn regressing_iteration_is_rejected_and_latest_checkpoint_still_restores() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    save_progress(
        &mut writer,
        &mut cancel,
        "orch-iteration-regression",
        100,
        7,
        &progress("stable", 100),
    );

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-iteration-regression",
            "orch-iteration-regression",
            99,
            7,
            &progress("regressed", 99),
        )
        .expect_err("regressive iteration should fail");
    let restored = writer
        .restore_checkpoint::<RuntimeProgress>(
            "trace-iteration-regression",
            "orch-iteration-regression",
        )
        .expect("restore should succeed")
        .expect("prior checkpoint should remain restorable");

    assert!(matches!(
        err,
        CheckpointError::HashChainViolation { ref reason, .. }
            if reason.contains("iteration_regressed")
    ));
    assert_eq!(restored.meta.iteration_count, 100);
    assert_eq!(restored.state.phase, "stable");
}

#[test]
fn regressing_epoch_is_rejected_and_does_not_mutate_checkpoint_list() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    save_progress(
        &mut writer,
        &mut cancel,
        "orch-epoch-regression",
        1,
        3,
        &progress("epoch-three", 1),
    );
    let before = writer
        .list_checkpoints("orch-epoch-regression")
        .expect("list before rejection");

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-epoch-regression",
            "orch-epoch-regression",
            100,
            2,
            &progress("epoch-two", 100),
        )
        .expect_err("regressive epoch should fail");
    let after = writer
        .list_checkpoints("orch-epoch-regression")
        .expect("list after rejection");

    assert!(matches!(
        err,
        CheckpointError::HashChainViolation { ref reason, .. }
            if reason.contains("epoch_regressed")
    ));
    assert_eq!(before.len(), after.len());
    assert_digest_eq(&before[0].checkpoint_id, &after[0].checkpoint_id);
}

#[test]
fn missing_orchestration_restore_returns_none_and_read_emits_missing_event() {
    let writer = new_writer();

    let restored = writer
        .restore_checkpoint::<RuntimeProgress>("trace-missing", "orch-missing")
        .expect("missing restore should not error");
    let read = writer
        .read_latest_valid("trace-missing", "orch-missing")
        .expect("missing read should not error");

    assert!(restored.is_none());
    assert!(read.latest.is_none());
    assert!(read.events.iter().any(|event| {
        event.event_code == FN_CK_002_CHECKPOINT_RESTORE
            && event.event_name == CHECKPOINT_MISSING
            && event.contract_status == "missing"
    }));
}

#[test]
fn restore_with_incompatible_target_type_reports_deserialization_error() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    save_progress(
        &mut writer,
        &mut cancel,
        "orch-deserialization",
        1,
        1,
        &progress("scan", 1),
    );

    let err = writer
        .restore_checkpoint::<StringCursorProgress>("trace-deserialization", "orch-deserialization")
        .expect_err("cursor is stored as u64 and should not deserialize as String");

    assert!(matches!(err, CheckpointError::Deserialization(_)));
    assert_eq!(err.code(), "CHECKPOINT_DESERIALIZATION_ERROR");
}

#[test]
fn read_latest_valid_skips_tampered_payload_and_restore_uses_prior_valid_checkpoint() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let first = save_progress(
        &mut writer,
        &mut cancel,
        "orch-tamper-payload",
        10,
        1,
        &progress("first", 10),
    );
    save_progress(
        &mut writer,
        &mut cancel,
        "orch-tamper-payload",
        20,
        1,
        &progress("second", 20),
    );
    writer.backend_mut().corrupt_progress_state_json(
        "orch-tamper-payload",
        1,
        "{\"phase\":\"tampered\",\"cursor\":999,\"flags\":{\"checkpointed\":false}}",
    );

    let read = writer
        .read_latest_valid("trace-tamper-payload", "orch-tamper-payload")
        .expect("read should succeed despite invalid suffix");
    let restored = writer
        .restore_checkpoint::<RuntimeProgress>("trace-tamper-payload", "orch-tamper-payload")
        .expect("restore should succeed")
        .expect("prior valid checkpoint should exist");

    assert_digest_eq(&read.latest.expect("latest valid").checkpoint_id, &first);
    assert_eq!(restored.meta.iteration_count, 10);
    assert_eq!(restored.state.phase, "first");
    assert!(read.events.iter().any(|event| {
        event.event_code == FN_CK_003_HASH_CHAIN_FAILURE
            && event.event_name == CHECKPOINT_HASH_CHAIN_FAILURE
            && event
                .contract_status
                .contains("progress_state_hash_mismatch")
    }));
}

#[test]
fn append_after_hash_chain_failure_is_rejected_without_mutating_backend_records() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let first = save_progress(
        &mut writer,
        &mut cancel,
        "orch-chain-failure",
        10,
        1,
        &progress("first", 10),
    );
    let second = save_progress(
        &mut writer,
        &mut cancel,
        "orch-chain-failure",
        20,
        1,
        &progress("second", 20),
    );
    writer.backend_mut().corrupt_previous_checkpoint_hash(
        "orch-chain-failure",
        1,
        Some("bad-prev"),
    );
    let before_count = writer.backend().record_count("orch-chain-failure");

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-chain-failure",
            "orch-chain-failure",
            30,
            1,
            &progress("third", 30),
        )
        .expect_err("append after invalid chain should fail closed");
    let after_count = writer.backend().record_count("orch-chain-failure");

    assert_digest_ne(&first, &second);
    assert_eq!(before_count, after_count);
    assert!(matches!(
        err,
        CheckpointError::HashChainViolation { ref checkpoint_id, ref reason, .. }
            if ct_eq(checkpoint_id, &second)
                && reason == "cannot_append_after_hash_chain_failure"
    ));
    assert!(writer.decision_stream().iter().any(|event| {
        event.event_code == FN_CK_007_CONTRACT_VIOLATION
            && event.event_name == CHECKPOINT_CONTRACT_VIOLATION
            && event.contract_status == "violation:cannot_append_after_hash_chain_failure"
    }));
}

#[test]
fn separate_orchestrations_have_isolated_save_restore_and_list_state() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let alpha = save_progress(
        &mut writer,
        &mut cancel,
        "orch-alpha",
        10,
        1,
        &progress("alpha", 10),
    );
    let beta = save_progress(
        &mut writer,
        &mut cancel,
        "orch-beta",
        10,
        1,
        &progress("beta", 10),
    );

    let alpha_restored = writer
        .restore_checkpoint::<RuntimeProgress>("trace-isolated", "orch-alpha")
        .expect("alpha restore")
        .expect("alpha checkpoint");
    let beta_restored = writer
        .restore_checkpoint::<RuntimeProgress>("trace-isolated", "orch-beta")
        .expect("beta restore")
        .expect("beta checkpoint");

    assert_digest_ne(&alpha, &beta);
    assert_eq!(
        writer
            .list_checkpoints("orch-alpha")
            .expect("alpha list")
            .len(),
        1
    );
    assert_eq!(
        writer
            .list_checkpoints("orch-beta")
            .expect("beta list")
            .len(),
        1
    );
    assert_eq!(alpha_restored.state.phase, "alpha");
    assert_eq!(beta_restored.state.phase, "beta");
    assert_eq!(alpha_restored.meta.orchestration_id, "orch-alpha");
    assert_eq!(beta_restored.meta.orchestration_id, "orch-beta");
}

#[test]
fn backend_save_error_propagates_without_recording_success_events() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    writer
        .backend_mut()
        .fail_next_save("checkpoint store unavailable");

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-save-error",
            "orch-save-error",
            1,
            1,
            &progress("save-error", 1),
        )
        .expect_err("backend save failure should propagate");

    assert!(matches!(
        err,
        CheckpointError::Backend(ref detail) if detail.contains("checkpoint store unavailable")
    ));
    assert_eq!(writer.backend().record_count("orch-save-error"), 0);
    assert!(
        !writer
            .decision_stream()
            .iter()
            .any(|event| event.event_code == FN_CK_001_CHECKPOINT_SAVE)
    );
}

#[test]
fn backend_load_error_propagates_through_list_and_restore() {
    let mut writer = new_writer();
    writer
        .backend_mut()
        .fail_loads("checkpoint index unavailable");

    let list_err = writer
        .list_checkpoints("orch-load-error")
        .expect_err("list should propagate load error");
    let restore_err = writer
        .restore_checkpoint::<RuntimeProgress>("trace-load-error", "orch-load-error")
        .expect_err("restore should propagate load error");

    assert!(matches!(
        list_err,
        CheckpointError::Backend(ref detail) if detail.contains("checkpoint index unavailable")
    ));
    assert!(matches!(
        restore_err,
        CheckpointError::Backend(ref detail) if detail.contains("checkpoint index unavailable")
    ));
}

#[test]
fn cancellation_before_save_enters_mask_failure_and_does_not_persist() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    cancel.request_cancel();

    let err = writer
        .save_checkpoint(
            &cx(),
            &mut cancel,
            "trace-cancelled-save",
            "orch-cancelled-save",
            1,
            1,
            &progress("cancelled", 1),
        )
        .expect_err("pre-cancelled save should fail inside bounded mask");

    assert!(matches!(
        err,
        CheckpointError::MaskFailure(ref detail)
            if detail.contains("MASK_CANCELLED_BEFORE_ENTRY")
    ));
    assert_eq!(writer.backend().record_count("orch-cancelled-save"), 0);
}

#[test]
fn read_latest_valid_reports_restore_event_for_latest_valid_checkpoint() {
    let mut writer = new_writer();
    let mut cancel = CancellationState::new();
    let checkpoint_id = save_progress(
        &mut writer,
        &mut cancel,
        "orch-read-latest",
        77,
        4,
        &progress("read", 77),
    );

    let read = writer
        .read_latest_valid("trace-read-latest", "orch-read-latest")
        .expect("read latest should succeed");
    let latest = read.latest.expect("latest checkpoint should exist");

    assert_digest_eq(&latest.checkpoint_id, &checkpoint_id);
    assert!(read.events.iter().any(|event| {
        event.event_code == FN_CK_002_CHECKPOINT_RESTORE
            && event.event_name == CHECKPOINT_RESTORE
            && event.contract_status == "valid"
            && event.iteration_count == 77
    }));
}
