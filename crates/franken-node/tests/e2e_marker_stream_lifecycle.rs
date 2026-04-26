//! Mock-free end-to-end test for the append-only control marker stream.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::marker_stream::MarkerStream` through
//! the full append → query → verify → diverge → recover lifecycle:
//!
//!   1. real `append` of every `MarkerEventType` variant with monotonic
//!      timestamps and explicit `payload_hash`/`trace_id` inputs,
//!   2. invariant enforcement: empty payload_hash, empty trace_id, and time
//!      regression are rejected with the right error variants,
//!   3. range/get/marker_by_sequence/sequence_by_timestamp queries return
//!      the expected markers (boundary + interior + before-first cases),
//!   4. `verify_integrity` walks the entire chain successfully,
//!   5. `find_divergence_point` performs the binary-search comparison
//!      across two streams that share a common prefix and diverge at a
//!      known sequence,
//!   6. `recover_torn_tail` is a no-op on a healthy stream.
//!
//! Bead: bd-1dj7l.
//!
//! No mocks: real SHA-256-backed marker hashes, real append-only chain,
//! real binary-search divergence finder. Each phase emits a structured
//! tracing event PLUS a JSON-line on stderr so a CI failure can be
//! reconstructed from the test transcript alone.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::marker_stream::{
    MarkerEventType, MarkerStream, MarkerStreamError, find_divergence_point,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

/// Append every event-type variant with monotonically increasing timestamps.
/// Returns the populated stream so each test can build its own.
fn build_real_stream(items: &[(MarkerEventType, &str, u64, &str)]) -> MarkerStream {
    let mut s = MarkerStream::new();
    for (et, payload, ts, trace) in items {
        s.append(*et, payload, *ts, trace).expect("real append");
    }
    s
}

#[test]
fn e2e_marker_stream_full_append_query_integrity() {
    let h = Harness::new("e2e_marker_stream_full_append_query_integrity");

    // ── ARRANGE: append one of every event_type with monotonic ts ──
    let items = [
        (MarkerEventType::TrustDecision, "sha256:trust-001", 1_000_000_000u64, "trace-trust-1"),
        (MarkerEventType::RevocationEvent, "sha256:rev-001", 1_000_000_010, "trace-rev-1"),
        (MarkerEventType::QuarantineAction, "sha256:quar-001", 1_000_000_020, "trace-quar-1"),
        (MarkerEventType::PolicyChange, "sha256:policy-001", 1_000_000_030, "trace-policy-1"),
        (MarkerEventType::EpochTransition, "sha256:epoch-001", 1_000_000_040, "trace-epoch-1"),
        (MarkerEventType::IncidentEscalation, "sha256:incident-001", 1_000_000_050, "trace-incident-1"),
    ];
    let mut stream = build_real_stream(&items);
    assert_eq!(stream.len(), 6);
    assert!(!stream.is_empty());
    h.log_phase("appended", true, json!({"count": 6}));

    // ── ASSERT: dense sequence numbering 0..6 ───────────────────────
    for seq in 0..6 {
        let m = stream.get(seq).expect("dense sequence");
        assert_eq!(m.sequence, seq);
        // Round-trip equivalent lookup via marker_by_sequence
        let other = stream.marker_by_sequence(seq).expect("by_sequence");
        assert_eq!(m, other);
    }
    assert!(stream.get(99).is_none(), "out-of-range get returns None");
    h.log_phase("sequence_dense", true, json!({}));

    // ── ASSERT: head + first ────────────────────────────────────────
    assert_eq!(stream.head().map(|m| m.sequence), Some(5));
    assert_eq!(stream.first().map(|m| m.sequence), Some(0));
    h.log_phase("head_first", true, json!({}));

    // ── ASSERT: range query is half-open [start, end) ───────────────
    let mid = stream.range(2, 5);
    assert_eq!(mid.len(), 3);
    assert_eq!(mid[0].sequence, 2);
    assert_eq!(mid[2].sequence, 4);
    let empty = stream.range(10, 20);
    assert!(empty.is_empty());
    h.log_phase("range_query", true, json!({}));

    // ── ASSERT: timestamp → sequence binary search ──────────────────
    // Exact hit on a marker timestamp.
    assert_eq!(
        stream.sequence_by_timestamp(1_000_000_030),
        Some(3),
        "ts equals marker[3] → returns 3"
    );
    // Between two markers — returns the predecessor.
    assert_eq!(
        stream.sequence_by_timestamp(1_000_000_025),
        Some(2),
        "ts strictly between m2 and m3 → returns 2"
    );
    // Before any marker — None.
    assert_eq!(stream.sequence_by_timestamp(0), None);
    // After the last — returns the last sequence.
    assert_eq!(stream.sequence_by_timestamp(u64::MAX), Some(5));
    h.log_phase("ts_to_seq_binary_search", true, json!({}));

    // ── ASSERT: integrity check passes on a clean chain ─────────────
    stream.verify_integrity().expect("clean chain verifies");
    // recover_torn_tail is a no-op on a healthy stream.
    assert!(stream.recover_torn_tail().is_none());
    h.log_phase("integrity_clean", true, json!({}));
}

#[test]
fn e2e_marker_stream_invariant_rejection_paths() {
    let h = Harness::new("e2e_marker_stream_invariant_rejection_paths");

    let mut s = MarkerStream::new();

    // ── empty payload_hash rejected ────────────────────────────────
    let err = s
        .append(MarkerEventType::TrustDecision, "   ", 1, "trace-bad-payload")
        .expect_err("empty payload_hash rejected");
    match err {
        MarkerStreamError::InvalidPayload { reason } => {
            assert!(reason.contains("payload_hash"));
            h.log_phase("empty_payload_rejected", true, json!({"reason": reason}));
        }
        other => panic!("expected InvalidPayload(payload_hash), got {other:?}"),
    }
    assert_eq!(s.len(), 0);

    // ── empty trace_id rejected ─────────────────────────────────────
    let err = s
        .append(MarkerEventType::TrustDecision, "sha256:ok", 1, "")
        .expect_err("empty trace_id rejected");
    match err {
        MarkerStreamError::InvalidPayload { reason } => {
            assert!(reason.contains("trace_id"));
            h.log_phase("empty_trace_rejected", true, json!({"reason": reason}));
        }
        other => panic!("expected InvalidPayload(trace_id), got {other:?}"),
    }
    assert_eq!(s.len(), 0);

    // Append two markers normally.
    s.append(MarkerEventType::TrustDecision, "sha256:p1", 100, "trace-1")
        .expect("first append");
    s.append(MarkerEventType::PolicyChange, "sha256:p2", 200, "trace-2")
        .expect("second append");
    assert_eq!(s.len(), 2);

    // ── INV-MKS-MONOTONIC-TIME: timestamp 150 < head 200 rejected ──
    let err = s
        .append(MarkerEventType::EpochTransition, "sha256:p3", 150, "trace-3")
        .expect_err("time regression rejected");
    match err {
        MarkerStreamError::TimeRegression {
            sequence,
            prev_ts,
            got_ts,
        } => {
            assert_eq!(sequence, 2);
            assert_eq!(prev_ts, 200);
            assert_eq!(got_ts, 150);
            h.log_phase(
                "time_regression_rejected",
                true,
                json!({"prev_ts": prev_ts, "got_ts": got_ts}),
            );
        }
        other => panic!("expected TimeRegression, got {other:?}"),
    }
    // Rejection must not have grown the stream.
    assert_eq!(s.len(), 2);

    // INV-MKS-MONOTONIC-TIME: equal timestamp accepted (>=, not >).
    s.append(MarkerEventType::PolicyChange, "sha256:p3", 200, "trace-3")
        .expect("equal-timestamp append accepted");
    assert_eq!(s.len(), 3);
    h.log_phase("equal_timestamp_accepted", true, json!({}));

    // ── ASSERT: chain still verifies after every accept/reject ─────
    s.verify_integrity().expect("chain still healthy");
}

#[test]
fn e2e_marker_stream_find_divergence_point_binary_search() {
    let h = Harness::new("e2e_marker_stream_find_divergence_point_binary_search");

    // Build TWO streams that agree on the first 4 markers, then diverge.
    let mut local = MarkerStream::new();
    let mut remote = MarkerStream::new();

    let prefix = [
        (MarkerEventType::TrustDecision, "sha256:p0", 100u64, "trace-0"),
        (MarkerEventType::TrustDecision, "sha256:p1", 110, "trace-1"),
        (MarkerEventType::TrustDecision, "sha256:p2", 120, "trace-2"),
        (MarkerEventType::TrustDecision, "sha256:p3", 130, "trace-3"),
    ];
    for (et, p, ts, tr) in prefix {
        local.append(et, p, ts, tr).expect("local prefix");
        remote.append(et, p, ts, tr).expect("remote prefix");
    }
    // Diverge at sequence 4 with different payload hashes (and different
    // event types, so the marker_hash absolutely diverges).
    local
        .append(MarkerEventType::PolicyChange, "sha256:LOCAL-only", 140, "trace-L")
        .expect("local divergent");
    remote
        .append(MarkerEventType::IncidentEscalation, "sha256:REMOTE-only", 140, "trace-R")
        .expect("remote divergent");

    let result = find_divergence_point(&local, &remote);
    assert!(result.has_common_prefix);
    assert_eq!(result.common_prefix_seq, 3, "common prefix ends at seq 3");
    assert!(result.has_divergence);
    assert_eq!(result.divergence_seq, 4);
    assert!(result.local_hash_at_divergence.is_some());
    assert!(result.remote_hash_at_divergence.is_some());
    assert_ne!(
        result.local_hash_at_divergence,
        result.remote_hash_at_divergence,
        "divergent markers must have different hashes"
    );
    // Binary search: comparison_count must be O(log n) of shared prefix.
    // For shared prefix len 5 (binary search bounds), at most ~4 comparisons.
    assert!(
        result.evidence.comparison_count <= 8,
        "binary search should not be O(n): {} comparisons",
        result.evidence.comparison_count
    );
    h.log_phase(
        "divergence_found",
        true,
        json!({
            "common_prefix_seq": result.common_prefix_seq,
            "divergence_seq": result.divergence_seq,
            "comparisons": result.evidence.comparison_count,
        }),
    );

    // Identical streams: no divergence.
    let mut twin_a = MarkerStream::new();
    let mut twin_b = MarkerStream::new();
    for (et, p, ts, tr) in prefix {
        twin_a.append(et, p, ts, tr).expect("twin a");
        twin_b.append(et, p, ts, tr).expect("twin b");
    }
    let same = find_divergence_point(&twin_a, &twin_b);
    assert!(!same.has_divergence, "identical streams must not diverge");
    h.log_phase("identical_no_divergence", true, json!({}));

    // Empty vs non-empty: divergence at sequence 0.
    let empty = MarkerStream::new();
    let one_sided = find_divergence_point(&empty, &twin_b);
    assert!(one_sided.has_divergence);
    assert_eq!(one_sided.divergence_seq, 0);
    assert!(!one_sided.has_common_prefix);
    h.log_phase("empty_vs_full_diverges_at_0", true, json!({}));

    // Two empty streams: no divergence (both length 0).
    let empty_a = MarkerStream::new();
    let empty_b = MarkerStream::new();
    let both_empty = find_divergence_point(&empty_a, &empty_b);
    assert!(!both_empty.has_divergence);
    h.log_phase("both_empty_no_divergence", true, json!({}));
}

#[test]
fn e2e_marker_stream_event_type_round_trip() {
    let h = Harness::new("e2e_marker_stream_event_type_round_trip");

    // Each label must round-trip through from_label.
    for et in MarkerEventType::all() {
        let label = et.label();
        let parsed = MarkerEventType::from_label(label).expect("round-trip");
        assert_eq!(parsed, *et);
    }
    h.log_phase("labels_round_trip", true, json!({}));

    // Unknown label returns None.
    assert!(MarkerEventType::from_label("nonexistent_event_type").is_none());
    h.log_phase("unknown_label_rejected", true, json!({}));
}
