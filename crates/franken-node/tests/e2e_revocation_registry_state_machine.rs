//! Mock-free end-to-end test for the supply-chain revocation registry.
//!
//! Drives `RevocationRegistry` through the full lifecycle invariants documented
//! on the production module:
//!   - INV-REV-MONOTONIC      strict-increasing sequence per zone
//!   - INV-REV-STALE-REJECT   `<=` current head is rejected with REV_STALE_HEAD
//!   - INV-REV-ZONE-ISOLATED  revocations in zone A do not leak into zone B
//!   - INV-REV-RECOVERABLE    `recover_from_log(canonical_log())` round-trips
//!
//! Bead: bd-ys4bc.
//!
//! No mocks: real registry instance, real BTreeMap-backed zone state, real
//! audit trail. Each phase emits a structured tracing event PLUS a JSON-line
//! on stderr so a CI failure is reconstructable from the test transcript.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::supply_chain::revocation_registry::{
    RevocationError, RevocationHead, RevocationRegistry,
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

fn head(zone: &str, seq: u64, artifact: &str, trace: &str) -> RevocationHead {
    RevocationHead {
        zone_id: zone.to_string(),
        sequence: seq,
        revoked_artifact: artifact.to_string(),
        reason: "policy_violation".to_string(),
        timestamp: "2026-04-26T22:00:00Z".to_string(),
        trace_id: trace.to_string(),
    }
}

#[test]
fn e2e_revocation_registry_monotonic_advance_and_stale_reject() {
    let h = Harness::new("e2e_revocation_registry_monotonic_advance_and_stale_reject");

    // ── ARRANGE: real registry with one initialised zone ────────────
    let mut reg = RevocationRegistry::new();
    reg.init_zone("zone-prod").expect("init zone");
    assert_eq!(reg.current_head("zone-prod").unwrap(), 0);
    assert_eq!(reg.zone_count(), 1);
    h.log_phase(
        "init",
        true,
        json!({"zone_count": reg.zone_count(), "head": 0u64}),
    );

    // ── ACT: advance the head with sequence 1, 2, 3 ─────────────────
    for (i, art) in ["sha256:art-001", "sha256:art-002", "sha256:art-003"]
        .iter()
        .enumerate()
    {
        let seq = (i + 1) as u64;
        let observed = reg
            .advance_head(head("zone-prod", seq, art, &format!("trace-adv-{seq}")))
            .expect("advance accepted");
        assert_eq!(observed, seq);
        assert_eq!(reg.current_head("zone-prod").unwrap(), seq);
        assert!(reg.is_revoked("zone-prod", art).unwrap());
        h.log_phase(
            "advance",
            true,
            json!({"seq": seq, "artifact": art, "head_after": seq}),
        );
    }
    assert_eq!(reg.total_revocations(), 3);

    // ── ASSERT: stale advance is rejected with REV_STALE_HEAD ───────
    let stale = reg.advance_head(head("zone-prod", 2, "sha256:art-stale", "trace-stale"));
    match stale {
        Err(RevocationError::StaleHead {
            zone_id,
            offered,
            current,
        }) => {
            assert_eq!(zone_id, "zone-prod");
            assert_eq!(offered, 2);
            assert_eq!(current, 3);
            h.log_phase("stale_rejected", true, json!({"offered": 2, "current": 3}));
        }
        other => panic!("expected StaleHead, got {other:?}"),
    }
    // Stale rejection must NOT advance the head.
    assert_eq!(reg.current_head("zone-prod").unwrap(), 3);
    // sha256:art-stale must NOT have been recorded.
    assert!(!reg.is_revoked("zone-prod", "sha256:art-stale").unwrap());

    // ── ASSERT: equal-to-current is rejected (boundary) ─────────────
    let equal = reg.advance_head(head("zone-prod", 3, "sha256:art-equal", "trace-eq"));
    assert!(matches!(equal, Err(RevocationError::StaleHead { .. })));
    h.log_phase("equal_to_current_rejected", true, json!({}));

    // ── ASSERT: audit trail captures every action, including rejects ─
    let advanced = reg.audits.iter().filter(|a| a.action == "advanced").count();
    let rejected = reg
        .audits
        .iter()
        .filter(|a| a.action == "rejected_stale")
        .count();
    assert_eq!(advanced, 3);
    assert_eq!(rejected, 2);
    h.log_phase(
        "audit_trail",
        true,
        json!({"advanced": advanced, "rejected": rejected}),
    );
}

#[test]
fn e2e_revocation_registry_zone_isolation() {
    let h = Harness::new("e2e_revocation_registry_zone_isolation");

    // ── ARRANGE: two zones share one registry ───────────────────────
    let mut reg = RevocationRegistry::new();
    reg.init_zone("zone-A").expect("init A");
    reg.init_zone("zone-B").expect("init B");

    // ── ACT: revoke artifact in zone-A only ─────────────────────────
    reg.advance_head(head("zone-A", 1, "sha256:shared-id", "trace-A1"))
        .expect("zone-A advance");
    h.log_phase("revoke_in_a", true, json!({"artifact": "sha256:shared-id"}));

    // ── ASSERT: zone-B sees the same artifact as NOT revoked ────────
    let b_check = reg
        .is_revoked("zone-B", "sha256:shared-id")
        .expect("zone-B is_revoked");
    assert!(
        !b_check,
        "INV-REV-ZONE-ISOLATED: revoking in zone-A must not affect zone-B"
    );
    h.log_phase("zone_b_unaffected", true, json!({"is_revoked": false}));

    // ── ASSERT: heads track per-zone ────────────────────────────────
    assert_eq!(reg.current_head("zone-A").unwrap(), 1);
    assert_eq!(reg.current_head("zone-B").unwrap(), 0);
    h.log_phase("heads_isolated", true, json!({"a": 1, "b": 0}));

    // ── ACT: zone-B can revoke the SAME artifact independently ──────
    reg.advance_head(head("zone-B", 1, "sha256:shared-id", "trace-B1"))
        .expect("zone-B advance independent");
    assert!(reg.is_revoked("zone-B", "sha256:shared-id").unwrap());
    assert!(reg.is_revoked("zone-A", "sha256:shared-id").unwrap());
    h.log_phase("independent_dual_revoke", true, json!({}));

    // ── ASSERT: querying an unknown zone is REV_ZONE_NOT_FOUND ──────
    let missing = reg.is_revoked("zone-ghost", "sha256:any");
    assert!(matches!(missing, Err(RevocationError::ZoneNotFound { .. })));
    h.log_phase("unknown_zone_rejected", true, json!({}));
}

#[test]
fn e2e_revocation_registry_recovery_from_canonical_log() {
    let h = Harness::new("e2e_revocation_registry_recovery_from_canonical_log");

    // ── ARRANGE: build a real registry across two zones ─────────────
    let mut reg = RevocationRegistry::new();
    reg.init_zone("zone-X").expect("init X");
    reg.init_zone("zone-Y").expect("init Y");
    reg.advance_head(head("zone-X", 1, "sha256:x-001", "trace-x1"))
        .expect("x1");
    reg.advance_head(head("zone-Y", 1, "sha256:y-001", "trace-y1"))
        .expect("y1");
    reg.advance_head(head("zone-X", 2, "sha256:x-002", "trace-x2"))
        .expect("x2");

    // Snapshot state expected after recovery.
    let head_x_before = reg.current_head("zone-X").unwrap();
    let head_y_before = reg.current_head("zone-Y").unwrap();
    let revs_before = reg.total_revocations();
    let log: Vec<RevocationHead> = reg.canonical_log().to_vec();
    h.log_phase(
        "snapshot",
        true,
        json!({
            "head_x": head_x_before,
            "head_y": head_y_before,
            "total_revocations": revs_before,
            "log_len": log.len(),
        }),
    );

    // ── ACT: recover into a fresh registry from the canonical log ──
    let recovered = RevocationRegistry::recover_from_log(&log).expect("recovery succeeds");
    h.log_phase(
        "recovered",
        true,
        json!({"recovered_log_len": recovered.canonical_log().len()}),
    );

    // ── ASSERT: heads, revoked sets, and log all round-trip ─────────
    assert_eq!(recovered.current_head("zone-X").unwrap(), head_x_before);
    assert_eq!(recovered.current_head("zone-Y").unwrap(), head_y_before);
    assert_eq!(recovered.total_revocations(), revs_before);
    assert!(recovered.is_revoked("zone-X", "sha256:x-001").unwrap());
    assert!(recovered.is_revoked("zone-X", "sha256:x-002").unwrap());
    assert!(recovered.is_revoked("zone-Y", "sha256:y-001").unwrap());
    assert!(!recovered.is_revoked("zone-X", "sha256:never").unwrap());
    h.log_phase("round_trip_equivalence", true, json!({}));

    // ── ASSERT: empty-log recovery is a hard failure ────────────────
    let empty_err = RevocationRegistry::recover_from_log(&[]).expect_err("empty log invalid");
    assert!(matches!(empty_err, RevocationError::RecoveryFailed { .. }));
    h.log_phase("empty_log_rejected", true, json!({}));

    // ── ASSERT: non-monotonic log is a hard failure ─────────────────
    let bad_log = vec![
        head("zone-Z", 5, "sha256:z-001", "trace-z5"),
        head("zone-Z", 3, "sha256:z-002", "trace-z3"),
    ];
    let bad_err =
        RevocationRegistry::recover_from_log(&bad_log).expect_err("non-monotonic invalid");
    match bad_err {
        RevocationError::RecoveryFailed { reason } => {
            assert!(reason.contains("non-monotonic"));
            h.log_phase(
                "non_monotonic_log_rejected",
                true,
                json!({"reason": reason}),
            );
        }
        other => panic!("expected RecoveryFailed, got {other:?}"),
    }
}

#[test]
fn e2e_revocation_registry_input_validation() {
    let h = Harness::new("e2e_revocation_registry_input_validation");

    let mut reg = RevocationRegistry::new();
    // Empty zone_id → InvalidInput.
    assert!(matches!(
        reg.init_zone("   "),
        Err(RevocationError::InvalidInput { .. })
    ));
    h.log_phase("empty_zone_id_rejected", true, json!({}));

    reg.init_zone("zone-real").expect("init real");

    // Empty artifact → InvalidInput.
    let bad_art = reg.advance_head(head("zone-real", 1, "  ", "trace-bad-art"));
    assert!(matches!(bad_art, Err(RevocationError::InvalidInput { .. })));
    h.log_phase("empty_artifact_rejected", true, json!({}));

    // Successful advance, then duplicate-revoke the same artifact at a higher
    // sequence: must be rejected as InvalidInput because revocation is
    // permanent and idempotent — duplicate advances would burn sequence numbers
    // without recording new state.
    reg.advance_head(head("zone-real", 1, "sha256:dup-art", "trace-dup-1"))
        .expect("first revoke");
    let dup = reg.advance_head(head("zone-real", 2, "sha256:dup-art", "trace-dup-2"));
    match dup {
        Err(RevocationError::InvalidInput { detail }) => {
            assert!(detail.contains("already revoked"));
            h.log_phase(
                "duplicate_revocation_rejected",
                true,
                json!({"detail": detail}),
            );
        }
        other => panic!("expected InvalidInput for duplicate revoke, got {other:?}"),
    }
    // Head must NOT have advanced past the first successful revoke.
    assert_eq!(reg.current_head("zone-real").unwrap(), 1);
}
