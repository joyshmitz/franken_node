//! Integration tests for bd-2yc4: Crash-loop detector with automatic rollback.
//!
//! Verifies threshold enforcement, automatic rollback, trust policy
//! enforcement, cooldown, and audit trail.

use frankenengine_node::runtime::crash_loop_detector::*;

fn cfg() -> CrashLoopConfig {
    CrashLoopConfig {
        max_crashes: 3,
        window_secs: 60,
        cooldown_secs: 30,
    }
}

fn crash(id: &str) -> CrashEvent {
    CrashEvent {
        connector_id: id.into(),
        timestamp: "t".into(),
        reason: "oom".into(),
    }
}

fn good_pin() -> KnownGoodPin {
    KnownGoodPin {
        connector_id: "conn-1".into(),
        version: "1.0.0".into(),
        pin_hash: "abc".into(),
        trusted: true,
    }
}

fn bad_pin() -> KnownGoodPin {
    KnownGoodPin {
        connector_id: "conn-1".into(),
        version: "0.5.0".into(),
        pin_hash: "bad".into(),
        trusted: false,
    }
}

#[test]
fn inv_cld_threshold_below() {
    let mut det = CrashLoopDetector::new(cfg());
    det.record_crash(&crash("conn-1"), 100);
    det.record_crash(&crash("conn-1"), 101);
    let events = vec![crash("conn-1"); 2];
    let result = det.evaluate("conn-1", &events, Some(&good_pin()), 101, "tr", "ts");
    let d = result.unwrap();
    assert!(!d.triggered, "INV-CLD-THRESHOLD: should not trigger below threshold");
}

#[test]
fn inv_cld_threshold_at() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    let result = det.evaluate("conn-1", &events, Some(&good_pin()), 102, "tr", "ts");
    let d = result.unwrap();
    assert!(d.triggered, "INV-CLD-THRESHOLD: should trigger at threshold");
}

#[test]
fn inv_cld_rollback_auto() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    let d = det.evaluate("conn-1", &events, Some(&good_pin()), 102, "tr", "ts").unwrap();
    assert!(d.rollback_allowed, "INV-CLD-ROLLBACK-AUTO: rollback must be automatic");
    assert!(d.rollback_target.is_some());
}

#[test]
fn inv_cld_trust_policy_rejects_untrusted() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    let result = det.evaluate("conn-1", &events, Some(&bad_pin()), 102, "tr", "ts");
    let err = result.unwrap_err();
    assert_eq!(err.code(), "CLD_PIN_UNTRUSTED", "INV-CLD-TRUST-POLICY violated");
}

#[test]
fn inv_cld_audit_trail() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    det.evaluate("conn-1", &events, Some(&good_pin()), 102, "tr", "ts").unwrap();
    assert!(!det.incidents.is_empty(), "INV-CLD-AUDIT: must produce incident record");
    assert_eq!(det.incidents[0].trace_id, "tr");
}

#[test]
fn no_pin_available_errors() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    let result = det.evaluate("conn-1", &events, None, 102, "tr", "ts");
    assert_eq!(result.unwrap_err().code(), "CLD_NO_KNOWN_GOOD");
}

#[test]
fn cooldown_blocks_immediate_retrigger() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    det.evaluate("conn-1", &events, Some(&good_pin()), 102, "tr1", "ts").unwrap();
    // Immediately try again
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 110 + i);
    }
    let events2 = vec![crash("conn-1"); 3];
    let result = det.evaluate("conn-1", &events2, Some(&good_pin()), 112, "tr2", "ts");
    assert_eq!(result.unwrap_err().code(), "CLD_COOLDOWN_ACTIVE");
}

#[test]
fn rollback_clears_window() {
    let mut det = CrashLoopDetector::new(cfg());
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 100 + i);
    }
    let events = vec![crash("conn-1"); 3];
    det.evaluate("conn-1", &events, Some(&good_pin()), 102, "tr", "ts").unwrap();
    assert_eq!(det.crashes_in_window(103), 0);
}

#[test]
fn sliding_window_correctness() {
    let mut det = CrashLoopDetector::new(cfg());
    // Crashes at t=0..2 are outside window at t=200 (window=60)
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), i);
    }
    assert!(!det.is_looping(200));
    // Now add crashes within window
    for i in 0..3 {
        det.record_crash(&crash("conn-1"), 190 + i);
    }
    assert!(det.is_looping(192));
}
