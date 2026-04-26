//! Mock-free end-to-end test for the evidence ledger lifecycle.
//!
//! Drives the public surface of
//! `frankenengine_node::observability::evidence_ledger::EvidenceLedger`
//! through the full append/verify/replay/hash-chain matrix using REAL
//! Ed25519 signatures (no test doubles, no fake signers).
//!
//! Bead: bd-1wjad.
//!
//! Coverage:
//!   - signed `append` → `iter_recent` round-trips the entry,
//!   - hash-chain enforcement: client-provided `prev_entry_hash` must
//!     match the ledger's `last_entry_hash`; mismatch returns
//!     `LedgerError::HashChainBroken`,
//!   - replay attack: re-appending an identical (timestamp_ms, signature)
//!     pair returns `LedgerError::ReplayAttack`,
//!   - signature verification: tampered payload after sign is rejected
//!     with `LedgerError::SignatureInvalid`,
//!   - capacity: zero `max_entries` rejects every append with
//!     `LedgerError::ZeroEntryCapacity`,
//!   - capacity: an entry whose serialized size exceeds `max_bytes` is
//!     rejected with `LedgerError::EntryTooLarge`,
//!   - eviction: FIFO eviction past `max_entries` updates `total_evicted`
//!     and `total_appended` independently,
//!   - free-standing helpers: `evidence_entry_hash_hex` is stable across
//!     re-runs and `verify_evidence_entry` round-trips for a signed entry.
//!
//! Each phase emits a structured tracing event PLUS a JSON-line on stderr
//! so a CI failure can be reconstructed from the test transcript alone.

use std::sync::Once;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use frankenengine_node::observability::evidence_ledger::{
    EvidenceLedger, LedgerCapacity, LedgerError, evidence_entry_hash_hex, sign_evidence_entry,
    test_entry, verify_evidence_entry,
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

fn signing_key() -> SigningKey {
    // Deterministic key seed so the test is reproducible.
    SigningKey::from_bytes(&[0xCC; 32])
}

#[test]
fn e2e_evidence_ledger_sign_append_chain_replay_full_matrix() {
    let h = Harness::new("e2e_evidence_ledger_sign_append_chain_replay_full_matrix");

    // ── ARRANGE: real ledger requiring signature verification ──────
    let key = signing_key();
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(8, 4096), key.verifying_key());
    assert!(ledger.is_empty());
    assert_eq!(ledger.total_appended(), 0);
    assert_eq!(ledger.total_evicted(), 0);
    h.log_phase("ledger_built", true, json!({"max_entries": 8, "max_bytes": 4096}));

    // ── ACT: sign + append three entries; chain advances each time ──
    let mut ids = Vec::new();
    for (i, dec) in ["DEC-001", "DEC-002", "DEC-003"].iter().enumerate() {
        let mut e = test_entry(dec, (i as u64).saturating_add(1));
        // distinct timestamp_ms so the replay-window keys are unique
        e.timestamp_ms = 100 + i as u64;
        sign_evidence_entry(&mut e, &key);
        let id = ledger.append(e).expect("signed append succeeds");
        ids.push(id);
        h.log_phase("append", true, json!({"decision": dec, "entry_id": id.0}));
    }
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.total_appended(), 3);
    assert_eq!(ledger.total_evicted(), 0);

    // ── ASSERT: iter_recent returns newest entries last ─────────────
    let recent: Vec<_> = ledger.iter_recent(2).collect();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].1.decision_id, "DEC-002");
    assert_eq!(recent[1].1.decision_id, "DEC-003");
    h.log_phase("recent_order", true, json!({"oldest": "DEC-002", "newest": "DEC-003"}));

    // ── ASSERT: replay attack rejected (re-append identical entry) ─
    let mut replay = test_entry("DEC-001", 1);
    replay.timestamp_ms = 100; // same as the first appended entry
    sign_evidence_entry(&mut replay, &key);
    let replay_err = ledger.append(replay).expect_err("replay rejected");
    match replay_err {
        LedgerError::ReplayAttack {
            timestamp_ms,
            signature,
        } => {
            assert_eq!(timestamp_ms, 100);
            assert!(!signature.is_empty());
            h.log_phase("replay_rejected", true, json!({"timestamp_ms": timestamp_ms}));
        }
        other => panic!("expected ReplayAttack, got {other:?}"),
    }
    // Replay must NOT have advanced counters.
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.total_appended(), 3);

    // ── ASSERT: hash-chain enforcement ──────────────────────────────
    // Build an entry whose prev_entry_hash is wrong: any non-empty value
    // that does NOT match the ledger's actual last_entry_hash must be
    // rejected with HashChainBroken.
    let mut chain_break = test_entry("DEC-CHAIN", 99);
    chain_break.timestamp_ms = 999_000;
    chain_break.prev_entry_hash =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
    sign_evidence_entry(&mut chain_break, &key);
    let chain_err = ledger.append(chain_break).expect_err("chain mismatch rejected");
    match chain_err {
        LedgerError::HashChainBroken {
            expected_hash,
            provided_hash,
        } => {
            assert!(!expected_hash.is_empty(), "expected hash must be set");
            assert_eq!(provided_hash.len(), 64, "provided hash must be sha256-hex");
            h.log_phase("chain_break_rejected", true, json!({"expected_len": expected_hash.len()}));
        }
        other => panic!("expected HashChainBroken, got {other:?}"),
    }
    assert_eq!(ledger.len(), 3);

    // ── ASSERT: tampered payload after signing rejected ────────────
    let mut tampered = test_entry("DEC-TAMPER", 50);
    tampered.timestamp_ms = 50_000;
    sign_evidence_entry(&mut tampered, &key);
    // Mutate the decision_id AFTER signing so the signature no longer covers
    // the canonical bytes.
    tampered.decision_id = "DEC-TAMPER-MODIFIED".to_string();
    let sig_err = ledger.append(tampered).expect_err("tampered payload rejected");
    assert!(
        matches!(sig_err, LedgerError::SignatureInvalid { .. }),
        "expected SignatureInvalid, got {sig_err:?}"
    );
    h.log_phase("tampered_payload_rejected", true, json!({}));

    // ── ASSERT: snapshot reflects exactly the appended entries ─────
    let snap = ledger.snapshot();
    assert_eq!(snap.entries.len(), 3);
    assert_eq!(snap.total_appended, 3);
    assert_eq!(snap.total_evicted, 0);
    h.log_phase("snapshot_consistent", true, json!({"entries": snap.entries.len()}));
}

#[test]
fn e2e_evidence_ledger_fifo_eviction_under_pressure() {
    let h = Harness::new("e2e_evidence_ledger_fifo_eviction_under_pressure");

    // Capacity: only 2 entries allowed. We append 5 to force 3 evictions.
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 8_192));

    for i in 0..5 {
        let mut e = test_entry(&format!("DEC-{i:03}"), i);
        e.timestamp_ms = 1_000 + i;
        ledger.append(e).expect("append");
    }

    // Final state: only the last 2 entries remain; 3 evictions occurred.
    assert_eq!(ledger.len(), 2, "ring buffer caps at 2 entries");
    assert_eq!(ledger.total_appended(), 5);
    assert_eq!(ledger.total_evicted(), 3);
    let kept: Vec<&str> = ledger
        .iter_all()
        .map(|(_, e, _)| e.decision_id.as_str())
        .collect();
    assert_eq!(kept, vec!["DEC-003", "DEC-004"], "FIFO eviction order");
    h.log_phase(
        "fifo_eviction",
        true,
        json!({"appended": 5, "evicted": 3, "kept": kept}),
    );
}

#[test]
fn e2e_evidence_ledger_capacity_rejection_paths() {
    let h = Harness::new("e2e_evidence_ledger_capacity_rejection_paths");

    // ── max_entries = 0: every append rejected ─────────────────────
    let mut zero_cap = EvidenceLedger::new(LedgerCapacity::new(0, 4_096));
    let zero_err = zero_cap
        .append(test_entry("DEC-zero", 1))
        .expect_err("zero-capacity ledger rejects appends");
    assert!(matches!(zero_err, LedgerError::ZeroEntryCapacity));
    h.log_phase("zero_capacity_rejected", true, json!({}));

    // ── entry too large: payload bigger than max_bytes ─────────────
    let mut tiny_bytes = EvidenceLedger::new(LedgerCapacity::new(8, 64));
    let mut bloated = test_entry("DEC-bloat", 1);
    // pad payload past the 64-byte cap with a long string field.
    bloated.payload = json!({"big": "x".repeat(512)});
    let too_big = tiny_bytes
        .append(bloated)
        .expect_err("entry larger than max_bytes rejected");
    match too_big {
        LedgerError::EntryTooLarge {
            entry_size,
            max_bytes,
        } => {
            assert!(entry_size > max_bytes);
            assert_eq!(max_bytes, 64);
            h.log_phase(
                "entry_too_large_rejected",
                true,
                json!({"entry_size": entry_size, "max_bytes": max_bytes}),
            );
        }
        other => panic!("expected EntryTooLarge, got {other:?}"),
    }
    assert!(tiny_bytes.is_empty(), "rejected entry must not occupy a slot");
}

#[test]
fn e2e_evidence_ledger_helpers_are_deterministic_and_reversible() {
    let h = Harness::new("e2e_evidence_ledger_helpers_are_deterministic_and_reversible");

    let key = signing_key();
    let mut a = test_entry("DEC-helper", 7);
    a.timestamp_ms = 7_777;
    sign_evidence_entry(&mut a, &key);

    // ── verify_evidence_entry round-trips for a freshly signed entry ──
    verify_evidence_entry(&a, &key.verifying_key()).expect("verify round-trip");
    h.log_phase("verify_round_trip", true, json!({}));

    // ── evidence_entry_hash_hex is stable across re-runs ─────────────
    let h1 = evidence_entry_hash_hex(&a);
    let h2 = evidence_entry_hash_hex(&a);
    assert_eq!(h1, h2, "hash must be deterministic for an unchanged entry");
    assert_eq!(h1.len(), 64, "hash must be sha256-hex (64 chars)");
    h.log_phase("hash_stable", true, json!({"hash": h1}));

    // ── tampering the entry changes its hash ────────────────────────
    let mut b = a.clone();
    b.decision_id = "DEC-helper-MUTATED".to_string();
    let h_mut = evidence_entry_hash_hex(&b);
    assert_ne!(h1, h_mut, "any field change must change the hash");
    h.log_phase("hash_changes_under_mutation", true, json!({}));

    // ── tampering invalidates verification under the same key ────────
    let verify_err = verify_evidence_entry(&b, &key.verifying_key());
    assert!(verify_err.is_err());
    h.log_phase("mutated_entry_fails_verify", true, json!({}));
}
