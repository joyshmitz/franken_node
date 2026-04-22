use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EvidenceEntry, EvidenceLedger, LabSpillMode, LedgerCapacity,
};

#[derive(Clone)]
struct CaptureWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer
            .lock()
            .map_err(|_| io::Error::other("capture buffer lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn misleading_size_entry(decision_id: &str, size_bytes: usize) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: DecisionKind::Admit,
        decision_time: "2026-04-22T00:00:00Z".to_string(),
        timestamp_ms: 1_776_816_000_000,
        trace_id: format!("trace-{decision_id}"),
        epoch_id: 42,
        payload: serde_json::json!({"actual": "small"}),
        size_bytes,
    }
}

#[test]
fn observability_ledger_uses_server_computed_size_for_snapshot_and_spill() {
    let attacker_claimed_size = 1_000_000;
    let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 10_000));

    ledger
        .append(misleading_size_entry(
            "observability-size-lie-snapshot",
            attacker_claimed_size,
        ))
        .expect("small payload should fit despite misleading size_bytes");
    let snapshot = ledger.snapshot();
    let stored = &snapshot.entries[0].1;

    assert_ne!(stored.size_bytes, attacker_claimed_size);
    assert_eq!(
        stored.size_bytes,
        serde_json::to_string(stored).unwrap().len()
    );
    assert_eq!(snapshot.current_bytes, stored.size_bytes);

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = CaptureWriter {
        buffer: Arc::clone(&buffer),
    };
    let mut spill = LabSpillMode::new(LedgerCapacity::new(10, 10_000), Box::new(writer));
    spill
        .append(misleading_size_entry(
            "observability-size-lie-spill",
            attacker_claimed_size,
        ))
        .expect("small payload should spill despite misleading size_bytes");

    let captured = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    let spilled: EvidenceEntry = serde_json::from_str(captured.trim()).unwrap();
    let spilled_snapshot = spill.snapshot();
    let retained = &spilled_snapshot.entries[0].1;

    assert_ne!(spilled.size_bytes, attacker_claimed_size);
    assert_eq!(
        spilled.size_bytes,
        serde_json::to_string(&spilled).unwrap().len()
    );
    assert_eq!(retained.size_bytes, spilled.size_bytes);
    assert_eq!(spilled_snapshot.current_bytes, spilled.size_bytes);
}
