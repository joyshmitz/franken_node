#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use frankenengine_node::tools::replay_bundle::{
    generate_replay_bundle, read_incident_evidence_package, replay_bundle_with_trusted_key,
    sign_replay_bundle, to_canonical_json, validate_bundle_integrity,
    verify_replay_bundle_signature, EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_EVENTS: usize = 16;
const MAX_RAW_JSON_BYTES: usize = 256 * 1024;
const MAX_TEXT_BYTES: usize = 512;
const CHUNK_STRESS_SENTINEL: u16 = 0xC0DE;

fuzz_target!(|input: FuzzInput| {
    fuzz_generated_bundle(&input);
    fuzz_raw_bundle_json(&input.raw_json);
});

fn fuzz_generated_bundle(input: &FuzzInput) {
    let incident_id = bounded_identifier(&input.incident_id, "INC-FUZZ");
    let events = build_events(input);
    let mut bundle = match generate_replay_bundle(&incident_id, &events) {
        Ok(bundle) => bundle,
        Err(_) => return,
    };

    assert!(
        validate_bundle_integrity(&bundle).expect("generated bundle integrity validation must run")
    );
    assert_eq!(
        usize::try_from(bundle.manifest.chunk_count).ok(),
        Some(bundle.chunks.len())
    );
    for chunk in &bundle.chunks {
        assert_eq!(chunk.bundle_id, bundle.bundle_id);
        assert_eq!(chunk.total_chunks, bundle.manifest.chunk_count);
        assert_eq!(chunk.event_count, chunk.events.len());
    }

    let canonical =
        to_canonical_json(&bundle).expect("generated bundle must export canonical JSON");
    let decoded: ReplayBundle =
        serde_json::from_str(&canonical).expect("canonical bundle JSON must deserialize");
    assert_eq!(
        canonical,
        to_canonical_json(&decoded).expect("decoded bundle must re-export canonically")
    );
    assert!(
        validate_bundle_integrity(&decoded).expect("decoded bundle integrity validation must run")
    );

    sign_and_verify_roundtrip(&mut bundle, canonical);
}

fn sign_and_verify_roundtrip(bundle: &mut ReplayBundle, unsigned_canonical: String) {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "fuzz-fixture",
        signing_identity: "fuzz-replay-bundle",
    };
    sign_replay_bundle(bundle, &material).expect("generated valid bundle must sign");
    let trusted_key_id = bundle
        .signature
        .as_ref()
        .expect("signing must attach signature")
        .key_id
        .clone();
    verify_replay_bundle_signature(bundle, Some(&trusted_key_id))
        .expect("trusted signed bundle must verify");
    let outcome = replay_bundle_with_trusted_key(bundle, &trusted_key_id)
        .expect("trusted signed bundle must replay");
    assert!(outcome.matched);

    let signed_canonical = to_canonical_json(bundle).expect("signed bundle must export");
    assert_ne!(unsigned_canonical, signed_canonical);
    let decoded: ReplayBundle =
        serde_json::from_str(&signed_canonical).expect("signed canonical JSON must parse");
    verify_replay_bundle_signature(&decoded, Some(&trusted_key_id))
        .expect("decoded trusted signed bundle must verify");
    assert_eq!(
        signed_canonical,
        to_canonical_json(&decoded).expect("decoded signed bundle must export deterministically")
    );
}

fn fuzz_raw_bundle_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let Ok(bundle) = serde_json::from_slice::<ReplayBundle>(bytes) else {
        return;
    };
    let Ok(valid) = validate_bundle_integrity(&bundle) else {
        return;
    };
    if !valid {
        return;
    }

    let Ok(canonical) = to_canonical_json(&bundle) else {
        return;
    };
    let decoded: ReplayBundle =
        serde_json::from_str(&canonical).expect("canonicalized valid bundle must parse");
    let recanonical = to_canonical_json(&decoded).expect("decoded valid bundle must canonicalize");
    assert_eq!(canonical, recanonical);

    if let Ok(path_text) = std::str::from_utf8(bytes) {
        let _ = read_incident_evidence_package(std::path::Path::new(path_text), None);
    }
}

fn build_events(input: &FuzzInput) -> Vec<RawEvent> {
    let limit = input.events.len().min(MAX_EVENTS);
    let mut events = Vec::with_capacity(limit.max(1));
    if limit == 0 {
        events.push(default_event(0, input));
        return events;
    }

    for (index, event) in input.events.iter().take(limit).enumerate() {
        let mut raw = RawEvent::new(
            timestamp_for_index(index),
            event.event_type.into(),
            payload_for_event(index, event, input.chunk_stress),
        );
        if event.include_snapshot {
            raw = raw.with_state_snapshot(json!({
                "index": index,
                "state": bounded_text(&event.text),
            }));
        }
        if event.include_policy_version {
            raw = raw.with_policy_version(format!("policy-{}", event.selector % 8));
        }
        if index > 0 && event.parent_delta % 3 == 0 {
            raw = raw.with_causal_parent(u64::try_from(index).unwrap_or(u64::MAX));
        }
        events.push(raw);
    }

    events
}

fn default_event(index: usize, input: &FuzzInput) -> RawEvent {
    RawEvent::new(
        timestamp_for_index(index),
        EventType::OperatorAction,
        json!({"default": bounded_text(&input.incident_id)}),
    )
}

fn payload_for_event(index: usize, event: &EventFuzz, chunk_stress: u16) -> Value {
    let payload_text = if chunk_stress == CHUNK_STRESS_SENTINEL && index == 0 {
        "x".repeat(10 * 1024 * 1024 + usize::from(event.selector))
    } else {
        bounded_text(&event.text)
    };

    json!({
        "event_index": index,
        "selector": event.selector,
        "message": payload_text,
        "bytes": event.bytes.iter().take(32).copied().collect::<Vec<u8>>(),
    })
}

fn timestamp_for_index(index: usize) -> String {
    format!("2026-04-21T00:00:{:02}Z", index % 60)
}

fn bounded_identifier(raw: &str, fallback: &str) -> String {
    let text = bounded_text(raw);
    if text.trim().is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

fn bounded_text(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_BYTES)
        .collect();
    if out.is_empty() {
        out.push('x');
    }
    out
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    incident_id: String,
    events: Vec<EventFuzz>,
    chunk_stress: u16,
    raw_json: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct EventFuzz {
    event_type: FuzzEventType,
    text: String,
    bytes: Vec<u8>,
    selector: u8,
    parent_delta: u8,
    include_snapshot: bool,
    include_policy_version: bool,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzEventType {
    StateChange,
    PolicyEval,
    ExternalSignal,
    OperatorAction,
}

impl From<FuzzEventType> for EventType {
    fn from(value: FuzzEventType) -> Self {
        match value {
            FuzzEventType::StateChange => Self::StateChange,
            FuzzEventType::PolicyEval => Self::PolicyEval,
            FuzzEventType::ExternalSignal => Self::ExternalSignal,
            FuzzEventType::OperatorAction => Self::OperatorAction,
        }
    }
}
