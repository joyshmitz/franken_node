#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::tools::replay_bundle::{
    generate_replay_bundle_from_evidence, validate_incident_evidence_package, EventType,
    IncidentEvidenceEvent, IncidentEvidenceMetadata, IncidentEvidencePackage, IncidentSeverity,
    INCIDENT_EVIDENCE_SCHEMA,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const MAX_EVENTS: usize = 16;
const MAX_EVIDENCE_REFS: usize = 16;
const MAX_RAW_JSON_BYTES: usize = 256 * 1024;
const MAX_TEXT_CHARS: usize = 256;

fuzz_target!(|input: IncidentBundleParseInput| {
    fuzz_structured_incident_package(&input);
    fuzz_raw_incident_package_json(&input.raw_json);
});

fn fuzz_structured_incident_package(input: &IncidentBundleParseInput) {
    let package = incident_package(input);
    json_roundtrip(&package);

    let expected_incident_id = expected_incident_id(input, &package);
    let validation = validate_incident_evidence_package(&package, expected_incident_id.as_deref());
    if validation.is_ok() {
        let bundle = generate_replay_bundle_from_evidence(&package)
            .expect("validated incident evidence package must generate bundle");
        assert_eq!(bundle.incident_id, package.incident_id);
        assert_eq!(bundle.timeline.len(), package.events.len());
        assert_eq!(bundle.manifest.event_count, package.events.len());
        assert_eq!(
            bundle.initial_state_snapshot,
            package.initial_state_snapshot
        );
    }
}

fn fuzz_raw_incident_package_json(bytes: &[u8]) {
    if bytes.len() > MAX_RAW_JSON_BYTES {
        return;
    }

    let Ok(package) = serde_json::from_slice::<IncidentEvidencePackage>(bytes) else {
        return;
    };
    json_roundtrip(&package);

    let validation = validate_incident_evidence_package(&package, None);
    if validation.is_ok() {
        let bundle = generate_replay_bundle_from_evidence(&package)
            .expect("validated raw incident evidence package must generate bundle");
        assert_eq!(bundle.incident_id, package.incident_id);
        assert_eq!(bundle.manifest.event_count, package.events.len());
    }
}

fn json_roundtrip(package: &IncidentEvidencePackage) {
    let encoded = serde_json::to_string(package).expect("incident package JSON encode");
    let decoded: IncidentEvidencePackage =
        serde_json::from_str(&encoded).expect("incident package JSON decode");
    assert_eq!(&decoded, package);
}

fn incident_package(input: &IncidentBundleParseInput) -> IncidentEvidencePackage {
    let incident_id = bounded_identifier(&input.incident_id, "INC-FUZZ");
    let evidence_refs = evidence_refs(input);
    let events = incident_events(input, &evidence_refs);

    IncidentEvidencePackage {
        schema_version: schema_version(input.schema_selector),
        incident_id,
        collected_at: timestamp_for_index(0),
        trace_id: bounded_identifier(&input.trace_id, "trace-fuzz"),
        severity: input.severity.into(),
        incident_type: bounded_identifier(&input.incident_type, "runtime_fault"),
        detector: bounded_identifier(&input.detector, "fuzz-detector"),
        policy_version: format!("policy-{}", input.policy_selector % 16),
        initial_state_snapshot: payload_value(&input.initial_state, 0, input.shape_selector),
        events,
        evidence_refs,
        metadata: IncidentEvidenceMetadata {
            title: bounded_text(&input.title, "fuzz incident"),
            affected_components: input
                .components
                .iter()
                .take(MAX_EVIDENCE_REFS)
                .enumerate()
                .map(|(index, component)| {
                    format!("component-{index}-{}", bounded_text(component, "runtime"))
                })
                .collect(),
            tags: input
                .tags
                .iter()
                .take(MAX_EVIDENCE_REFS)
                .map(|tag| bounded_identifier(tag, "fuzz"))
                .collect(),
        },
    }
}

fn incident_events(
    input: &IncidentBundleParseInput,
    evidence_refs: &[String],
) -> Vec<IncidentEvidenceEvent> {
    if input.events.is_empty() {
        return vec![IncidentEvidenceEvent {
            event_id: "evt-0000-default".to_string(),
            timestamp: timestamp_for_index(1),
            event_type: EventType::OperatorAction,
            payload: payload_value(&input.initial_state, 0, input.shape_selector),
            provenance_ref: evidence_refs
                .first()
                .cloned()
                .unwrap_or_else(|| "evidence/default.json".to_string()),
            parent_event_id: None,
            state_snapshot: None,
            policy_version: Some(format!("policy-{}", input.policy_selector % 16)),
        }];
    }

    let event_count = input.events.len().min(MAX_EVENTS);
    (0..event_count)
        .map(|index| {
            let event_input = &input.events[index];
            let event_id = format!(
                "evt-{index:04}-{}",
                bounded_identifier(&event_input.id, "id")
            );
            let parent_event_id = if index > 0 && event_input.parent_previous {
                Some(format!(
                    "evt-{:04}-{}",
                    index - 1,
                    bounded_identifier(&input.events[index - 1].id, "id")
                ))
            } else {
                None
            };
            let provenance_ref = evidence_refs
                .get(index % evidence_refs.len().max(1))
                .cloned()
                .unwrap_or_else(|| "evidence/default.json".to_string());

            IncidentEvidenceEvent {
                event_id,
                timestamp: timestamp_for_index(index.saturating_add(1)),
                event_type: event_input.event_type.into(),
                payload: payload_value(&event_input.payload, index, input.shape_selector),
                provenance_ref,
                parent_event_id,
                state_snapshot: event_input
                    .include_state
                    .then(|| payload_value(&event_input.state, index, input.shape_selector)),
                policy_version: event_input
                    .include_policy
                    .then(|| format!("policy-{}", event_input.policy_selector % 16)),
            }
        })
        .collect()
}

fn evidence_refs(input: &IncidentBundleParseInput) -> Vec<String> {
    let refs = input
        .evidence_refs
        .iter()
        .take(MAX_EVIDENCE_REFS)
        .enumerate()
        .map(|(index, reference)| {
            format!(
                "evidence/{index}/{}.json",
                bounded_identifier(reference, "receipt")
            )
        })
        .collect::<Vec<_>>();
    if refs.is_empty() {
        vec!["evidence/default.json".to_string()]
    } else {
        refs
    }
}

fn expected_incident_id(
    input: &IncidentBundleParseInput,
    package: &IncidentEvidencePackage,
) -> Option<String> {
    match input.expected_selector % 3 {
        0 => None,
        1 => Some(package.incident_id.clone()),
        _ => Some(format!("{}-mismatch", package.incident_id)),
    }
}

fn schema_version(selector: u8) -> String {
    if selector % 7 == 0 {
        format!("{INCIDENT_EVIDENCE_SCHEMA}-future")
    } else {
        INCIDENT_EVIDENCE_SCHEMA.to_string()
    }
}

fn payload_value(raw: &[u8], index: usize, selector: u8) -> Value {
    let text = bounded_bytes(raw);
    match selector % 5 {
        0 => json!({ "index": index, "text": text }),
        1 => json!([
            index,
            text,
            raw.iter().take(16).copied().collect::<Vec<u8>>()
        ]),
        2 => json!({ "nested": { "index": index, "flag": index % 2 == 0 } }),
        3 => json!(text),
        _ => json!(index),
    }
}

fn timestamp_for_index(index: usize) -> String {
    format!("2026-04-21T00:00:{:02}Z", index % 60)
}

fn bounded_identifier(raw: &str, fallback: &str) -> String {
    let text = bounded_text(raw, fallback)
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '@') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if text.trim_matches('-').is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

fn bounded_text(raw: &str, fallback: &str) -> String {
    let text = raw.chars().take(MAX_TEXT_CHARS).collect::<String>();
    if text.trim().is_empty() {
        fallback.to_string()
    } else {
        text
    }
}

fn bounded_bytes(raw: &[u8]) -> String {
    String::from_utf8_lossy(&raw[..raw.len().min(MAX_TEXT_CHARS)]).into_owned()
}

#[derive(Debug, Arbitrary)]
struct IncidentBundleParseInput {
    raw_json: Vec<u8>,
    schema_selector: u8,
    expected_selector: u8,
    policy_selector: u8,
    shape_selector: u8,
    severity: SeverityFuzz,
    incident_id: String,
    trace_id: String,
    incident_type: String,
    detector: String,
    title: String,
    initial_state: Vec<u8>,
    evidence_refs: Vec<String>,
    components: Vec<String>,
    tags: Vec<String>,
    events: Vec<EventFuzz>,
}

#[derive(Debug, Arbitrary)]
struct EventFuzz {
    id: String,
    event_type: EventTypeFuzz,
    payload: Vec<u8>,
    state: Vec<u8>,
    parent_previous: bool,
    include_state: bool,
    include_policy: bool,
    policy_selector: u8,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
struct SeverityFuzz(u8);

impl From<SeverityFuzz> for IncidentSeverity {
    fn from(value: SeverityFuzz) -> Self {
        match value.0 % 5 {
            0 => Self::Low,
            1 => Self::Medium,
            2 => Self::High,
            3 => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, Arbitrary)]
struct EventTypeFuzz(u8);

impl From<EventTypeFuzz> for EventType {
    fn from(value: EventTypeFuzz) -> Self {
        match value.0 % 4 {
            0 => Self::StateChange,
            1 => Self::PolicyEval,
            2 => Self::ExternalSignal,
            _ => Self::OperatorAction,
        }
    }
}
