use frankenengine_node::connector::canonical_serializer::{
    CanonicalSerializer, SerializerError, SignaturePreimage, TrustObjectType, event_codes,
};
use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundle, ReplayBundleSigningMaterial, generate_replay_bundle,
    replay_bundle_with_trusted_key, sign_replay_bundle, to_canonical_json,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const TEXT_DEPTH_LIMIT: usize = 12;
const LONG_FUZZ_DURATION_SECS: u64 = 60;
const SHORT_FUZZ_DURATION_MILLIS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationExpectation {
    AcceptCanonical,
    RejectFloat,
}

#[derive(Debug, Clone, Copy)]
struct StructuredMutationCase {
    name: &'static str,
    payload: &'static str,
    expectation: MutationExpectation,
}

#[derive(Debug, Default)]
struct MutationCampaignStats {
    iterations: u64,
    accept_cases: u64,
    reject_cases: u64,
}

fn replay_grammar_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[44_u8; 32])
}

fn replay_grammar_trusted_key_id() -> String {
    let signing_key = replay_grammar_signing_key();
    frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_key.verifying_key(),
    )
    .to_string()
}

fn sign_replay_grammar_bundle(bundle: &mut ReplayBundle) {
    let signing_key = replay_grammar_signing_key();
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "test",
        signing_identity: "canonical-serializer-fuzz",
    };
    sign_replay_bundle(bundle, &signing_material).expect("sign replay grammar bundle");
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HarnessDecodeError {
    Serializer(String),
    Utf8,
    Json(String),
    DepthLimit { depth: usize, limit: usize },
    ShortPreimage,
    InvalidDomainTag { expected: [u8; 2], actual: [u8; 2] },
}

impl From<SerializerError> for HarnessDecodeError {
    fn from(error: SerializerError) -> Self {
        Self::Serializer(error.to_string())
    }
}

#[derive(Debug, Clone)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn seeded(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn choose_index(&mut self, len: usize) -> usize {
        assert!(len > 0, "cannot choose from empty slice");
        (self.next_u64() % u64::try_from(len).expect("slice length fits u64")) as usize
    }
}

fn seed_payloads() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"{}".to_vec(),
        br#"{"a":1}"#.to_vec(),
        br#"{"array":[1,2,3],"flag":true}"#.to_vec(),
        br#"{"nested":{"left":"right"}}"#.to_vec(),
        b"plain-text-payload".to_vec(),
        vec![0x00, 0x01, 0x02, 0x7f],
        vec![0xff; 64],
        (0u8..=31).collect(),
    ]
}

fn encoded_payload(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("seed payload fits canonical length prefix");
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

fn deserialize_text_payload(
    serializer: &CanonicalSerializer,
    object_type: TrustObjectType,
    canonical: &[u8],
) -> Result<String, HarnessDecodeError> {
    let payload = serializer.deserialize(object_type, canonical)?;
    String::from_utf8(payload).map_err(|_| HarnessDecodeError::Utf8)
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => items
            .iter()
            .map(json_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        Value::Object(fields) => fields
            .values()
            .map(json_depth)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
        _ => 1,
    }
}

fn deserialize_json_with_depth_limit(
    serializer: &CanonicalSerializer,
    object_type: TrustObjectType,
    canonical: &[u8],
    limit: usize,
) -> Result<Value, HarnessDecodeError> {
    let text = deserialize_text_payload(serializer, object_type, canonical)?;
    let value: Value =
        serde_json::from_str(&text).map_err(|error| HarnessDecodeError::Json(error.to_string()))?;
    let depth = json_depth(&value);
    if depth > limit {
        return Err(HarnessDecodeError::DepthLimit { depth, limit });
    }
    Ok(value)
}

fn parse_preimage_for_type(
    object_type: TrustObjectType,
    bytes: &[u8],
) -> Result<SignaturePreimage, HarnessDecodeError> {
    if bytes.len() < 3 {
        return Err(HarnessDecodeError::ShortPreimage);
    }

    let expected = object_type.domain_tag();
    let actual = [bytes[1], bytes[2]];
    if actual != expected {
        return Err(HarnessDecodeError::InvalidDomainTag { expected, actual });
    }

    Ok(SignaturePreimage::build(
        bytes[0],
        actual,
        bytes[3..].to_vec(),
    ))
}

fn deeply_nested_json(depth: usize) -> Vec<u8> {
    let mut text = String::from("0");
    for _ in 0..depth {
        text = format!(r#"{{"n":{text}}}"#);
    }
    text.into_bytes()
}

fn structured_mutation_corpus() -> &'static [StructuredMutationCase] {
    &[
        StructuredMutationCase {
            name: "leading-space-decimal",
            payload: r#" {"score":3.14}"#,
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-newline-tab-scientific",
            payload: "\n\t{\"score\":1e9}",
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-crlf-array-infinity",
            payload: "\r\n[{\"score\":Infinity}]",
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-tab-escaped-quote-real-float",
            payload: "\t{\"note\":\"quoted \\\"1.0\\\" text\",\"score\":3.14}",
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-space-version-string-nested-float",
            payload: r#" {"version":"1.0.0","nested":{"score":9.5}}"#,
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-crlf-signed-exponent-after-string",
            payload: "\r\n{\"note\":\"1E-9 stays text\",\"score\":6E23}",
            expectation: MutationExpectation::RejectFloat,
        },
        StructuredMutationCase {
            name: "leading-space-integer-object",
            payload: r#" {"score":42,"count":7}"#,
            expectation: MutationExpectation::AcceptCanonical,
        },
        StructuredMutationCase {
            name: "leading-tab-version-string-only",
            payload: "\t{\"version\":\"1.0.0\",\"count\":42}",
            expectation: MutationExpectation::AcceptCanonical,
        },
        StructuredMutationCase {
            name: "leading-newline-escaped-quote-string-only",
            payload: "\n{\"note\":\"quoted \\\"1.5\\\" text\",\"count\":7}",
            expectation: MutationExpectation::AcceptCanonical,
        },
        StructuredMutationCase {
            name: "leading-crlf-scientific-string-only",
            payload: "\r\n{\"note\":\"1e9 stays text\",\"count\":100}",
            expectation: MutationExpectation::AcceptCanonical,
        },
        StructuredMutationCase {
            name: "leading-space-version-array-labels",
            payload: r#" [{"label":"v1.0.0"},{"count":3}]"#,
            expectation: MutationExpectation::AcceptCanonical,
        },
    ]
}

fn whitespace_prefix(rng: &mut XorShift64) -> &'static str {
    const PREFIXES: &[&str] = &["", " ", "\t", "\n", "\r\n", " \n\t", "\r\n \t"];
    PREFIXES[rng.choose_index(PREFIXES.len())]
}

fn wrap_case_payload(
    expectation: MutationExpectation,
    core_payload: &str,
    rng: &mut XorShift64,
) -> String {
    match expectation {
        MutationExpectation::RejectFloat => match rng.choose_index(4) {
            0 => core_payload.to_string(),
            1 => format!(r#"{{"outer":{core_payload}}}"#),
            2 => format!(r#"[{core_payload},{{"note":"1.0.0 stays text"}}]"#),
            _ => format!(r#"{{"note":"quoted \"1.0\" text","payload":{core_payload},"epoch":7}}"#),
        },
        MutationExpectation::AcceptCanonical => match rng.choose_index(4) {
            0 => core_payload.to_string(),
            1 => format!(r#"{{"outer":{core_payload},"note":"1.0.0 stays text"}}"#),
            2 => format!(r#"[{core_payload},{{"note":"1e9 stays text"}}]"#),
            _ => format!(r#"{{"payload":{core_payload},"note":"quoted \"1.5\" text","count":7}}"#),
        },
    }
}

fn mutate_structured_case(case: StructuredMutationCase, rng: &mut XorShift64) -> Vec<u8> {
    let mut text = wrap_case_payload(case.expectation, case.payload.trim_start(), rng);

    if rng.choose_index(2) == 1 {
        text = match case.expectation {
            MutationExpectation::RejectFloat => {
                format!(r#"{{"meta":"v1.0.0","payload":{text}}}"#)
            }
            MutationExpectation::AcceptCanonical => {
                format!(r#"[{text},{{"meta":"v1.0.0","count":3}}]"#)
            }
        };
    }

    format!("{}{}", whitespace_prefix(rng), text).into_bytes()
}

fn assert_mutation_case_oracle(
    case_name: &str,
    object_type: TrustObjectType,
    expectation: MutationExpectation,
    payload: &[u8],
) {
    match expectation {
        MutationExpectation::RejectFloat => {
            let mut serialize_serializer = CanonicalSerializer::with_all_schemas();
            let serialize_result = serialize_serializer.serialize(object_type, payload, case_name);
            assert!(
                matches!(
                    serialize_result,
                    Err(SerializerError::FloatingPointRejected { .. })
                ),
                "{case_name} should reject float payload during serialize: {}",
                String::from_utf8_lossy(payload)
            );
            assert!(
                serialize_serializer
                    .events()
                    .iter()
                    .all(|event| event.event_code != event_codes::CAN_PREIMAGE_CONSTRUCT),
                "{case_name} must not emit a preimage event after float rejection"
            );

            let mut preimage_serializer = CanonicalSerializer::with_all_schemas();
            let preimage_result =
                preimage_serializer.build_preimage(object_type, payload, case_name);
            assert!(
                matches!(
                    preimage_result,
                    Err(SerializerError::FloatingPointRejected { .. })
                ),
                "{case_name} should reject float payload during preimage build: {}",
                String::from_utf8_lossy(payload)
            );
            assert!(
                preimage_serializer
                    .events()
                    .iter()
                    .all(|event| event.event_code != event_codes::CAN_PREIMAGE_CONSTRUCT),
                "{case_name} must not emit a preimage event after build_preimage rejection"
            );
        }
        MutationExpectation::AcceptCanonical => {
            let mut serializer = CanonicalSerializer::with_all_schemas();
            let canonical = serializer
                .serialize(object_type, payload, case_name)
                .expect("non-float structured payload should serialize");
            assert_eq!(
                canonical,
                encoded_payload(payload),
                "{case_name} canonical output must remain length-prefixed identity"
            );
            let decoded = serializer
                .deserialize(object_type, &canonical)
                .expect("canonical payload must deserialize");
            assert_eq!(decoded, payload, "{case_name} payload must round-trip");

            let round_trip = serializer
                .round_trip_canonical(object_type, payload, case_name)
                .expect("accepted structured payload must round-trip");
            assert_eq!(
                round_trip, canonical,
                "{case_name} round-trip must be byte-stable"
            );

            let preimage = serializer
                .build_preimage(object_type, payload, case_name)
                .expect("accepted structured payload must build a preimage");
            assert_eq!(preimage.domain_tag, object_type.domain_tag(), "{case_name}");
            assert_eq!(preimage.canonical_payload, canonical, "{case_name}");
            let parsed =
                parse_preimage_for_type(object_type, &preimage.to_bytes()).expect("parse preimage");
            assert_eq!(parsed, preimage, "{case_name}");
            assert!(
                serializer
                    .events()
                    .iter()
                    .any(|event| event.event_code == event_codes::CAN_PREIMAGE_CONSTRUCT),
                "{case_name} should emit a preimage construct event"
            );
        }
    }
}

fn run_mutation_campaign(duration: Duration) -> MutationCampaignStats {
    let start = Instant::now();
    let mut rng = XorShift64::seeded(0xC0DE_1625_1D4D_D397);
    let corpus = structured_mutation_corpus();
    let mut stats = MutationCampaignStats::default();

    for (index, case) in corpus.iter().copied().enumerate() {
        let object_type = TrustObjectType::all()[index % TrustObjectType::all().len()];
        let mutated = mutate_structured_case(case, &mut rng);
        assert!(
            mutated.len() <= 16 * 1024,
            "mutation output should stay bounded for fuzz throughput"
        );
        assert_mutation_case_oracle(case.name, object_type, case.expectation, &mutated);
        stats.iterations = stats.iterations.saturating_add(1);
        match case.expectation {
            MutationExpectation::AcceptCanonical => {
                stats.accept_cases = stats.accept_cases.saturating_add(1)
            }
            MutationExpectation::RejectFloat => {
                stats.reject_cases = stats.reject_cases.saturating_add(1)
            }
        }
    }

    while start.elapsed() < duration {
        let case = corpus[rng.choose_index(corpus.len())];
        let object_type = TrustObjectType::all()[rng.choose_index(TrustObjectType::all().len())];
        let mutated = mutate_structured_case(case, &mut rng);
        assert!(
            mutated.len() <= 16 * 1024,
            "mutation output should stay bounded for fuzz throughput"
        );
        assert_mutation_case_oracle(case.name, object_type, case.expectation, &mutated);
        stats.iterations = stats.iterations.saturating_add(1);
        match case.expectation {
            MutationExpectation::AcceptCanonical => {
                stats.accept_cases = stats.accept_cases.saturating_add(1)
            }
            MutationExpectation::RejectFloat => {
                stats.reject_cases = stats.reject_cases.saturating_add(1)
            }
        }
    }

    stats
}

fn replay_grammar_event_logs() -> Vec<(&'static str, Vec<RawEvent>)> {
    vec![
        (
            "minimal",
            vec![
                RawEvent::new(
                    "2026-02-20T10:00:00.000001Z",
                    EventType::ExternalSignal,
                    json!({"signal":"anomaly","severity":"high"}),
                )
                .with_state_snapshot(json!({"epoch":7_u64,"mode":"strict"}))
                .with_policy_version("1.2.3"),
            ],
        ),
        (
            "causal-chain",
            vec![
                RawEvent::new(
                    "2026-02-20T10:00:00.000001Z",
                    EventType::ExternalSignal,
                    json!({"signal":"anomaly","severity":"high"}),
                )
                .with_state_snapshot(json!({"epoch":7_u64,"mode":"strict"}))
                .with_policy_version("1.2.3"),
                RawEvent::new(
                    "2026-02-20T10:00:00.000002Z",
                    EventType::PolicyEval,
                    json!({"decision":"quarantine","confidence":91_u64}),
                )
                .with_causal_parent(1),
                RawEvent::new(
                    "2026-02-20T10:00:00.000003Z",
                    EventType::OperatorAction,
                    json!({"action":"seal","result":"accepted"}),
                )
                .with_causal_parent(2),
            ],
        ),
        (
            "out-of-order",
            vec![
                RawEvent::new(
                    "2026-02-20T10:00:00.000300Z",
                    EventType::OperatorAction,
                    json!({"action":"seal","result":"accepted"}),
                ),
                RawEvent::new(
                    "2026-02-20T10:00:00.000100Z",
                    EventType::ExternalSignal,
                    json!({"signal":"anomaly","severity":"medium"}),
                )
                .with_state_snapshot(json!({"epoch":8_u64,"mode":"balanced"}))
                .with_policy_version("1.2.4"),
            ],
        ),
        (
            "nested-payload",
            vec![
                RawEvent::new(
                    "2026-02-20T10:00:00.000001Z",
                    EventType::ExternalSignal,
                    json!({
                        "signal": "anomaly",
                        "evidence": {
                            "artifacts": [
                                {"kind": "hash", "value": "sha256:abc"},
                                {"kind": "receipt", "value": "receipt-1"}
                            ],
                            "scores": {"risk": 95_u64, "impact": 7_u64}
                        }
                    }),
                )
                .with_state_snapshot(json!({"epoch":9_u64,"mode":"strict"}))
                .with_policy_version("1.2.5"),
            ],
        ),
    ]
}

fn replay_bundle_payloads() -> Vec<(&'static str, Vec<u8>)> {
    replay_grammar_event_logs()
        .into_iter()
        .map(|(name, events)| {
            let incident_id = format!("INC-FUZZ-{name}");
            let bundle =
                generate_replay_bundle(&incident_id, &events).expect("replay grammar should build");
            let canonical_json = to_canonical_json(&bundle).expect("bundle should canonicalize");
            (name, canonical_json.into_bytes())
        })
        .collect()
}

#[test]
fn fuzz_round_trip_identity_across_object_types_and_seed_corpus() {
    let mut serializer = CanonicalSerializer::with_all_schemas();

    for object_type in TrustObjectType::all() {
        for payload in seed_payloads() {
            let canonical = serializer
                .round_trip_canonical(*object_type, &payload, "fuzz-rt")
                .expect("seed payload should round-trip canonically");
            let decoded = serializer
                .deserialize(*object_type, &canonical)
                .expect("round-trip output should decode");
            assert_eq!(decoded, payload);
            assert_eq!(canonical, encoded_payload(&payload));
        }
    }
}

#[test]
fn fuzz_repeated_serialization_is_byte_deterministic() {
    for object_type in TrustObjectType::all() {
        for payload in seed_payloads() {
            let mut first_serializer = CanonicalSerializer::with_all_schemas();
            let mut second_serializer = CanonicalSerializer::with_all_schemas();
            let first = first_serializer
                .serialize(*object_type, &payload, "fuzz-det-a")
                .expect("first serialization should succeed");
            let second = second_serializer
                .serialize(*object_type, &payload, "fuzz-det-b")
                .expect("second serialization should succeed");
            assert_eq!(first, second);
        }
    }
}

#[test]
fn fuzz_distinct_inputs_have_distinct_canonical_outputs() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let payloads = seed_payloads();
    let mut outputs = BTreeSet::new();

    for payload in &payloads {
        let canonical = serializer
            .serialize(
                TrustObjectType::PolicyCheckpoint,
                payload,
                "fuzz-uniqueness",
            )
            .expect("seed payload should serialize");
        assert!(
            outputs.insert(canonical),
            "duplicate canonical output for payload {:?}",
            payload
        );
    }

    assert_eq!(outputs.len(), payloads.len());
}

#[test]
fn fuzz_length_prefix_boundaries_round_trip_exactly() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let boundary_payloads = [
        Vec::new(),
        vec![b'a'],
        vec![b'b'; 255],
        vec![b'c'; 256],
        vec![b'd'; 257],
        vec![b'e'; 1024],
    ];

    for payload in boundary_payloads {
        let canonical = serializer
            .serialize(TrustObjectType::DelegationToken, &payload, "fuzz-prefix")
            .expect("boundary payload should serialize");
        assert_eq!(canonical, encoded_payload(&payload));
        assert_eq!(
            serializer
                .deserialize(TrustObjectType::DelegationToken, &canonical)
                .expect("boundary payload should deserialize"),
            payload
        );
    }
}

#[test]
fn fuzz_malformed_utf8_is_rejected_by_text_artifact_boundary() {
    let serializer = CanonicalSerializer::with_all_schemas();
    let malformed_utf8 = encoded_payload(&[0xf0, 0x28, 0x8c, 0x28]);
    let result = deserialize_text_payload(
        &serializer,
        TrustObjectType::OperatorReceipt,
        &malformed_utf8,
    );

    assert_eq!(result, Err(HarnessDecodeError::Utf8));
}

#[test]
fn fuzz_truncated_length_prefixed_inputs_are_rejected() {
    let serializer = CanonicalSerializer::with_all_schemas();
    let cases = [
        Vec::new(),
        vec![0x00],
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00],
        vec![0x00, 0x00, 0x00, 0x05],
        vec![0x00, 0x00, 0x00, 0x05, b'a', b'b', b'c', b'd'],
    ];

    for case in cases {
        let result = serializer.deserialize(TrustObjectType::SessionTicket, &case);
        assert!(
            matches!(result, Err(SerializerError::NonCanonicalInput { .. })),
            "truncated case should fail closed: {:?}",
            case
        );
    }
}

#[test]
fn fuzz_invalid_length_tags_with_extra_payload_are_rejected() {
    let serializer = CanonicalSerializer::with_all_schemas();
    let cases = [
        vec![0x00, 0x00, 0x00, 0x00, b'x'],
        vec![0x00, 0x00, 0x00, 0x01, b'a', b'b'],
        vec![0x00, 0x00, 0x00, 0x02, b'a', b'b', b'c'],
        vec![0x00, 0x00, 0x01, 0x00, b'a'],
    ];

    for case in cases {
        let result = serializer.deserialize(TrustObjectType::ZoneBoundaryClaim, &case);
        assert!(
            matches!(result, Err(SerializerError::NonCanonicalInput { .. })),
            "invalid length tag should fail closed: {:?}",
            case
        );
    }
}

#[test]
fn fuzz_invalid_domain_tag_preimage_is_rejected() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let preimage = serializer
        .build_preimage(
            TrustObjectType::RevocationAssertion,
            br#"{"revoked":"extension-a"}"#,
            "fuzz-tag",
        )
        .expect("valid preimage should build");
    let mut tampered = preimage.to_bytes();
    tampered[1] ^= 0x01;

    let result = parse_preimage_for_type(TrustObjectType::RevocationAssertion, &tampered);
    assert!(matches!(
        result,
        Err(HarnessDecodeError::InvalidDomainTag { .. })
    ));
}

#[test]
fn fuzz_short_preimage_is_rejected_before_tag_read() {
    for bytes in [Vec::new(), vec![1], vec![1, 0x10]] {
        let result = parse_preimage_for_type(TrustObjectType::PolicyCheckpoint, &bytes);
        assert_eq!(result, Err(HarnessDecodeError::ShortPreimage));
    }
}

#[test]
fn fuzz_nested_json_depth_limit_hit_is_rejected() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let payload = deeply_nested_json(TEXT_DEPTH_LIMIT.saturating_add(3));
    let canonical = serializer
        .serialize(TrustObjectType::PolicyCheckpoint, &payload, "fuzz-depth")
        .expect("deep JSON bytes should serialize before text depth validation");

    let result = deserialize_json_with_depth_limit(
        &serializer,
        TrustObjectType::PolicyCheckpoint,
        &canonical,
        TEXT_DEPTH_LIMIT,
    );

    assert!(matches!(
        result,
        Err(HarnessDecodeError::DepthLimit {
            depth: _,
            limit: TEXT_DEPTH_LIMIT
        })
    ));
}

#[test]
fn fuzz_valid_nested_json_at_limit_is_accepted() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let payload = deeply_nested_json(TEXT_DEPTH_LIMIT.saturating_sub(1));
    let canonical = serializer
        .serialize(TrustObjectType::PolicyCheckpoint, &payload, "fuzz-depth-ok")
        .expect("bounded-depth JSON should serialize");

    let result = deserialize_json_with_depth_limit(
        &serializer,
        TrustObjectType::PolicyCheckpoint,
        &canonical,
        TEXT_DEPTH_LIMIT,
    );

    assert!(result.is_ok());
}

#[test]
fn fuzz_structured_mutation_corpus_covers_recent_float_guard_regressions() {
    let names: BTreeSet<_> = structured_mutation_corpus()
        .iter()
        .map(|case| case.name)
        .collect();
    for required in [
        "leading-tab-escaped-quote-real-float",
        "leading-space-version-string-nested-float",
        "leading-crlf-signed-exponent-after-string",
    ] {
        assert!(
            names.contains(required),
            "missing churn-derived corpus case {required}"
        );
    }

    let reject_count = structured_mutation_corpus()
        .iter()
        .filter(|case| case.expectation == MutationExpectation::RejectFloat)
        .count();
    let accept_count = structured_mutation_corpus()
        .iter()
        .filter(|case| case.expectation == MutationExpectation::AcceptCanonical)
        .count();
    assert!(reject_count >= 6, "need broad float-rejection coverage");
    assert!(accept_count >= 5, "need false-positive guard coverage");
}

#[test]
fn fuzz_structured_mutation_corpus_matches_labelled_oracle() {
    for case in structured_mutation_corpus() {
        assert_mutation_case_oracle(
            case.name,
            TrustObjectType::OperatorReceipt,
            case.expectation,
            case.payload.as_bytes(),
        );
    }
}

#[test]
fn fuzz_structured_mutation_campaign_smoke() {
    let stats = run_mutation_campaign(Duration::from_millis(SHORT_FUZZ_DURATION_MILLIS));
    assert!(
        stats.iterations > 0,
        "smoke campaign must exercise at least one input"
    );
    assert!(
        stats.reject_cases > 0,
        "smoke campaign must hit float rejection paths"
    );
    assert!(
        stats.accept_cases > 0,
        "smoke campaign must hit acceptance paths"
    );
}

#[test]
#[ignore = "long-running structure-aware mutation campaign"]
fn fuzz_structured_mutation_campaign_60s() {
    let stats = run_mutation_campaign(Duration::from_secs(LONG_FUZZ_DURATION_SECS));
    assert!(
        stats.iterations >= 1_000,
        "60s campaign should cover many mutations"
    );
    assert!(stats.reject_cases > 0, "campaign must hit reject cases");
    assert!(stats.accept_cases > 0, "campaign must hit accept cases");
}

#[test]
fn fuzz_json_float_payloads_are_rejected_as_non_canonical() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let cases = [
        br#"{"score":3.14}"#.as_slice(),
        b" {\"score\":3.14}".as_slice(),
        b"\n\t{\"score\":1e9}".as_slice(),
        b"\r\n[{\"score\":Infinity}]".as_slice(),
        b"\t{\"note\":\"quoted \\\"1.0\\\" text\",\"score\":3.14}".as_slice(),
        b" {\"version\":\"1.0.0\",\"nested\":{\"score\":9.5}}".as_slice(),
        b"\r\n{\"note\":\"1E-9 stays text\",\"score\":6E23}".as_slice(),
        br#"[1,2.5,3]"#.as_slice(),
        br#"{"nested":{"score":9.5}}"#.as_slice(),
    ];

    for payload in cases {
        let result = serializer.serialize(TrustObjectType::OperatorReceipt, payload, "fuzz-float");
        assert!(
            matches!(result, Err(SerializerError::FloatingPointRejected { .. })),
            "float payload should be rejected: {}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn fuzz_replay_bundle_grammar_payloads_round_trip_through_serializer() {
    let mut serializer = CanonicalSerializer::with_all_schemas();

    for (name, payload) in replay_bundle_payloads() {
        let canonical = serializer
            .serialize(
                TrustObjectType::OperatorReceipt,
                &payload,
                "fuzz-replay-grammar",
            )
            .expect("replay bundle grammar payload should serialize");
        assert_eq!(canonical, encoded_payload(&payload), "{name}");

        let decoded = serializer
            .deserialize(TrustObjectType::OperatorReceipt, &canonical)
            .expect("replay bundle grammar payload should deserialize");
        assert_eq!(decoded, payload, "{name}");

        let decoded_value: Value =
            serde_json::from_slice(&decoded).expect("decoded replay bundle should be JSON");
        assert_eq!(decoded_value["incident_id"], format!("INC-FUZZ-{name}"));
        assert!(decoded_value.get("manifest").is_some(), "{name}");
        assert!(decoded_value.get("chunks").is_some(), "{name}");
    }
}

#[test]
fn fuzz_replay_bundle_grammar_is_stable_across_generation_and_serializer_instances() {
    for (name, events) in replay_grammar_event_logs() {
        let incident_id = format!("INC-FUZZ-{name}");
        let mut first_bundle =
            generate_replay_bundle(&incident_id, &events).expect("first grammar bundle");
        let mut second_bundle =
            generate_replay_bundle(&incident_id, &events).expect("second grammar bundle");
        sign_replay_grammar_bundle(&mut first_bundle);
        sign_replay_grammar_bundle(&mut second_bundle);
        let trusted_key_id = replay_grammar_trusted_key_id();
        let first_replay = replay_bundle_with_trusted_key(&first_bundle, &trusted_key_id)
            .expect("first bundle should replay");
        assert!(first_replay.matched, "{name}");

        let first_json = to_canonical_json(&first_bundle).expect("first canonical JSON");
        let second_json = to_canonical_json(&second_bundle).expect("second canonical JSON");
        assert_eq!(first_json, second_json, "{name}");

        let mut first_serializer = CanonicalSerializer::with_all_schemas();
        let mut second_serializer = CanonicalSerializer::with_all_schemas();
        let first_canonical = first_serializer
            .serialize(
                TrustObjectType::PolicyCheckpoint,
                first_json.as_bytes(),
                "fuzz-replay-stable-a",
            )
            .expect("first replay JSON should serialize");
        let second_canonical = second_serializer
            .serialize(
                TrustObjectType::PolicyCheckpoint,
                second_json.as_bytes(),
                "fuzz-replay-stable-b",
            )
            .expect("second replay JSON should serialize");

        assert_eq!(first_canonical, second_canonical, "{name}");
    }
}

#[test]
fn fuzz_replay_bundle_grammar_float_mutations_fail_closed() {
    let mut serializer = CanonicalSerializer::with_all_schemas();
    let cases = [
        br#"{"timeline":[{"payload":{"score":3.14}}]}"#.as_slice(),
        br#"{"initial_state_snapshot":{"load":1e9},"timeline":[]}"#.as_slice(),
        br#"{"chunks":[{"events":[{"payload":{"ratio":NaN}}]}]}"#.as_slice(),
    ];

    for payload in cases {
        let result = serializer.serialize(
            TrustObjectType::OperatorReceipt,
            payload,
            "fuzz-replay-float",
        );
        assert!(
            matches!(result, Err(SerializerError::FloatingPointRejected { .. })),
            "replay grammar float payload should be rejected: {}",
            String::from_utf8_lossy(payload)
        );
    }
}
