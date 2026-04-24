#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::supply_chain::trust_card::to_canonical_json;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Number, Value};

const MAX_JSON_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 128;
const MAX_PAIRS: usize = 64;
const MAX_VALUES: usize = 64;

#[derive(Debug, Arbitrary)]
struct CanonicalizeCase {
    raw_json: Vec<u8>,
    object_pairs: Vec<(String, JsonAtom)>,
    array_values: Vec<JsonAtom>,
    selector: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum JsonAtom {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    Text(String),
}

fuzz_target!(|case: CanonicalizeCase| {
    fuzz_trust_card_canonicalize(case);
});

fn fuzz_trust_card_canonicalize(mut case: CanonicalizeCase) {
    if case.raw_json.len() > MAX_JSON_BYTES {
        case.raw_json.truncate(MAX_JSON_BYTES);
    }
    case.object_pairs.truncate(MAX_PAIRS);
    case.array_values.truncate(MAX_VALUES);

    fuzz_raw_json(&case.raw_json);
    fuzz_generated_object(&case.object_pairs);
    fuzz_generated_nested_value(&case);
}

fn fuzz_raw_json(bytes: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    assert_canonical_idempotent(&value);
}

fn fuzz_generated_object(pairs: &[(String, JsonAtom)]) {
    let forward = object_from_pairs(pairs.iter());
    let reverse = object_from_pairs(pairs.iter().rev());

    let forward_canonical = to_canonical_json(&forward).expect("generated object canonicalizes");
    let reverse_canonical = to_canonical_json(&reverse).expect("generated object canonicalizes");

    assert_eq!(
        forward_canonical, reverse_canonical,
        "object insertion order must not affect trust-card canonical JSON"
    );
    assert_canonical_json_idempotent(&forward_canonical);
}

fn fuzz_generated_nested_value(case: &CanonicalizeCase) {
    let mut root = Map::new();
    root.insert(
        "kind".to_string(),
        Value::String("trust-card-canonicalize-fuzz".to_string()),
    );
    root.insert(
        "selector".to_string(),
        Value::Number(Number::from(case.selector)),
    );
    root.insert(
        "object".to_string(),
        Value::Object(object_from_pairs(case.object_pairs.iter())),
    );
    root.insert(
        "array".to_string(),
        Value::Array(
            case.array_values
                .iter()
                .map(atom_to_value)
                .collect::<Vec<_>>(),
        ),
    );

    assert_canonical_idempotent(&Value::Object(root));
}

fn object_from_pairs<'a>(pairs: impl Iterator<Item = &'a (String, JsonAtom)>) -> Map<String, Value> {
    let mut object = Map::new();
    for (key, value) in pairs {
        object.insert(bounded_text(key), atom_to_value(value));
    }
    object
}

fn atom_to_value(atom: &JsonAtom) -> Value {
    match atom {
        JsonAtom::Null => Value::Null,
        JsonAtom::Bool(value) => Value::Bool(*value),
        JsonAtom::U64(value) => Value::Number(Number::from(*value)),
        JsonAtom::I64(value) => Value::Number(Number::from(*value)),
        JsonAtom::Text(value) => Value::String(bounded_text(value)),
    }
}

fn assert_canonical_idempotent(value: &Value) {
    let canonical = to_canonical_json(value).expect("canonical JSON must serialize");
    assert_canonical_json_idempotent(&canonical);
}

fn assert_canonical_json_idempotent(canonical: &str) {
    let reparsed: Value =
        serde_json::from_str(canonical).expect("canonical JSON must parse as JSON");
    let recanonical = to_canonical_json(&reparsed).expect("canonical JSON must recanonicalize");
    assert_eq!(
        canonical, recanonical,
        "canonicalization must be idempotent after parse"
    );
}

fn bounded_text(raw: &str) -> String {
    let mut out = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TEXT_BYTES)
        .collect::<String>();
    if out.is_empty() {
        out.push('x');
    }
    out
}
