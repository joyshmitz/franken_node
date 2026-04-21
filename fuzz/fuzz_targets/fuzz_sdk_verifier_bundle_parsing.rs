#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use frankenengine_verifier_sdk::bundle::{
    ReplayBundle, BundleHeader, TimelineEvent, BundleChunk,
    BundleArtifact, BundleSignature, deserialize,
    hash, integrity_hash, verify,
};

// Fuzz target for SDK verifier bundle parsing and verification.
//
// Tests structure-aware fuzzing of the verifier SDK's bundle deserialization patterns.
// This targets untrusted verifier input through `serde_json::from_slice` calls in
// the external verifier SDK surface.
//
// Priority target (bd-11xn6): SDK verifier bundle input parsing
// - ReplayBundle: main bundle format (highest risk)
// - TimelineEvent, BundleArtifact, BundleChunk: supporting structures
// - Bundle verification logic: integrity_hash, verify
fuzz_target!(|data: FuzzInput| {
    match data {
        FuzzInput::StructuredHeader(header) => {
            fuzz_bundle_header_structured(header);
        }
        FuzzInput::StructuredChunk(chunk) => {
            fuzz_bundle_chunk_structured(chunk);
        }
        FuzzInput::StructuredArtifact(artifact) => {
            fuzz_bundle_artifact_structured(artifact);
        }
        FuzzInput::StructuredSignature(signature) => {
            fuzz_bundle_signature_structured(signature);
        }
        FuzzInput::RawBundleBytes(bytes) => {
            fuzz_bundle_raw_bytes(bytes);
        }
    }
});

/// Fuzz structured BundleHeader objects
fn fuzz_bundle_header_structured(header: BundleHeader) {
    if let Ok(json) = serde_json::to_vec(&header) {
        let _ = serde_json::from_slice::<BundleHeader>(&json);
    }

    let test_bundle = create_minimal_bundle_with_header(header);
    let _ = integrity_hash(&test_bundle);
    verify_structured_bundle(&test_bundle);
}

/// Fuzz structured BundleChunk objects
fn fuzz_bundle_chunk_structured(chunk: BundleChunk) {
    if let Ok(json) = serde_json::to_vec(&chunk) {
        let _ = serde_json::from_slice::<BundleChunk>(&json);
    }

    // Test edge cases with chunk indices and sizes
    let test_bundle = create_minimal_bundle_with_chunks(vec![chunk]);
    let _ = integrity_hash(&test_bundle);
    verify_structured_bundle(&test_bundle);
}

/// Fuzz structured BundleSignature objects
fn fuzz_bundle_signature_structured(signature: BundleSignature) {
    if let Ok(json) = serde_json::to_vec(&signature) {
        let _ = serde_json::from_slice::<BundleSignature>(&json);
    }

    // Test hex decoding edge cases
    let _ = hex::decode(&signature.signature_hex);

    // Test signature verification with fuzzed signature
    let test_bundle = create_minimal_bundle_with_signature(signature);
    verify_structured_bundle(&test_bundle);
}

/// Helper to create minimal bundle for testing components
fn create_minimal_bundle_with_header(header: BundleHeader) -> ReplayBundle {
    ReplayBundle {
        header,
        schema_version: "vsdk-replay-bundle-v1.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        bundle_id: "test".to_string(),
        incident_id: "test".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        policy_version: "v1".to_string(),
        verifier_identity: "test".to_string(),
        timeline: vec![],
        initial_state_snapshot: serde_json::json!({}),
        evidence_refs: vec![],
        artifacts: std::collections::BTreeMap::new(),
        chunks: vec![],
        metadata: std::collections::BTreeMap::new(),
        integrity_hash: String::new(),
        signature: BundleSignature {
            algorithm: "ed25519".to_string(),
            signature_hex: String::new(),
        },
    }
}

/// Helper to create minimal bundle with fuzzed chunks
fn create_minimal_bundle_with_chunks(chunks: Vec<BundleChunk>) -> ReplayBundle {
    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes: 0,
        chunk_count: chunks.len() as u32,
    });
    bundle.chunks = chunks;
    bundle
}

/// Helper to create minimal bundle with fuzzed signature
fn create_minimal_bundle_with_signature(signature: BundleSignature) -> ReplayBundle {
    let mut bundle = create_minimal_bundle_with_header(BundleHeader {
        hash_algorithm: "sha256".to_string(),
        payload_length_bytes: 0,
        chunk_count: 0,
    });
    bundle.signature = signature;
    bundle
}

/// Fuzz structured BundleArtifact objects
fn fuzz_bundle_artifact_structured(artifact: BundleArtifact) {
    if let Ok(json) = serde_json::to_vec(&artifact) {
        let _ = serde_json::from_slice::<BundleArtifact>(&json);
    }

    // Test hex decoding edge cases
    let _ = hex::decode(&artifact.bytes_hex);
    let _ = hex::decode(&artifact.digest);
}

/// Fuzz raw bundle bytes (coverage-guided approach)
fn fuzz_bundle_raw_bytes(bytes: Vec<u8>) {
    // Size guard: reject overly large inputs to prevent OOM
    if bytes.len() > 10_000_000 {
        return;
    }

    // Test main deserialization entry point
    let _ = deserialize(&bytes);

    // Test individual component deserialization
    let _ = serde_json::from_slice::<ReplayBundle>(&bytes);
    let _ = serde_json::from_slice::<BundleHeader>(&bytes);
    let _ = serde_json::from_slice::<TimelineEvent>(&bytes);
    let _ = serde_json::from_slice::<BundleChunk>(&bytes);
    let _ = serde_json::from_slice::<BundleArtifact>(&bytes);
    let _ = serde_json::from_slice::<BundleSignature>(&bytes);

    // Test hash function with raw bytes
    let _ = hash(&bytes);

    // Test validation against malformed input
    if let Ok(bundle) = deserialize(&bytes) {
        // Test verification logic on potentially malformed data
        let _ = integrity_hash(&bundle);
        let _ = verify(&bytes);
    }
}

fn verify_structured_bundle(bundle: &ReplayBundle) {
    if let Ok(bytes) = serde_json::to_vec(bundle) {
        let _ = verify(&bytes);
    }
}

/// Input structure for hybrid structure-aware + coverage-guided fuzzing.
#[derive(Arbitrary, Debug)]
enum FuzzInput {
    /// Generate valid structured BundleHeader then test in bundle context
    StructuredHeader(BundleHeader),
    /// Generate valid structured BundleChunk then test chunk validation
    StructuredChunk(BundleChunk),
    /// Generate valid structured BundleArtifact then test hex decoding
    StructuredArtifact(BundleArtifact),
    /// Generate valid structured BundleSignature then test signature verification
    StructuredSignature(BundleSignature),
    /// Raw bytes for coverage-guided fuzzing of parser edge cases
    RawBundleBytes(Vec<u8>),
}
