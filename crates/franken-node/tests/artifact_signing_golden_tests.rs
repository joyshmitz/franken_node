//! Golden artifact tests for supply_chain::artifact_signing module.
//!
//! Tests deterministic ChecksumManifest canonical format and JSON serialization
//! to catch regressions in signature/manifest formats. Any changes to frozen
//! golden outputs require human review.

use frankenengine_node::supply_chain::artifact_signing::{
    ChecksumManifest, ManifestEntry, ArtifactSigningEvent, signing_key_from_seed_hex,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use regex::Regex;

/// Scrub non-deterministic values from JSON output before golden comparison
fn scrub_json(json_str: &str) -> String {
    let mut scrubbed = json_str.to_string();

    // Replace timestamps with placeholder - handles both Unix timestamp and ISO format
    let timestamp_re = Regex::new(r"\d{10}(\.\d+)?").unwrap();
    scrubbed = timestamp_re.replace_all(&scrubbed, "[TIMESTAMP]").to_string();

    // Replace ISO timestamps if any
    let iso_timestamp_re = Regex::new(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?"
    ).unwrap();
    scrubbed = iso_timestamp_re.replace_all(&scrubbed, "[TIMESTAMP]").to_string();

    scrubbed
}

/// Core golden comparison function with UPDATE_GOLDENS support
fn assert_golden(test_name: &str, actual: &str) {
    let golden_path = Path::new("tests/golden/artifact_signing")
        .join(format!("{test_name}.golden"));

    // UPDATE MODE: overwrite golden with actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff actual vs golden
    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|_| panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/",
            golden_path.display()
        ));

    if actual != expected {
        // Write actual for easy diffing
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected length: {}\n\
             Actual length: {}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            expected.len(),
            actual.len(),
            golden_path.display(),
            actual_path.display(),
        );
    }
}

#[test]
fn test_checksum_manifest_canonical_format_golden() {
    // Create deterministic manifest with fixed content
    let mut entries = BTreeMap::new();

    entries.insert("artifact.tar.gz".to_string(), ManifestEntry {
        name: "artifact.tar.gz".to_string(),
        sha256: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string(),
        size_bytes: 1234,
    });

    entries.insert("checksums.txt".to_string(), ManifestEntry {
        name: "checksums.txt".to_string(),
        sha256: "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c".to_string(),
        size_bytes: 567,
    });

    let manifest = ChecksumManifest {
        entries,
        signing_key_id: "test-key-2024".to_string(),
    };

    let canonical_output = manifest.to_canonical();
    assert_golden("manifest_canonical_format", &canonical_output);
}

#[test]
fn test_checksum_manifest_roundtrip_golden() {
    // Test that canonical format can be parsed back correctly
    let original_canonical = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3  artifact.tar.gz  1234\n\
                             b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c  checksums.txt  567\n";

    let parsed = ChecksumManifest::parse_canonical(original_canonical).unwrap();
    let roundtrip_canonical = parsed.to_canonical();

    assert_golden("manifest_roundtrip", &roundtrip_canonical);

    // Ensure roundtrip preserves exact format
    assert_eq!(original_canonical, roundtrip_canonical,
               "Roundtrip should preserve exact canonical format");
}

#[test]
fn test_artifact_signing_event_json_golden() {
    // Create deterministic signing event (timestamp will be scrubbed)
    let event = ArtifactSigningEvent::new(
        "ASV-001",
        "release.tar.gz",
        "test-key-2024",
        "sign",
        "success"
    );

    let json_output = event.to_json().to_string();
    let scrubbed_json = scrub_json(&json_output);

    assert_golden("signing_event_json", &scrubbed_json);
}

#[test]
fn test_manifest_with_multiple_artifacts_golden() {
    // Test manifest with multiple artifacts in deterministic order
    let mut entries = BTreeMap::new();

    // Add entries that will be sorted alphabetically
    entries.insert("alpha.bin".to_string(), ManifestEntry {
        name: "alpha.bin".to_string(),
        sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb".to_string(), // sha256("a")
        size_bytes: 1,
    });

    entries.insert("beta.bin".to_string(), ManifestEntry {
        name: "beta.bin".to_string(),
        sha256: "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d".to_string(), // sha256("b")
        size_bytes: 1,
    });

    entries.insert("gamma.bin".to_string(), ManifestEntry {
        name: "gamma.bin".to_string(),
        sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae".to_string(), // sha256("hello")
        size_bytes: 5,
    });

    let manifest = ChecksumManifest {
        entries,
        signing_key_id: "multi-artifact-key".to_string(),
    };

    let canonical_output = manifest.to_canonical();
    assert_golden("manifest_multiple_artifacts", &canonical_output);
}

#[test]
fn test_empty_manifest_golden() {
    // Test edge case of empty manifest
    let manifest = ChecksumManifest {
        entries: BTreeMap::new(),
        signing_key_id: "empty-manifest-key".to_string(),
    };

    let canonical_output = manifest.to_canonical();
    assert_golden("manifest_empty", &canonical_output);
}

#[test]
fn test_manifest_entry_edge_cases_golden() {
    // Test edge cases like very long names, zero-byte files, etc.
    let mut entries = BTreeMap::new();

    // Zero-byte file
    entries.insert("empty.txt".to_string(), ManifestEntry {
        name: "empty.txt".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), // sha256("")
        size_bytes: 0,
    });

    // File with special characters in name (but valid)
    entries.insert("special-chars_123.bin".to_string(), ManifestEntry {
        name: "special-chars_123.bin".to_string(),
        sha256: "abc123def456abc123def456abc123def456abc123def456abc123def456abc1".to_string(),
        size_bytes: 999999999,
    });

    let manifest = ChecksumManifest {
        entries,
        signing_key_id: "edge-cases-key".to_string(),
    };

    let canonical_output = manifest.to_canonical();
    assert_golden("manifest_edge_cases", &canonical_output);
}

#[test]
fn test_signing_key_deterministic_golden() {
    // Test that signing key generation from seed is deterministic
    let seed_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let signing_key = signing_key_from_seed_hex(&format!("hex:{}", seed_hex)).unwrap();

    // Get the verifying key (public key) which should be deterministic
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_hex = hex::encode(public_key_bytes);

    assert_golden("signing_key_deterministic", &public_key_hex);
}