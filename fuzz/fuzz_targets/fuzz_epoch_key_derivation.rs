#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use zeroize::Zeroize;

use frankenengine_node::security::epoch_scoped_keys::{
    RootSecret, DerivedKey, Signature, derive_epoch_key, sign_epoch_artifact,
    verify_epoch_signature, AuthError
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;

#[derive(Debug, Clone, Arbitrary)]
struct EpochFuzzCase {
    /// Root secret parameters
    root_secret_params: RootSecretParams,
    /// Epoch value (bounded)
    epoch_value: u64,
    /// Domain string with potential attacks
    domain_params: DomainParams,
    /// Artifact data for signing
    artifact_data: Vec<u8>,
    /// Attack strategy to test
    attack_strategy: EpochAttackStrategy,
}

#[derive(Debug, Clone, Arbitrary)]
struct RootSecretParams {
    /// Source bytes for root secret
    secret_bytes: [u8; 32],
    /// How to construct the secret
    construction_method: SecretConstruction,
    /// Mutation to apply
    secret_mutation: SecretMutation,
}

#[derive(Debug, Clone, Arbitrary)]
struct DomainParams {
    /// Base domain string
    base_domain: String,
    /// Domain attack vector
    domain_attack: DomainAttack,
    /// Length manipulation
    length_attack: LengthAttack,
}

#[derive(Debug, Clone, Arbitrary)]
enum SecretConstruction {
    /// Construct from bytes directly
    FromBytes,
    /// Construct from hex string
    FromHex { hex_variant: HexVariant },
    /// Test with all-zero secret
    AllZeros,
    /// Test with all-FF secret
    AllOnes,
    /// Test with patterned secret
    Pattern { pattern: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum SecretMutation {
    /// No mutation
    None,
    /// Single bit flip
    BitFlip { position: u8, bit: u8 },
    /// Byte replacement
    ByteReplace { position: u8, value: u8 },
    /// Truncation (for hex construction)
    Truncate { new_length: u8 },
    /// Extension (for hex construction)
    Extend { extension: String },
}

#[derive(Debug, Clone, Arbitrary)]
enum HexVariant {
    /// Lowercase hex
    Lowercase,
    /// Uppercase hex
    Uppercase,
    /// Mixed case hex
    MixedCase,
    /// With padding
    Padded { prefix: String, suffix: String },
}

#[derive(Debug, Clone, Arbitrary)]
enum DomainAttack {
    /// Clean domain
    Clean,
    /// Domain separator injection
    SeparatorInjection { separator: String },
    /// Unicode attacks
    UnicodeAttack { variant: UnicodeVariant },
    /// Control character injection
    ControlCharAttack,
    /// Path traversal in domain
    PathTraversal,
    /// Length collision attempt
    LengthCollision { collision_domain: String },
    /// Epoch spoofing in domain
    EpochSpoofing { fake_epoch: u64 },
}

#[derive(Debug, Clone, Arbitrary)]
enum UnicodeVariant {
    /// BiDi override attack
    BiDiOverride,
    /// Zero-width characters
    ZeroWidth,
    /// Normalization confusion (NFC vs NFD)
    NormalizationConfusion,
    /// Script mixing (Cyrillic/Latin)
    ScriptMixing,
}

#[derive(Debug, Clone, Arbitrary)]
enum LengthAttack {
    /// Normal length
    Normal,
    /// Very long domain
    VeryLong { size: u16 },
    /// Empty domain
    Empty,
    /// Whitespace only
    WhitespaceOnly,
}

#[derive(Debug, Clone, Arbitrary)]
enum EpochAttackStrategy {
    /// Standard key derivation test
    Standard,
    /// Cross-epoch replay attack
    CrossEpochReplay { target_epoch: u64 },
    /// Cross-domain replay attack
    CrossDomainReplay { target_domain: String },
    /// HKDF info injection
    HkdfInjection { injected_info: Vec<u8> },
    /// Signature format attack
    SignatureFormatAttack { format_attack: SigFormatAttack },
    /// Round-trip consistency test
    RoundTripTest,
    /// Timing analysis
    TimingAnalysis,
    /// Memory zeroization test
    ZeroizationTest,
}

#[derive(Debug, Clone, Arbitrary)]
enum SigFormatAttack {
    /// Wrong signature length
    WrongLength { new_length: u8 },
    /// Bit flip in signature
    BitFlip { position: u8 },
    /// All-zero signature
    AllZeros,
    /// All-FF signature
    AllOnes,
}

const MAX_DOMAIN_LEN: usize = 1024;
const MAX_ARTIFACT_LEN: usize = 8192;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(test_case) = EpochFuzzCase::arbitrary(&mut unstructured) else { return };

    // Bound inputs to prevent resource exhaustion
    if test_case.domain_params.base_domain.len() > MAX_DOMAIN_LEN { return }
    if test_case.artifact_data.len() > MAX_ARTIFACT_LEN { return }

    // Construct root secret
    let root_secret = match construct_root_secret(&test_case.root_secret_params) {
        Ok(secret) => secret,
        Err(_) => return, // Expected failure for invalid construction
    };

    // Process domain
    let domain = process_domain(&test_case.domain_params);

    // Create epoch
    let epoch = ControlEpoch::new(test_case.epoch_value);

    // Execute test strategy
    execute_epoch_strategy(&root_secret, epoch, &domain, &test_case.artifact_data, &test_case.attack_strategy);
});

fn construct_root_secret(params: &RootSecretParams) -> Result<RootSecret, AuthError> {
    let mut bytes = params.secret_bytes;

    // Apply mutation first
    apply_secret_mutation(&mut bytes, &params.secret_mutation);

    match &params.construction_method {
        SecretConstruction::FromBytes => {
            Ok(RootSecret::from_bytes(bytes))
        },

        SecretConstruction::FromHex { hex_variant } => {
            let hex_string = format_hex_string(&bytes, hex_variant);
            let final_hex = apply_hex_mutation(&hex_string, &params.secret_mutation);
            RootSecret::from_hex(&final_hex)
        },

        SecretConstruction::AllZeros => {
            Ok(RootSecret::from_bytes([0u8; 32]))
        },

        SecretConstruction::AllOnes => {
            Ok(RootSecret::from_bytes([0xFFu8; 32]))
        },

        SecretConstruction::Pattern { pattern } => {
            Ok(RootSecret::from_bytes([*pattern; 32]))
        },
    }
}

fn apply_secret_mutation(bytes: &mut [u8; 32], mutation: &SecretMutation) {
    match mutation {
        SecretMutation::None => {},
        SecretMutation::BitFlip { position, bit } => {
            let pos = (*position as usize) % bytes.len();
            bytes[pos] ^= 1u8 << (bit % 8);
        },
        SecretMutation::ByteReplace { position, value } => {
            let pos = (*position as usize) % bytes.len();
            bytes[pos] = *value;
        },
        SecretMutation::Truncate { .. } | SecretMutation::Extend { .. } => {
            // Only applied during hex construction
        },
    }
}

fn format_hex_string(bytes: &[u8], variant: &HexVariant) -> String {
    match variant {
        HexVariant::Lowercase => hex::encode(bytes),
        HexVariant::Uppercase => hex::encode(bytes).to_uppercase(),
        HexVariant::MixedCase => {
            hex::encode(bytes).chars().enumerate().map(|(i, c)| {
                if i % 2 == 0 { c.to_ascii_uppercase() } else { c }
            }).collect()
        },
        HexVariant::Padded { prefix, suffix } => {
            format!("{}{}{}", prefix, hex::encode(bytes), suffix)
        },
    }
}

fn apply_hex_mutation(hex: &str, mutation: &SecretMutation) -> String {
    match mutation {
        SecretMutation::Truncate { new_length } => {
            let target_len = (*new_length as usize).min(hex.len());
            hex.chars().take(target_len).collect()
        },
        SecretMutation::Extend { extension } => {
            format!("{}{}", hex, extension)
        },
        _ => hex.to_string(),
    }
}

fn process_domain(params: &DomainParams) -> String {
    let mut domain = params.base_domain.clone();

    // Apply length attack first
    match &params.length_attack {
        LengthAttack::Normal => {},
        LengthAttack::VeryLong { size } => {
            let target_size = (*size as usize).min(MAX_DOMAIN_LEN);
            domain = "x".repeat(target_size);
        },
        LengthAttack::Empty => {
            domain = String::new();
        },
        LengthAttack::WhitespaceOnly => {
            domain = "   \t  \n  ".to_string();
        },
    }

    // Apply domain attack
    apply_domain_attack(&mut domain, &params.domain_attack);

    domain
}

fn apply_domain_attack(domain: &mut String, attack: &DomainAttack) {
    match attack {
        DomainAttack::Clean => {},

        DomainAttack::SeparatorInjection { separator } => {
            *domain = format!("{}:{}", domain, separator);
        },

        DomainAttack::UnicodeAttack { variant } => {
            match variant {
                UnicodeVariant::BiDiOverride => {
                    *domain = format!("\u{202E}{}\u{202D}", domain);
                },
                UnicodeVariant::ZeroWidth => {
                    *domain = format!("dom\u{200B}ain\u{FEFF}{}", domain);
                },
                UnicodeVariant::NormalizationConfusion => {
                    if domain.contains('e') {
                        *domain = domain.replace('e', "e\u{0301}");
                    }
                },
                UnicodeVariant::ScriptMixing => {
                    *domain = format!("dоmain_{}", domain); // Cyrillic 'о'
                },
            }
        },

        DomainAttack::ControlCharAttack => {
            *domain = format!("{}\r\n\t\x00{}", domain, domain);
        },

        DomainAttack::PathTraversal => {
            *domain = format!("../../../{}", domain);
        },

        DomainAttack::LengthCollision { collision_domain } => {
            // Try to create length collision in HKDF info
            *domain = format!("{}:{}", domain, collision_domain);
        },

        DomainAttack::EpochSpoofing { fake_epoch } => {
            *domain = format!("{}:epoch:{}", domain, fake_epoch);
        },
    }
}

fn execute_epoch_strategy(
    root_secret: &RootSecret,
    epoch: ControlEpoch,
    domain: &str,
    artifact_data: &[u8],
    strategy: &EpochAttackStrategy,
) {
    match strategy {
        EpochAttackStrategy::Standard => {
            fuzz_standard_key_derivation(root_secret, epoch, domain, artifact_data);
        },

        EpochAttackStrategy::CrossEpochReplay { target_epoch } => {
            fuzz_cross_epoch_replay(root_secret, epoch, *target_epoch, domain, artifact_data);
        },

        EpochAttackStrategy::CrossDomainReplay { target_domain } => {
            fuzz_cross_domain_replay(root_secret, epoch, domain, target_domain, artifact_data);
        },

        EpochAttackStrategy::HkdfInjection { injected_info: _ } => {
            // HKDF injection is not directly possible since derive_epoch_key is internal,
            // but we can test domain manipulation attacks that might affect HKDF info
            fuzz_standard_key_derivation(root_secret, epoch, domain, artifact_data);
        },

        EpochAttackStrategy::SignatureFormatAttack { format_attack } => {
            fuzz_signature_format_attack(root_secret, epoch, domain, artifact_data, format_attack);
        },

        EpochAttackStrategy::RoundTripTest => {
            fuzz_round_trip_consistency(root_secret, epoch, domain, artifact_data);
        },

        EpochAttackStrategy::TimingAnalysis => {
            fuzz_timing_consistency(root_secret, epoch, domain, artifact_data);
        },

        EpochAttackStrategy::ZeroizationTest => {
            fuzz_zeroization_behavior(root_secret, epoch, domain);
        },
    }
}

fn fuzz_standard_key_derivation(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str, artifact_data: &[u8]) {
    // Test key derivation
    let derived_key = derive_epoch_key(root_secret, epoch, domain);

    // Invariant: Key derivation should always succeed (no panic)
    assert_eq!(derived_key.as_bytes().len(), 32);

    // Test signing with derived context
    match sign_epoch_artifact(artifact_data, epoch, domain, root_secret) {
        Ok(signature) => {
            // Signature should verify with same parameters
            let verify_result = verify_epoch_signature(artifact_data, &signature, epoch, domain, root_secret);
            assert!(verify_result.is_ok(), "Valid signature should verify");

            // Test fingerprint consistency
            let fingerprint = derived_key.fingerprint();
            assert_eq!(fingerprint.len(), 16, "Fingerprint should be 16 chars");
        },
        Err(err) => {
            // Domain validation or other expected failure
            assert!(matches!(err, AuthError::DomainEmpty | AuthError::KeyDerivationFailed { .. }));
        }
    }
}

fn fuzz_cross_epoch_replay(
    root_secret: &RootSecret,
    source_epoch: ControlEpoch,
    target_epoch: u64,
    domain: &str,
    artifact_data: &[u8],
) {
    // Create signature with source epoch
    let Ok(source_sig) = sign_epoch_artifact(artifact_data, source_epoch, domain, root_secret) else { return };

    // Try to verify with different epoch (should fail)
    let target_epoch = ControlEpoch::new(target_epoch);
    if source_epoch.value() != target_epoch.value() {
        let replay_result = verify_epoch_signature(artifact_data, &source_sig, target_epoch, domain, root_secret);
        assert!(replay_result.is_err(), "Cross-epoch replay should fail");
    }
}

fn fuzz_cross_domain_replay(
    root_secret: &RootSecret,
    epoch: ControlEpoch,
    source_domain: &str,
    target_domain: &str,
    artifact_data: &[u8],
) {
    // Create signature with source domain
    let Ok(source_sig) = sign_epoch_artifact(artifact_data, epoch, source_domain, root_secret) else { return };

    // Try to verify with different domain (should fail if domains differ)
    if source_domain != target_domain {
        let replay_result = verify_epoch_signature(artifact_data, &source_sig, epoch, target_domain, root_secret);
        if replay_result.is_ok() {
            // This would be a serious bug - cross-domain verification succeeded
            panic!("CRITICAL: Cross-domain signature replay succeeded! Source: '{}', Target: '{}'",
                   source_domain, target_domain);
        }
    }
}

fn fuzz_signature_format_attack(
    root_secret: &RootSecret,
    epoch: ControlEpoch,
    domain: &str,
    artifact_data: &[u8],
    attack: &SigFormatAttack,
) {
    let Ok(mut signature) = sign_epoch_artifact(artifact_data, epoch, domain, root_secret) else { return };

    // Apply format attack to signature
    match attack {
        SigFormatAttack::WrongLength { new_length } => {
            let target_len = (*new_length as usize).min(64);
            signature.bytes = [0u8; 32];
            signature.bytes[..target_len.min(32)].fill(0xAA);
        },
        SigFormatAttack::BitFlip { position } => {
            let pos = (*position as usize) % 32;
            signature.bytes[pos] ^= 0x01;
        },
        SigFormatAttack::AllZeros => {
            signature.bytes = [0u8; 32];
        },
        SigFormatAttack::AllOnes => {
            signature.bytes = [0xFFu8; 32];
        },
    }

    // Attacked signature should fail verification
    let attack_result = verify_epoch_signature(artifact_data, &signature, epoch, domain, root_secret);
    assert!(attack_result.is_err(), "Attacked signature should not verify");
}

fn fuzz_round_trip_consistency(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str, artifact_data: &[u8]) {
    let Ok(signature) = sign_epoch_artifact(artifact_data, epoch, domain, root_secret) else { return };

    // Round-trip: sign then verify should always succeed with same parameters
    let verify_result = verify_epoch_signature(artifact_data, &signature, epoch, domain, root_secret);
    assert!(verify_result.is_ok(), "Round-trip sign->verify should succeed");

    // Test serialization round-trip
    let sig_hex = signature.to_hex();
    if let Ok(parsed_sig) = Signature::from_hex(&sig_hex) {
        assert_eq!(signature.bytes, parsed_sig.bytes, "Hex round-trip should preserve signature");
    }

    // Test key derivation consistency
    let key1 = derive_epoch_key(root_secret, epoch, domain);
    let key2 = derive_epoch_key(root_secret, epoch, domain);
    assert_eq!(key1, key2, "Key derivation should be deterministic");
}

fn fuzz_timing_consistency(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str, artifact_data: &[u8]) {
    // Test timing consistency of verification operations
    let Ok(valid_sig) = sign_epoch_artifact(artifact_data, epoch, domain, root_secret) else { return };

    let mut invalid_sig = valid_sig.clone();
    invalid_sig.bytes[0] ^= 0x01;

    // Time valid verification
    let start = std::time::Instant::now();
    let _ = verify_epoch_signature(artifact_data, &valid_sig, epoch, domain, root_secret);
    let valid_time = start.elapsed();

    // Time invalid verification
    let start = std::time::Instant::now();
    let _ = verify_epoch_signature(artifact_data, &invalid_sig, epoch, domain, root_secret);
    let invalid_time = start.elapsed();

    // Basic timing check - operations should be in same order of magnitude
    if valid_time.as_nanos() > 0 && invalid_time.as_nanos() > 0 {
        let ratio = (valid_time.as_nanos() as f64) / (invalid_time.as_nanos() as f64);
        assert!(ratio < 10.0 && ratio > 0.1,
               "Timing difference too large between valid and invalid verification");
    }
}

fn fuzz_zeroization_behavior(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str) {
    let mut derived_key = derive_epoch_key(root_secret, epoch, domain);
    let original_bytes = *derived_key.as_bytes();

    // Test manual zeroization
    derived_key.zeroize();
    assert_eq!(derived_key.as_bytes(), &[0u8; 32], "Manual zeroization should clear key");
    assert_ne!(&original_bytes, &[0u8; 32], "Original key should not be all zeros (usually)");

    // Test fingerprint doesn't leak key material
    let key = derive_epoch_key(root_secret, epoch, domain);
    let fingerprint = key.fingerprint();
    assert_eq!(fingerprint.len(), 16);

    // Fingerprint should not be the key itself
    let key_hex = key.to_hex();
    assert_ne!(fingerprint, &key_hex[..16], "Fingerprint should not be raw key prefix");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_secret_construction() {
        let params = RootSecretParams {
            secret_bytes: [0x42; 32],
            construction_method: SecretConstruction::FromBytes,
            secret_mutation: SecretMutation::None,
        };

        let secret = construct_root_secret(&params).unwrap();
        assert_eq!(secret.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn test_domain_processing() {
        let params = DomainParams {
            base_domain: "test".to_string(),
            domain_attack: DomainAttack::Clean,
            length_attack: LengthAttack::Normal,
        };

        let domain = process_domain(&params);
        assert_eq!(domain, "test");
    }

    #[test]
    fn test_basic_key_derivation() {
        let secret = RootSecret::from_bytes([0x01; 32]);
        let epoch = ControlEpoch::new(1);
        let domain = "test";

        let key = derive_epoch_key(&secret, epoch, domain);
        assert_eq!(key.as_bytes().len(), 32);
    }
}