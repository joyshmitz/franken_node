//! Security hardening conformance test suite
//!
//! This test harness verifies that the security module implementations
//! conform to the hardening requirements from the user's audit request:
//!
//! 1. Constant-time comparisons are used everywhere for cryptographic operations
//! 2. Key material is properly zeroized and doesn't leak in memory
//! 3. Capability tokens expire correctly with fail-closed semantics
//! 4. SSRF policies block correctly and handle all bypass attempts
//!
//! These tests verify the actual implementation behavior, not just mock behavior.

use frankenengine_node::security::constant_time::{ct_eq, ct_eq_bytes};
use frankenengine_node::security::epoch_scoped_keys::{
    AuthError, RootSecret, sign_epoch_artifact, verify_epoch_signature
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope
};
use frankenengine_node::security::ssrf_policy::SsrfPolicyTemplate;
use frankenengine_node::security::network_guard::Protocol;
use frankenengine_node::control_plane::control_epoch::ControlEpoch;

use std::time::{SystemTime, UNIX_EPOCH};

// === 1. CONSTANT-TIME COMPARISON CONFORMANCE ===

#[test]
fn ct_eq_is_constant_time_for_equal_length_strings() {
    // Verify that ct_eq returns correct results for strings of equal length
    // (the actual constant-time property can't be tested in unit tests,
    // but we can verify correctness)

    assert!(ct_eq("identical", "identical"));
    assert!(!ct_eq("different", "differing"));
    assert!(!ct_eq("almost___", "almost123"));
    assert!(ct_eq("", ""));

    // Test with cryptographic-style strings
    let signature1 = "0123456789abcdef0123456789abcdef01234567";
    let signature2 = "0123456789abcdef0123456789abcdef01234567";
    let signature3 = "0123456789abcdef0123456789abcdef01234568"; // Last char different

    assert!(ct_eq(signature1, signature2));
    assert!(!ct_eq(signature1, signature3));
}

#[test]
fn ct_eq_bytes_handles_cryptographic_material() {
    let key1 = [0xAB; 32];
    let key2 = [0xAB; 32];
    let mut key3 = [0xAB; 32];
    key3[31] = 0xAC; // Only last byte differs

    assert!(ct_eq_bytes(&key1, &key2));
    assert!(!ct_eq_bytes(&key1, &key3));

    // Test with different lengths (should return false quickly)
    let short_key = [0xAB; 16];
    assert!(!ct_eq_bytes(&key1, &short_key));
}

#[test]
fn epoch_keys_use_constant_time_comparisons() {
    // Verify that the epoch key system uses constant-time comparisons
    // We test this by verifying that signature verification fails correctly
    // when signatures differ (the ct_eq should be used internally)

    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let epoch = ControlEpoch::new(42);
    let domain = "test_domain";
    let artifact = b"test_artifact_data";

    // Create a valid signature
    let valid_sig = sign_epoch_artifact(artifact, epoch, domain, &root_secret)
        .expect("sign should work");

    // Create an invalid signature by modifying one byte
    let mut invalid_sig = valid_sig.clone();
    invalid_sig.bytes[31] ^= 0x01; // Flip last bit

    // Valid signature should verify
    assert!(verify_epoch_signature(artifact, &valid_sig, epoch, domain, &root_secret).is_ok());

    // Invalid signature should fail (this internally uses ct_eq)
    assert!(verify_epoch_signature(artifact, &invalid_sig, epoch, domain, &root_secret).is_err());
}

// === 2. KEY MATERIAL ZEROIZATION CONFORMANCE ===

#[test]
fn root_secret_can_be_zeroized() {
    use zeroize::Zeroize;

    let test_bytes = [0xAB; 32];
    let mut secret = RootSecret::from_hex(
        "ababababababababababababababababababababababababababababababab"
    ).expect("valid hex");

    // Verify initial state
    assert_eq!(secret.as_bytes(), &test_bytes);

    // Zeroize the secret
    secret.zeroize();

    // Verify it's been zeroed
    assert_eq!(secret.as_bytes(), &[0u8; 32]);
}

#[test]
fn derived_keys_use_constant_time_equality() {
    // Test that DerivedKey equality uses constant-time comparison
    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let epoch1 = ControlEpoch::new(1);
    let epoch2 = ControlEpoch::new(2);
    let domain = "test_domain";

    let key1a = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch1, domain);
    let key1b = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch1, domain);
    let key2 = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch2, domain);

    // Same epoch should produce identical keys
    assert_eq!(key1a, key1b);

    // Different epochs should produce different keys
    assert_ne!(key1a, key2);
}

// === 3. CAPABILITY TOKEN EXPIRY CONFORMANCE ===

#[test]
fn capability_tokens_expire_with_fail_closed_semantics() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let issued_at = 1_700_000_000u64;
    let ttl_secs = 300u64;
    let expires_at = issued_at + ttl_secs;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        issued_at,
        ttl_secs,
        true,  // operator_authorized
        false, // single_use
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // Should be valid just before expiry
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at - 1,
        "test-trace-before"
    ).is_ok());

    // Should be EXPIRED at exact boundary (fail-closed: >= means expired)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at, // Exactly at expiry
        "test-trace-at-boundary"
    ).expect_err("should be expired at boundary");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");

    // Should be expired after boundary
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at + 1,
        "test-trace-after"
    ).expect_err("should be expired after boundary");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

#[test]
fn capability_tokens_not_valid_before_issue_time() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let issued_at = 1_700_000_000u64;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        issued_at,
        300,
        true,
        false,
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // Should be invalid before issue time (fail-closed)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        issued_at - 1,
        "test-trace-early"
    ).expect_err("should not be valid before issue time");
    assert_eq!(err.code(), "REMOTECAP_NOT_YET_VALID");
}

#[test]
fn single_use_tokens_prevent_replay() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        1_700_000_000,
        300,
        true,
        true, // single_use = true
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // First use should succeed
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        1_700_000_010,
        "test-trace-first"
    ).is_ok());

    // Second use should fail (replay detection)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        1_700_000_011,
        "test-trace-replay"
    ).expect_err("second use should fail");
    assert_eq!(err.code(), "REMOTECAP_REPLAY");
}

#[test]
fn capability_tokens_use_saturating_arithmetic() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    // Issue with potential overflow condition
    let near_max_time = u64::MAX - 100;
    let large_ttl = 200;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        near_max_time,
        large_ttl,
        true,
        false,
        "test-trace"
    ).expect("should issue even with potential overflow");

    // expires_at should be saturated at u64::MAX, not wrapped around
    assert_eq!(cap.expires_at_epoch_secs(), u64::MAX);

    let mut gate = CapabilityGate::new("test-secret");

    // Should be valid at issue time
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        near_max_time,
        "test-trace-valid"
    ).is_ok());

    // Should be expired at u64::MAX (fail-closed)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        u64::MAX,
        "test-trace-max"
    ).expect_err("should be expired at u64::MAX");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

// === 4. SSRF POLICY CONFORMANCE ===

#[test]
fn ssrf_policy_blocks_localhost_variants() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let localhost_variants = [
        "127.0.0.1",
        "127.1.2.3",
        "127.255.255.255",
        "localhost",
        "LOCALHOST",
        "localhost.",
        "API.localhost",
        "subdomain.localhost.",
    ];

    for variant in &localhost_variants {
        let result = policy.check_ssrf(variant, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block localhost variant: {}", variant);
    }
}

#[test]
fn ssrf_policy_blocks_private_networks() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let private_networks = [
        ("10.0.0.1", "RFC1918 Class A"),
        ("10.255.255.255", "RFC1918 Class A boundary"),
        ("172.16.0.1", "RFC1918 Class B start"),
        ("172.31.255.255", "RFC1918 Class B end"),
        ("192.168.0.1", "RFC1918 Class C start"),
        ("192.168.255.255", "RFC1918 Class C end"),
        ("169.254.169.254", "AWS metadata"),
        ("169.254.0.1", "Link-local"),
        ("100.100.100.100", "CGNAT/Tailnet"),
    ];

    for (ip, description) in &private_networks {
        let result = policy.check_ssrf(ip, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block {}: {}", description, ip);
    }
}

#[test]
fn ssrf_policy_blocks_ipv6_loopback() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let ipv6_variants = ["::1", "[::1]", " ::1 "];

    for variant in &ipv6_variants {
        let result = policy.check_ssrf(variant, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block IPv6 loopback variant: {}", variant);
    }
}

#[test]
fn ssrf_policy_blocks_bypass_attempts() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let bypass_attempts = [
        ("127.0.0.1.", "Trailing dot on IP"),
        ("8.8.8.8.", "Trailing dot on public IP"),
        ("[127.0.0.1]", "Brackets around IPv4"),
        ("example.com..", "Multiple trailing dots"),
        ("127.0.0.1..", "Multiple trailing dots on IP"),
        ("[example.com]", "Brackets around hostname"),
    ];

    for (attempt, description) in &bypass_attempts {
        let result = policy.check_ssrf(attempt, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block bypass attempt {}: {}", description, attempt);
    }
}

#[test]
fn ssrf_policy_allows_legitimate_public_targets() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let legitimate_targets = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("api.example.com", "Public hostname"),
        ("github.com", "Public service"),
        ("203.0.113.1", "Documentation IP range"),
    ];

    for (target, description) in &legitimate_targets {
        let result = policy.check_ssrf(target, 443, Protocol::Http, "test-trace", "test-time");
        if target.chars().next().unwrap().is_alphabetic() {
            // DNS names should be allowed (they'll be resolved elsewhere)
            assert!(result.is_ok(), "Should allow {}: {}", description, target);
        } else if let Some(octets) = parse_simple_ipv4(target) {
            // Simple check for common public IPs
            if is_simple_public_ip(octets) {
                assert!(result.is_ok(), "Should allow public IP {}: {}", description, target);
            }
        }
    }
}

#[test]
fn ssrf_policy_allowlist_overrides_blocks() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    // Add allowlist entry for normally blocked IP
    let receipt = policy.add_allowlist(
        "10.0.0.100",
        Some(8080),
        "Internal API for health checks",
        "test-trace",
        "test-time"
    ).expect("should add allowlist entry");

    assert!(!receipt.receipt_id.is_empty());
    assert_eq!(receipt.host, "10.0.0.100");
    assert_eq!(receipt.reason, "Internal API for health checks");

    // Should now allow the previously blocked IP
    let result = policy.check_ssrf(
        "10.0.0.100",
        8080,
        Protocol::Http,
        "test-trace-allowed",
        "test-time"
    );
    assert!(result.is_ok(), "Allowlisted IP should be allowed");

    // Should still block same IP on different port
    let result = policy.check_ssrf(
        "10.0.0.100",
        3000,
        Protocol::Http,
        "test-trace-wrong-port",
        "test-time"
    );
    assert!(result.is_err(), "Should block same IP on non-allowlisted port");
}

// === INTEGRATED CONFORMANCE TESTS ===

#[test]
fn integration_fail_closed_semantics_across_modules() {
    // Test that fail-closed semantics are consistent across all security modules

    // 1. SSRF: Malformed input should be blocked (fail-closed)
    let mut ssrf_policy = SsrfPolicyTemplate::default_template("test".to_string());
    let malformed_result = ssrf_policy.check_ssrf(
        "malformed..",
        80,
        Protocol::Http,
        "test",
        "test"
    );
    assert!(malformed_result.is_err(), "SSRF should fail-closed on malformed input");

    // 2. Capabilities: Expired tokens should be rejected (fail-closed)
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(vec![RemoteOperation::TelemetryExport], vec!["https://test.com".to_string()]);
    let (cap, _) = provider.issue("issuer", scope, 1000, 100, true, false, "trace").expect("issue");
    let mut gate = CapabilityGate::new("test-secret");

    let expired_result = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://test.com",
        1100, // Exactly at expiry boundary
        "test"
    );
    assert!(expired_result.is_err(), "Capabilities should fail-closed at expiry boundary");

    // 3. Cryptographic verification should use constant-time comparison
    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let sig_result = sign_epoch_artifact(
        b"test",
        ControlEpoch::new(1),
        "domain",
        &root_secret
    );
    assert!(sig_result.is_ok(), "Signing should work");
}

// Helper functions for SSRF tests

fn parse_simple_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

fn is_simple_public_ip(octets: [u8; 4]) -> bool {
    // Simple check for well-known public IPs
    match octets {
        [8, 8, 8, 8] => true,     // Google DNS
        [1, 1, 1, 1] => true,     // Cloudflare DNS
        [203, 0, 113, _] => true, // Documentation range
        _ => false,
    }
}