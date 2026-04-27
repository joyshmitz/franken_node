# Crypto Trait Abstraction Design

**Status**: Design Phase (bd-18dd1)  
**Author**: CrimsonCrane  
**Date**: 2026-04-27

## Overview

This document defines concrete trait abstractions to unify cryptographic operations across the franken_node codebase. The design addresses inconsistencies in signature verification, key material handling, and crypto scheme selection across multiple modules.

## Motivation

Current cryptographic operations are scattered across:
- `ed25519_verify` module - direct Ed25519 operations
- `decision_receipt` module - receipt signature validation
- `remote_cap` module - capability signature verification  
- `replay_bundle` module - bundle integrity checks

Each module implements crypto operations independently, leading to:
- Code duplication
- Inconsistent error handling
- Security pattern violations
- Testing complexity

## Design

### Core Traits

#### SignatureScheme Trait

```rust
/// Unified signature scheme abstraction
pub trait SignatureScheme: Send + Sync + 'static {
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    type Signature: AsRef<[u8]> + Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Scheme identifier for domain separation
    fn scheme_id() -> &'static str;
    
    /// Generate a new keypair
    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    
    /// Sign a message with domain separation
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;
    
    /// Verify a signature with domain separation and constant-time comparison
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8], 
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool; // Note: returns bool for constant-time usage
    
    /// Parse public key from bytes
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;
    
    /// Parse signature from bytes
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error>;
}
```

#### CryptoSigner Trait

```rust
/// High-level signing operations with built-in security patterns
pub trait CryptoSigner {
    type Scheme: SignatureScheme;
    type SigningKey;
    
    /// Sign with automatic domain separation
    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<<Self::Scheme as SignatureScheme>::Signature, <Self::Scheme as SignatureScheme>::Error>;
    
    /// Sign structured data with type-safe domain separation
    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<<Self::Scheme as SignatureScheme>::Signature, <Self::Scheme as SignatureScheme>::Error>;
}
```

#### KeyMaterial Trait

```rust
/// Key material management with security guarantees
pub trait KeyMaterial: Send + Sync {
    type PublicKey: AsRef<[u8]> + Clone;
    type SecretKey;
    type Error: std::error::Error + Send + Sync + 'static;
    
    /// Load key material from secure storage
    fn load_from_secure_storage(
        key_id: &str,
    ) -> Result<Self, Self::Error>;
    
    /// Export public key for verification
    fn public_key(&self) -> &Self::PublicKey;
    
    /// Check if key material is valid/not expired
    fn is_valid(&self) -> bool;
    
    /// Get key fingerprint for logging/identification
    fn fingerprint(&self) -> String;
    
    /// Secure key rotation
    fn rotate(&mut self) -> Result<(), Self::Error>;
}
```

### Concrete Implementations

#### Ed25519Scheme

```rust
/// Ed25519 signature scheme implementation
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32]; 
    type Signature = [u8; 64];
    type Error = Ed25519Error;
    
    fn scheme_id() -> &'static str {
        "ed25519_v1"
    }
    
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ed25519_sign_v1:");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        let digest = hasher.finalize();
        
        // Use ed25519_dalek for actual signing
        // ... implementation details
    }
    
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8], 
        signature: &Self::Signature,
    ) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ed25519_verify_v1:");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        let digest = hasher.finalize();
        
        // Use constant-time verification
        // Return bool (not Result) for constant-time usage
        match ed25519_dalek::verify_strict(public_key, digest.as_bytes(), signature) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}
```

#### Ed25519Signer

```rust
/// Ed25519-specific signer with security patterns
pub struct Ed25519Signer {
    _phantom: PhantomData<Ed25519Scheme>,
}

impl CryptoSigner for Ed25519Signer {
    type Scheme = Ed25519Scheme;
    type SigningKey = [u8; 32];
    
    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<[u8; 64], Ed25519Error> {
        let domain = format!("franken_node_{}:", context);
        Ed25519Scheme::sign_with_domain(key, domain.as_bytes(), message)
    }
    
    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<[u8; 64], Ed25519Error> {
        let serialized = serde_json::to_vec(data)
            .map_err(|e| Ed25519Error::SerializationFailed(e.to_string()))?;
        self.sign_message(key, context, &serialized)
    }
}
```

### Security Patterns Integration

All implementations enforce established franken_node security patterns:

1. **Domain Separation**: Every signature operation includes context-specific domain separators
2. **Constant-Time Operations**: All verification uses `ct_eq` patterns  
3. **Length Prefixing**: Variable-length inputs are length-prefixed to prevent collision
4. **Fail-Closed**: Invalid operations return secure defaults
5. **Saturating Arithmetic**: All counter operations use `saturating_add`

### Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },
    
    #[error("Signature verification failed")]
    VerificationFailed,
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
}
```

## Migration Strategy

### Phase 1: Core Trait Implementation
- Implement traits in new `crates/franken-node/src/crypto/` module
- Add comprehensive test suite with security pattern validation
- Verify trait API ergonomics with proof-of-concept usage

### Phase 2: Consumer Module Updates  
- **ed25519_verify**: Replace direct Ed25519 calls with `Ed25519Scheme` trait
- **decision_receipt**: Migrate to `CryptoSigner` for receipt signing
- **remote_cap**: Update capability verification to use trait abstractions
- **replay_bundle**: Modernize bundle integrity checking

### Phase 3: Security Hardening
- Audit all crypto operations for pattern compliance
- Add fuzzing test harnesses for trait implementations  
- Performance benchmarking vs. direct crypto library calls

### Phase 4: Advanced Features
- Add support for additional signature schemes (P-256, etc.)
- Implement hardware security module (HSM) key material backends
- Add crypto agility for scheme migration

## Testing Strategy

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_roundtrip() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";
        
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        assert!(Ed25519Scheme::verify_with_domain(&pk, domain, message, &signature));
    }
    
    #[test]  
    fn test_domain_separation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        
        let sig1 = Ed25519Scheme::sign_with_domain(&sk, b"domain1", message).unwrap();
        let sig2 = Ed25519Scheme::sign_with_domain(&sk, b"domain2", message).unwrap();
        
        // Same message, different domains should produce different signatures
        assert_ne!(sig1, sig2);
        
        // Cross-domain verification should fail
        assert!(!Ed25519Scheme::verify_with_domain(&pk, b"domain1", message, &sig2));
        assert!(!Ed25519Scheme::verify_with_domain(&pk, b"domain2", message, &sig1));
    }
    
    #[test]
    fn test_constant_time_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";
        
        let valid_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let mut invalid_sig = valid_sig.clone();
        invalid_sig[0] ^= 1; // Flip one bit
        
        // Both should complete in similar time (constant-time)
        let start = std::time::Instant::now();
        let result1 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &valid_sig);
        let time1 = start.elapsed();
        
        let start = std::time::Instant::now();
        let result2 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &invalid_sig);
        let time2 = start.elapsed();
        
        assert!(result1);
        assert!(!result2);
        // In practice, timing should be similar (this is hard to test deterministically)
    }
}
```

## Implementation Notes

- All trait methods marked as `#[must_use]` where appropriate
- Public APIs documented with security considerations
- Integration with existing `crate::security::constant_time` module
- Backward compatibility maintained during migration
- Zero-cost abstractions - traits compile to direct function calls

## Dependencies

```toml
[dependencies]
ed25519-dalek = { version = "2.0", features = ["serde"] }
blake3 = "1.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
```

## Follow-on Work

This design phase creates the foundation for:
- **bd-TBD**: Implement core crypto traits module
- **bd-TBD**: Migrate ed25519_verify to trait abstractions  
- **bd-TBD**: Update decision_receipt crypto operations
- **bd-TBD**: Modernize remote_cap signature verification
- **bd-TBD**: Refactor replay_bundle integrity checking

Each migration bead will include:
- Module-specific trait integration
- Security pattern validation  
- Performance benchmarking
- Comprehensive test coverage