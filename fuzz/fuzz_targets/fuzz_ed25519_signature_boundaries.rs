#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::{Signer, SigningKey};
use frankenengine_verifier_sdk::bundle::{BundleError, verify_ed25519_signature};
use libfuzzer_sys::fuzz_target;

const MAX_PAYLOAD_BYTES: usize = 4096;
const MAX_RANDOM_SIG_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
struct Ed25519BoundaryCase {
    signer_seed: [u8; 32],
    wrong_seed: [u8; 32],
    payload: Vec<u8>,
    random_signature: Vec<u8>,
    flip_index: u8,
    mutation: SignatureMutation,
}

#[derive(Debug, Arbitrary)]
enum SignatureMutation {
    Valid,
    Truncated { keep: u8 },
    Extended { extra: Vec<u8> },
    FlippedBit,
    WrongPayload { suffix: Vec<u8> },
    WrongPublicKey,
    RandomBytes,
}

fuzz_target!(|case: Ed25519BoundaryCase| {
    fuzz_ed25519_boundary(case);
});

fn fuzz_ed25519_boundary(mut case: Ed25519BoundaryCase) {
    if case.payload.len() > MAX_PAYLOAD_BYTES {
        case.payload.truncate(MAX_PAYLOAD_BYTES);
    }
    if case.random_signature.len() > MAX_RANDOM_SIG_BYTES {
        case.random_signature.truncate(MAX_RANDOM_SIG_BYTES);
    }

    let signing_key = SigningKey::from_bytes(&case.signer_seed);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&case.payload);
    let mut signature_bytes = signature.to_bytes().to_vec();

    verify_ed25519_signature(&verifying_key, &case.payload, &signature_bytes)
        .expect("freshly signed payload must verify");

    match case.mutation {
        SignatureMutation::Valid => {
            verify_ed25519_signature(&verifying_key, &case.payload, &signature_bytes)
                .expect("valid signature must verify repeatedly");
        }
        SignatureMutation::Truncated { keep } => {
            let keep = usize::from(keep % 64);
            signature_bytes.truncate(keep);
            assert_malformed_length(
                verify_ed25519_signature(&verifying_key, &case.payload, &signature_bytes),
                keep,
            );
        }
        SignatureMutation::Extended { mut extra } => {
            if extra.is_empty() {
                extra.push(0);
            }
            if extra.len() > MAX_RANDOM_SIG_BYTES {
                extra.truncate(MAX_RANDOM_SIG_BYTES);
            }
            signature_bytes.extend(extra);
            assert_malformed_length(
                verify_ed25519_signature(&verifying_key, &case.payload, &signature_bytes),
                signature_bytes.len(),
            );
        }
        SignatureMutation::FlippedBit => {
            let index = usize::from(case.flip_index) % signature_bytes.len();
            signature_bytes[index] ^= 0x01;
            assert_invalid_signature(verify_ed25519_signature(
                &verifying_key,
                &case.payload,
                &signature_bytes,
            ));
        }
        SignatureMutation::WrongPayload { mut suffix } => {
            if suffix.is_empty() {
                suffix.push(0);
            }
            if suffix.len() > MAX_PAYLOAD_BYTES {
                suffix.truncate(MAX_PAYLOAD_BYTES);
            }
            let mut wrong_payload = case.payload;
            wrong_payload.extend(suffix);
            assert_invalid_signature(verify_ed25519_signature(
                &verifying_key,
                &wrong_payload,
                &signature_bytes,
            ));
        }
        SignatureMutation::WrongPublicKey => {
            if case.wrong_seed == case.signer_seed {
                case.wrong_seed[0] ^= 0x80;
            }
            let wrong_key = SigningKey::from_bytes(&case.wrong_seed).verifying_key();
            assert_invalid_signature(verify_ed25519_signature(
                &wrong_key,
                &case.payload,
                &signature_bytes,
            ));
        }
        SignatureMutation::RandomBytes => {
            let _ = verify_ed25519_signature(
                &verifying_key,
                &case.payload,
                &case.random_signature,
            );
        }
    }
}

fn assert_malformed_length(result: Result<(), BundleError>, expected_length: usize) {
    match result {
        Err(BundleError::Ed25519SignatureMalformed { length }) => {
            assert_eq!(length, expected_length);
        }
        other => panic!("expected malformed Ed25519 signature length, got {other:?}"),
    }
}

fn assert_invalid_signature(result: Result<(), BundleError>) {
    match result {
        Err(BundleError::Ed25519SignatureInvalid) => {}
        other => panic!("expected invalid Ed25519 signature, got {other:?}"),
    }
}
