use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::security::epoch_scoped_keys::{
    RootSecret as EpochIkm, Signature, derive_epoch_key, sign_epoch_artifact,
    verify_epoch_signature,
};

type TestResult = Result<(), String>;

const KDF_INFO_DOMAIN: &[u8] = b"franken-node:epoch-kdf-info:v1:";
const SIGNATURE_PAYLOAD_DOMAIN: &[u8] = b"epoch_scoped_sign_v1:";

#[derive(Debug, Clone, Copy)]
struct CoverageRow {
    spec_section: &'static str,
    invariant: &'static str,
    level: &'static str,
    tested: bool,
}

#[derive(Debug, Clone, Copy)]
struct EpochKeyVector {
    name: &'static str,
    ikm_bytes: [u8; 32],
    epoch: u64,
    domain: &'static str,
    artifact_hex: &'static str,
    expected_kdf_info_hex: &'static str,
    expected_derived_key_hex: &'static str,
    expected_key_fingerprint: &'static str,
    expected_signature_payload_hex: &'static str,
    expected_signature_hex: &'static str,
}

const COVERAGE: &[CoverageRow] = &[
    CoverageRow {
        spec_section: "section_10_14_epoch_scoped_key_derivation",
        invariant: "INV-EPOCH-KDF-DOMAIN-SEPARATED",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "section_10_14_epoch_scoped_key_derivation",
        invariant: "INV-EPOCH-KDF-LENGTH-PREFIXED",
        level: "MUST",
        tested: true,
    },
    CoverageRow {
        spec_section: "section_10_14_epoch_scoped_key_derivation",
        invariant: "INV-EPOCH-SIGNATURE-BYTE-STABLE",
        level: "MUST",
        tested: true,
    },
];

const VECTORS: &[EpochKeyVector] = &[
    EpochKeyVector {
        name: "published_marker_signature",
        ikm_bytes: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        epoch: 13,
        domain: "marker",
        artifact_hex: "61727469666163742d616c706861",
        expected_kdf_info_hex: "6672616e6b656e2d6e6f64653a65706f63682d6b64662d696e666f3a76313a0d0000000000000006000000000000006d61726b6572",
        expected_derived_key_hex: "d7350d1a4c2204ef30e35ef14064aee424caf6a0d93edb99da9399a80d45c4da",
        expected_key_fingerprint: "a379144c3ac4e677",
        expected_signature_payload_hex: "65706f63685f73636f7065645f7369676e5f76313a0e0000000000000061727469666163742d616c706861",
        expected_signature_hex: "519e51e3271ef97992091d38d8913602037dc6d52e2644ec1aac856fc5f7cdde",
    },
    EpochKeyVector {
        name: "genesis_empty_artifact",
        ikm_bytes: [0xff; 32],
        epoch: 0,
        domain: "policy",
        artifact_hex: "",
        expected_kdf_info_hex: "6672616e6b656e2d6e6f64653a65706f63682d6b64662d696e666f3a76313a00000000000000000600000000000000706f6c696379",
        expected_derived_key_hex: "cb396eef81dd06b57a0756c8f94229156019b59c3374fff26e8d7b23c8a94ba6",
        expected_key_fingerprint: "a38ec695a8624a5e",
        expected_signature_payload_hex: "65706f63685f73636f7065645f7369676e5f76313a0000000000000000",
        expected_signature_hex: "ef8ed11ab569620a1bc05fd54605381b02c97ec4ad6e82afaf080ddabcb8f944",
    },
    EpochKeyVector {
        name: "length_boundary_ab_c",
        ikm_bytes: [0x11; 32],
        epoch: 513,
        domain: "ab",
        artifact_hex: "63",
        expected_kdf_info_hex: "6672616e6b656e2d6e6f64653a65706f63682d6b64662d696e666f3a76313a010200000000000002000000000000006162",
        expected_derived_key_hex: "d9131ab83abf365ae1e3056818fa5d99dfef5876c559ca1f45272c592e42fdfe",
        expected_key_fingerprint: "4b67200a3b399bd8",
        expected_signature_payload_hex: "65706f63685f73636f7065645f7369676e5f76313a010000000000000063",
        expected_signature_hex: "fc683cd2a1f05fc37e7a0d80e80ed1e30b386455bd9285f58e54f13be101a199",
    },
    EpochKeyVector {
        name: "length_boundary_a_bc",
        ikm_bytes: [0x11; 32],
        epoch: 513,
        domain: "a",
        artifact_hex: "6263",
        expected_kdf_info_hex: "6672616e6b656e2d6e6f64653a65706f63682d6b64662d696e666f3a76313a0102000000000000010000000000000061",
        expected_derived_key_hex: "72051a43c21796059ada6d90a68719eb237dcb16f3ec3723e0fafb5693f6f234",
        expected_key_fingerprint: "0cd510ab8beee0d9",
        expected_signature_payload_hex: "65706f63685f73636f7065645f7369676e5f76313a02000000000000006263",
        expected_signature_hex: "2e61c6174c148d8941172081bcbb8c458164f46dfb5cf30cab81cbadd2de2c1a",
    },
];

fn canonical_kdf_info(epoch: ControlEpoch, domain: &str) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let mut bytes = Vec::with_capacity(
        KDF_INFO_DOMAIN
            .len()
            .saturating_add(16)
            .saturating_add(domain_bytes.len()),
    );
    bytes.extend_from_slice(KDF_INFO_DOMAIN);
    bytes.extend_from_slice(&epoch.value().to_le_bytes());
    bytes.extend_from_slice(&(u64::try_from(domain_bytes.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(domain_bytes);
    bytes
}

fn canonical_signature_payload(artifact: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        SIGNATURE_PAYLOAD_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(artifact.len()),
    );
    bytes.extend_from_slice(SIGNATURE_PAYLOAD_DOMAIN);
    bytes.extend_from_slice(&(u64::try_from(artifact.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(artifact);
    bytes
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|err| format!("{label} must be valid hex: {err}"))
}

fn assert_vector(vector: &EpochKeyVector) -> TestResult {
    let ikm = EpochIkm::from_bytes(vector.ikm_bytes);
    let epoch = ControlEpoch::new(vector.epoch);
    let artifact = decode_hex(vector.artifact_hex, vector.name)?;

    let actual_info = canonical_kdf_info(epoch, vector.domain);
    assert_eq!(
        hex::encode(actual_info),
        vector.expected_kdf_info_hex,
        "{} KDF info bytes drifted",
        vector.name
    );

    let key = derive_epoch_key(&ikm, epoch, vector.domain);
    assert_eq!(
        key.to_hex(),
        vector.expected_derived_key_hex,
        "{} derived key bytes drifted",
        vector.name
    );
    assert_eq!(
        key.fingerprint(),
        vector.expected_key_fingerprint,
        "{} key fingerprint bytes drifted",
        vector.name
    );

    let actual_payload = canonical_signature_payload(&artifact);
    assert_eq!(
        hex::encode(actual_payload),
        vector.expected_signature_payload_hex,
        "{} signature payload bytes drifted",
        vector.name
    );

    let signature = sign_epoch_artifact(&artifact, epoch, vector.domain, &ikm)
        .map_err(|err| format!("{} signature must be generated: {err}", vector.name))?;
    assert_eq!(
        signature.to_hex(),
        vector.expected_signature_hex,
        "{} signature bytes drifted",
        vector.name
    );

    let expected_signature = Signature::from_hex(vector.expected_signature_hex)
        .map_err(|err| format!("{} expected signature must parse: {err}", vector.name))?;
    verify_epoch_signature(&artifact, &expected_signature, epoch, vector.domain, &ikm)
        .map_err(|err| format!("{} expected signature must verify: {err}", vector.name))?;

    Ok(())
}

#[test]
fn control_plane_epoch_key_vectors_cover_required_contract() {
    for required in [
        "INV-EPOCH-KDF-DOMAIN-SEPARATED",
        "INV-EPOCH-KDF-LENGTH-PREFIXED",
        "INV-EPOCH-SIGNATURE-BYTE-STABLE",
    ] {
        assert!(
            COVERAGE.iter().any(|row| {
                row.spec_section == "section_10_14_epoch_scoped_key_derivation"
                    && row.invariant == required
                    && row.level == "MUST"
                    && row.tested
            }),
            "{required} must be covered by the conformance matrix"
        );
    }
}

#[test]
fn control_plane_epoch_key_derivation_and_signatures_match_exact_vectors() -> TestResult {
    for vector in VECTORS {
        assert_vector(vector)?;
    }
    Ok(())
}

#[test]
fn control_plane_epoch_key_length_framing_splits_ambiguous_tuples() -> TestResult {
    let ab_c = VECTORS
        .iter()
        .find(|vector| vector.name == "length_boundary_ab_c")
        .expect("length boundary vector exists");
    let a_bc = VECTORS
        .iter()
        .find(|vector| vector.name == "length_boundary_a_bc")
        .expect("length boundary vector exists");

    assert_ne!(ab_c.expected_kdf_info_hex, a_bc.expected_kdf_info_hex);
    assert_ne!(ab_c.expected_derived_key_hex, a_bc.expected_derived_key_hex);
    assert_ne!(
        ab_c.expected_signature_payload_hex,
        a_bc.expected_signature_payload_hex
    );
    assert_ne!(ab_c.expected_signature_hex, a_bc.expected_signature_hex);

    Ok(())
}

#[test]
fn control_plane_epoch_key_exact_signature_fails_closed_when_reframed() -> TestResult {
    let vector = &VECTORS[0];
    let ikm = EpochIkm::from_bytes(vector.ikm_bytes);
    let signature = Signature::from_hex(vector.expected_signature_hex)
        .map_err(|err| format!("signature must parse: {err}"))?;
    let artifact = decode_hex(vector.artifact_hex, vector.name)?;

    let wrong_domain = verify_epoch_signature(
        &artifact,
        &signature,
        ControlEpoch::new(vector.epoch),
        "manifest",
        &ikm,
    );
    assert!(wrong_domain.is_err(), "domain reframe must fail closed");

    let wrong_artifact = verify_epoch_signature(
        b"artifact-alpha\0",
        &signature,
        ControlEpoch::new(vector.epoch),
        vector.domain,
        &ikm,
    );
    assert!(wrong_artifact.is_err(), "artifact reframe must fail closed");

    Ok(())
}
