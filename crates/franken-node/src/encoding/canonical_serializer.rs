#[cfg(test)]
mod tests {
    use super::super::deterministic_seed::{
        ContentHash, DeterministicSeed, DomainTag, ScheduleConfig, derive_seed,
    };
    use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_SCHEMA_VERSIONS};
    use crate::storage::frankensqlite_adapter::{FrankensqliteAdapter, PersistenceClass};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeSet;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MatrixCase {
        label: &'static str,
        config_version: u32,
        payload_len: usize,
        schema_version_probe: u32,
        audit_index_probe: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct FrankensqliteCanonicalRow {
        requirement_id: String,
        matrix_row: String,
        domain: DomainTag,
        domain_label: String,
        domain_prefix: String,
        persistence_class: PersistenceClass,
        persistence_class_label: String,
        persistence_tier_label: String,
        content_hash: ContentHash,
        config: ScheduleConfig,
        config_hash_hex: String,
        seed: DeterministicSeed,
        schema_version_probe: u32,
        audit_index_probe: usize,
        payload_len: usize,
        payload: String,
    }

    fn fill_schema_versions_to_limit(adapter: &mut FrankensqliteAdapter) -> u32 {
        let schema_limit =
            u32::try_from(MAX_SCHEMA_VERSIONS).expect("schema version cap should fit u32");
        for version in 2..=schema_limit {
            adapter
                .migrate(version, "canonical serializer conformance limit probe")
                .expect("schema migration limit probe should succeed");
        }
        assert_eq!(adapter.schema_version(), schema_limit);
        schema_limit
    }

    fn prefill_audit_log_to_near_limit(
        adapter: &mut FrankensqliteAdapter,
        reserved_audit_rows: usize,
    ) -> usize {
        let prefill_count = MAX_AUDIT_LOG_ENTRIES.saturating_sub(reserved_audit_rows);
        for index in 0..prefill_count {
            let key = format!("prefill-audit-{index:04}");
            adapter
                .write(PersistenceClass::AuditLog, &key, b"prefill")
                .expect("audit prefill should succeed");
        }
        prefill_count
    }

    fn content_hash_for(
        domain: DomainTag,
        class: PersistenceClass,
        case: MatrixCase,
    ) -> ContentHash {
        let mut bytes = [0u8; 32];
        let material = format!(
            "{}|{}|{}|{}|{}",
            domain.prefix(),
            class.label(),
            class.tier().label(),
            case.label,
            case.payload_len
        );
        for (index, byte) in material.bytes().enumerate() {
            let slot = index % bytes.len();
            bytes[slot] = bytes[slot]
                .wrapping_add(byte)
                .wrapping_add(u8::try_from(index % 251).expect("bounded index fits u8"));
        }
        ContentHash(bytes)
    }

    fn config_for(domain: DomainTag, class: PersistenceClass, case: MatrixCase) -> ScheduleConfig {
        ScheduleConfig::new(case.config_version)
            .with_param("audit_index_probe", case.audit_index_probe.to_string())
            .with_param("domain", domain.label())
            .with_param("domain_prefix", domain.prefix())
            .with_param("payload_len", case.payload_len.to_string())
            .with_param("persistence_class", class.label())
            .with_param("persistence_tier", class.tier().label())
            .with_param(
                "schema_version_probe",
                case.schema_version_probe.to_string(),
            )
    }

    fn conformance_row(
        domain: DomainTag,
        class: PersistenceClass,
        case: MatrixCase,
    ) -> FrankensqliteCanonicalRow {
        let content_hash = content_hash_for(domain, class, case);
        let config = config_for(domain, class, case);
        let seed = derive_seed(&domain, &content_hash, &config);
        let payload = "x".repeat(case.payload_len);

        FrankensqliteCanonicalRow {
            requirement_id: "FSA-CANONICAL-ROUNDTRIP-DOMAIN-PERSISTENCE".to_string(),
            matrix_row: format!("{}::{}::{}", domain.label(), class.label(), case.label),
            domain,
            domain_label: domain.label().to_string(),
            domain_prefix: domain.prefix().to_string(),
            persistence_class: class,
            persistence_class_label: class.label().to_string(),
            persistence_tier_label: class.tier().label().to_string(),
            config_hash_hex: hex::encode(config.config_hash()),
            content_hash,
            config,
            seed,
            schema_version_probe: case.schema_version_probe,
            audit_index_probe: case.audit_index_probe,
            payload_len: case.payload_len,
            payload,
        }
    }

    fn canonical_bytes(row: &FrankensqliteCanonicalRow) -> Vec<u8> {
        let encoded = serde_json::to_vec(row).expect("canonical row should serialize");
        let decoded: FrankensqliteCanonicalRow =
            serde_json::from_slice(&encoded).expect("canonical row should deserialize");
        assert_eq!(*row, decoded);

        let reencoded = serde_json::to_vec(&decoded).expect("decoded row should reserialize");
        assert_eq!(reencoded, encoded);
        encoded
    }

    #[test]
    fn frankensqlite_adapter_canonical_roundtrip_matrix_covers_domain_tag_by_persistence_class() {
        let mut adapter = FrankensqliteAdapter::default();
        let schema_limit = fill_schema_versions_to_limit(&mut adapter);
        let pair_count = DomainTag::all()
            .len()
            .checked_mul(PersistenceClass::all().len())
            .expect("matrix pair count should not overflow");
        let near_limit_payload_len = MAX_SCHEMA_VERSIONS.saturating_sub(1);
        let max_audit_index = MAX_AUDIT_LOG_ENTRIES.saturating_sub(1);
        let cases = [
            MatrixCase {
                label: "nominal",
                config_version: 1,
                payload_len: 0,
                schema_version_probe: 1,
                audit_index_probe: 0,
            },
            MatrixCase {
                label: "near_schema_limit",
                config_version: schema_limit,
                payload_len: near_limit_payload_len,
                schema_version_probe: schema_limit,
                audit_index_probe: max_audit_index,
            },
        ];
        let expected_matrix_rows = pair_count
            .checked_mul(cases.len())
            .expect("matrix row count should not overflow");
        let expected_audit_rows = DomainTag::all()
            .len()
            .checked_mul(cases.len())
            .expect("audit matrix row count should not overflow");
        let audit_prefill_count =
            prefill_audit_log_to_near_limit(&mut adapter, expected_audit_rows);

        let mut covered_pairs = BTreeSet::new();
        let mut covered_rows = BTreeSet::new();
        let mut near_limit_rows = 0usize;

        for domain in DomainTag::all() {
            for class in PersistenceClass::all() {
                covered_pairs.insert((domain.label().to_string(), class.label().to_string()));

                for case in cases {
                    let row = conformance_row(*domain, *class, case);
                    let first = canonical_bytes(&row);
                    let second = canonical_bytes(&row);
                    assert_eq!(
                        first, second,
                        "canonical bytes drifted for {}",
                        row.matrix_row
                    );

                    let key = format!("canonical-{}", row.matrix_row.replace("::", "-"));
                    let write = adapter
                        .write(*class, &key, &first)
                        .expect("matrix row write should succeed");
                    assert!(write.success);
                    assert_eq!(write.persistence_class, *class);
                    assert_eq!(write.tier, class.tier());

                    let read = adapter.read(*class, &key);
                    assert!(read.found, "matrix row should be readable: {key}");
                    assert_eq!(read.value.as_deref(), Some(first.as_slice()));
                    assert_eq!(read.persistence_class, *class);
                    assert_eq!(read.tier, class.tier());

                    let read_bytes = read.value.expect("matrix row should include bytes");
                    let read_row: FrankensqliteCanonicalRow = serde_json::from_slice(&read_bytes)
                        .expect("stored canonical row should deserialize");
                    assert_eq!(read_row, row);
                    assert_eq!(
                        serde_json::to_vec(&read_row).expect("stored row should reserialize"),
                        first
                    );

                    covered_rows.insert(row.matrix_row.clone());
                    if case.label == "near_schema_limit" {
                        near_limit_rows = near_limit_rows.saturating_add(1);
                        assert_eq!(row.schema_version_probe, schema_limit);
                        assert_eq!(row.audit_index_probe, max_audit_index);
                        assert_eq!(row.payload_len, near_limit_payload_len);
                    }
                }
            }
        }

        assert_eq!(covered_pairs.len(), pair_count);
        assert_eq!(covered_rows.len(), expected_matrix_rows);
        assert_eq!(near_limit_rows, pair_count);

        let replay = adapter.replay();
        assert_eq!(replay.len(), MAX_AUDIT_LOG_ENTRIES);
        assert!(
            replay.iter().all(|(_, matches)| *matches),
            "audit replay must remain deterministic at capacity"
        );

        let summary = adapter.summary();
        assert_eq!(
            summary.total_writes,
            audit_prefill_count.saturating_add(expected_matrix_rows)
        );
        assert_eq!(summary.schema_version, schema_limit);
        assert_eq!(summary.replay_mismatches, 0);
    }
}
