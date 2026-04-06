# bd-phf: Ecosystem Telemetry for Trust and Adoption Metrics

## Bead: bd-phf | Section: 10.4

## Purpose

Provides the quantitative feedback loop that drives reputation scoring,
certification decisions, policy tuning, and program success measurement.
Implements privacy-respecting aggregation, anomaly detection, and time-series
retention for ecosystem-level trust and adoption signals.

## Invariants

| ID | Statement |
|----|-----------|
| INV-TEL-OPT-IN | Telemetry collection is disabled by default and requires explicit opt-in. |
| INV-TEL-PRIVACY | All published metrics satisfy k-anonymity (min_aggregation_k >= 5). |
| INV-TEL-RETENTION | Time-series data respects retention policy: raw <= 7d, hourly <= 30d, daily <= 365d, weekly indefinite. |
| INV-TEL-ANOMALY | Anomaly detection activates only after minimum data points threshold and triggers on deviation above configured percentage. |
| INV-TEL-BUDGET | Resource budget enforces max in-memory points with eviction of raw data when exceeded. |
| INV-TEL-QUERY | Query filtering supports metric kind, time range, aggregation level, label dimensions, and result limiting. |
| INV-TEL-EXPORT | Ecosystem health export surfaces compatibility pass rate, migration velocity, provenance coverage, and active alerts. |
| INV-TEL-GOVERNANCE | Data governance configuration controls collected and published categories independently. |
| INV-TEL-EXPORT-PROVENANCE | Every derived export field documents its authoritative upstream inputs. |
| INV-TEL-EXPORT-NO-PLACEHOLDER | Missing or stale upstream inputs must be surfaced explicitly; live exports may not silently substitute `1.0` or empty maps as if they were measured values. |
| INV-TEL-COMPROMISE | `compromise_reduction_factor` is derived from the Section 13 compromise-reduction report, not from ad hoc local heuristics. |
| INV-TEL-CERT-DIST | `certification_distribution` counts the active extension set using canonical certification levels from `certification.rs`, not the presentation tiers in `trust_card.rs`. |

## Metric Families

### Trust Metrics

| Metric | Description |
|--------|-------------|
| CertificationDistribution | Distribution of extensions across certification levels. |
| RevocationPropagationLatency | Time from revocation issue to fleet-wide propagation. |
| QuarantineResolutionTime | Time from quarantine to resolution (cleared or confirmed). |
| ProvenanceCoverageRate | Fraction of extensions with verified provenance chains. |
| ReputationDistribution | Distribution of publisher reputation scores. |

### Adoption Metrics

| Metric | Description |
|--------|-------------|
| ExtensionsPublished | Extensions published per time period. |
| ProvenanceLevelAdoption | Extensions using each provenance level. |
| TrustCardQueryVolume | Trust-card query volume by operators. |
| PolicyOverrideFrequency | Frequency of policy override usage. |
| QuarantineActionsPerPeriod | Operator-initiated quarantine actions per period. |

## Anomaly Types

| Type | Trigger |
|------|---------|
| ProvenanceCoverageDrop | Sudden drop in provenance coverage rate. |
| QuarantineSpike | Spike in quarantine events beyond threshold. |
| ReputationDistributionShift | Significant shift in reputation score distribution. |
| RevocationPropagationDelay | Unusual revocation propagation delay. |
| PublicationVolumeAnomaly | Abnormal extension publication volume (possible supply-chain attack). |

## Event Codes

| Code | When Emitted |
|------|--------------|
| TELEMETRY_INGESTED | Data point accepted into pipeline. |
| TELEMETRY_AGGREGATED | Aggregation cycle completed. |
| TELEMETRY_QUERY_SERVED | Query executed and results returned. |
| TELEMETRY_ANOMALY_DETECTED | Anomaly alert generated. |
| TELEMETRY_EXPORT_GENERATED | Health export produced. |
| TELEMETRY_PRIVACY_FILTER_APPLIED | Privacy filtering applied to query results. |

## Dependencies

- Upstream: bd-ml1 (publisher reputation), bd-273 (certification levels)
- Downstream: bd-261k (section gate), bd-1xg (plan tracker)

## Ecosystem Health Derived Metrics

### `compromise_reduction_factor`

| Aspect | Contract |
|--------|----------|
| Authoritative inputs | `artifacts/13/compromise_reduction_report.json` plus the schema/semantics in `docs/specs/section_13/bd-3cpa_contract.md` |
| Canonical formula | `baseline_compromised / hardened_compromised` |
| Counted unit | Successful host compromises recorded by the same adversarial campaign runbook |
| Freshness rule | Use only a verified report from the same reporting/release window as the ecosystem health export |
| Forbidden shortcut | Do not emit a placeholder `1.0` when the report is missing, stale, or not yet verified |

Required missing-data semantics:

- `missing_upstream`: no verified Section 13 report is available.
- `stale_upstream`: the available report is outside the reporting/release window.
- `complete_containment`: `hardened_compromised == 0` and `baseline_compromised > 0`; this must be surfaced explicitly instead of inventing a capped numeric ratio.
- `baseline_absent`: `baseline_compromised == 0`, so the ratio is undefined.

Implementation note for `bd-2fqyv.9.2`:

- Because a bare `f64` cannot distinguish unavailable data from a real value, the implementation bead must add explicit availability/provenance metadata rather than preserving the current placeholder behavior.
- The current Rust export surface carries this explicitly via `compromise_reduction_metadata` and `certification_distribution_metadata`, both of which expose `DerivedMetricAvailability`, authoritative input lists, observed inputs, source timestamps, and a human-readable provenance detail string.

### `certification_distribution`

| Aspect | Contract |
|--------|----------|
| Authoritative inputs | `SignedExtensionRegistry.list(Some(ExtensionStatus::Active))` and `CertificationRegistry` records keyed by `extension_id@version` |
| Canonical grouping | `uncertified`, `basic`, `standard`, `verified`, `audited` from `crates/franken-node/src/supply_chain/certification.rs` |
| Counted unit | One active `extension_id@version` per signed extension entry |
| Inclusion rule | Count only `ExtensionStatus::Active` entries from the signed extension registry |
| Missing-record rule | If an active extension version has no certification record, count it in the `uncertified` bucket |
| Forbidden shortcut | Do not derive this metric from the bronze/silver/gold/platinum presentation tiers in `crates/franken-node/src/supply_chain/trust_card.rs` |

Required missing-data semantics:

- `missing_upstream`: the active extension set or certification registry is unavailable.
- `stale_upstream`: the active extension snapshot or certification data is outside the export window.
- Partial active-set coverage must be called out explicitly; the implementation must not silently drop unmatched active extensions.

Implementation note for `bd-2fqyv.9.2`:

- The implementation bead should introduce an explicit status/provenance payload for this metric if the export format would otherwise confuse "empty because nothing is certified" with "empty because upstream state was unavailable."

## Validation Workflow

`bd-2fqyv.9.3` ratchets this surface with a scenario matrix and artifact-backed verification workflow so the telemetry export cannot drift back toward placeholders.

| Scenario | Inputs | Expected export semantics | Locked by |
|----------|--------|---------------------------|-----------|
| `complete_inputs` | Verified compromise report plus current active extension and certification registries | Numeric compromise ratio and certification counts with populated provenance metadata | `test_health_export_computes_compromise_reduction_from_authoritative_report`, `test_health_export_counts_active_extensions_using_certification_registry` |
| `partial_active_set_coverage` | Active extension exists without a certification record | Extension remains counted via the `uncertified` bucket instead of being silently dropped | `test_health_export_counts_active_extensions_using_certification_registry` |
| `missing_inputs` | No report and/or no registry inputs | Export metadata marks the field as `missing_upstream` instead of emitting placeholder values | `test_health_export` |
| `stale_compromise_report` | Verified report from a different reporting window | `compromise_reduction_metadata.availability = stale_upstream` | `test_health_export_surfaces_stale_compromise_report` |
| `stale_certification_inputs` | Active extension or certification evaluation timestamp is outside the export window | `certification_distribution_metadata.availability = stale_upstream` | `test_health_export_marks_stale_certification_distribution_inputs` |
| `complete_containment_or_baseline_absent` | Edge-case report where `hardened_compromised == 0` or `baseline_compromised == 0` | Metadata exposes `complete_containment` or `baseline_absent`; no fabricated numeric ratio is emitted | `test_health_export_surfaces_complete_containment_instead_of_placeholder_ratio`, `test_health_export_surfaces_baseline_absent_for_undefined_compromise_ratio` |

Verification artifacts and workflow:

- Run `python3 scripts/check_ecosystem_telemetry.py --json`.
- Treat `artifacts/section_10_4/bd-phf/verification_evidence.json` as the report-level fixture for required symbols, tests, and contract markers.
- Treat `artifacts/section_10_4/bd-phf/verification_summary.md` as the operator-facing verification digest.
- Derived metric provenance must remain inspectable through `authoritative_inputs`, `observed_inputs`, `source_timestamp`, and `detail`.
