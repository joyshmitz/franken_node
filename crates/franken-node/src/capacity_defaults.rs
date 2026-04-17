//! Centralized bounded-collection defaults for `franken_node`.
//!
//! This module is the shared source of truth for high-frequency capacity
//! constants that currently recur across the crate surface. Follow-up migration
//! beads can replace file-local raw literals with aliases from here while
//! preserving local readability.

// Inline negative-path tests for constant validation and boundary checking
#[cfg(test)]
#[allow(unused_imports)]
use std::collections::HashMap;

/// Canonical bucket sizes reused across the product surface.
pub mod base {
    /// Small bounded collections such as approvals and compact histories.
    pub const SMALL: usize = 256;

    /// Medium windows for disputes, replay capsules, and similar registries.
    pub const MEDIUM: usize = 2_048;

    /// Common default for event logs, receipts, and audit trails.
    pub const STANDARD: usize = 4_096;

    /// Larger collections for traces, obligations, and artifact inventories.
    pub const LARGE: usize = 8_192;

    /// Extended histories that exceed the standard large bucket.
    pub const XL: usize = 16_384;

    /// Trace/register-sized collections that are intentionally tighter.
    pub const TRACE: usize = 1_024;

    /// Very large dedupe/nonces windows.
    pub const DEDUPE: usize = 65_536;

    // Inline negative-path tests for base bucket validation
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: all base constants must be non-zero to prevent capacity bypass
        const _: () = assert!(SMALL > 0, "SMALL capacity must be non-zero");
        const _: () = assert!(MEDIUM > 0, "MEDIUM capacity must be non-zero");
        const _: () = assert!(STANDARD > 0, "STANDARD capacity must be non-zero");
        const _: () = assert!(LARGE > 0, "LARGE capacity must be non-zero");
        const _: () = assert!(XL > 0, "XL capacity must be non-zero");
        const _: () = assert!(TRACE > 0, "TRACE capacity must be non-zero");
        const _: () = assert!(DEDUPE > 0, "DEDUPE capacity must be non-zero");

        // Test: bucket hierarchy must be strictly increasing to prevent capacity confusion
        const _: () = assert!(SMALL < TRACE, "SMALL must be less than TRACE");
        const _: () = assert!(TRACE < MEDIUM, "TRACE must be less than MEDIUM");
        const _: () = assert!(MEDIUM < STANDARD, "MEDIUM must be less than STANDARD");
        const _: () = assert!(STANDARD < LARGE, "STANDARD must be less than LARGE");
        const _: () = assert!(LARGE < XL, "LARGE must be less than XL");
        const _: () = assert!(XL < DEDUPE, "XL must be less than DEDUPE");

        // Test: power-of-two alignment for cache efficiency
        const _: () = assert!(SMALL & (SMALL - 1) == 0, "SMALL should be power of 2");
        const _: () = assert!(TRACE & (TRACE - 1) == 0, "TRACE should be power of 2");
        const _: () = assert!(MEDIUM & (MEDIUM - 1) == 0, "MEDIUM should be power of 2");
        const _: () = assert!(STANDARD & (STANDARD - 1) == 0, "STANDARD should be power of 2");
        const _: () = assert!(LARGE & (LARGE - 1) == 0, "LARGE should be power of 2");
        const _: () = assert!(XL & (XL - 1) == 0, "XL should be power of 2");
        const _: () = assert!(DEDUPE & (DEDUPE - 1) == 0, "DEDUPE should be power of 2");

        // Test: no overflow when used in common arithmetic operations
        const _: () = assert!(DEDUPE.saturating_add(1000) > DEDUPE, "DEDUPE must not overflow in normal use");
        const _: () = assert!(XL.saturating_mul(2) < usize::MAX / 2, "XL doubling must not approach overflow");

        // Test: sufficient separation between adjacent buckets for meaningful differentiation
        const _: () = assert!(TRACE > SMALL * 2, "TRACE should be meaningfully larger than SMALL");
        const _: () = assert!(MEDIUM > TRACE * 2, "MEDIUM should be meaningfully larger than TRACE");
        const _: () = assert!(STANDARD > MEDIUM * 2, "STANDARD should be meaningfully larger than MEDIUM");
        const _: () = assert!(LARGE > STANDARD * 2, "LARGE should be meaningfully larger than STANDARD");

        // Test: dedupe window large enough for collision resistance
        const _: () = assert!(DEDUPE >= 32768, "DEDUPE must be sufficiently large for collision resistance");

        // Test: trace bucket appropriate for in-memory debugging structures
        const _: () = assert!(TRACE <= 2048, "TRACE should remain memory-efficient for debugging");

        // Test: standard bucket balanced between memory usage and functionality
        const _: () = assert!(STANDARD >= 2048 && STANDARD <= 8192, "STANDARD should be balanced capacity");
    };
}

/// Audit-oriented capacities.
pub mod audit {
    use super::base;

    pub const LOG_ENTRIES: usize = base::STANDARD;
    pub const TRAIL_ENTRIES: usize = base::STANDARD;
    pub const ACTION_LOG_ENTRIES: usize = base::STANDARD;
    pub const RECORDS: usize = base::STANDARD;
    pub const RECEIPT_CHAIN: usize = base::LARGE;

    // Inline negative-path tests for audit capacity validation
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: all audit constants derive from valid base buckets only
        const _: () = assert!(LOG_ENTRIES == base::STANDARD, "LOG_ENTRIES must use STANDARD bucket");
        const _: () = assert!(TRAIL_ENTRIES == base::STANDARD, "TRAIL_ENTRIES must use STANDARD bucket");
        const _: () = assert!(ACTION_LOG_ENTRIES == base::STANDARD, "ACTION_LOG_ENTRIES must use STANDARD bucket");
        const _: () = assert!(RECORDS == base::STANDARD, "RECORDS must use STANDARD bucket");
        const _: () = assert!(RECEIPT_CHAIN == base::LARGE, "RECEIPT_CHAIN must use LARGE bucket");

        // Test: audit capacities must not collapse to smaller buckets
        const _: () = assert!(LOG_ENTRIES > base::MEDIUM, "LOG_ENTRIES must exceed MEDIUM capacity");
        const _: () = assert!(TRAIL_ENTRIES > base::TRACE, "TRAIL_ENTRIES must exceed TRACE capacity");
        const _: () = assert!(ACTION_LOG_ENTRIES > base::SMALL, "ACTION_LOG_ENTRIES must exceed SMALL capacity");

        // Test: receipt chain must be larger than individual log capacities for aggregation
        const _: () = assert!(RECEIPT_CHAIN > LOG_ENTRIES, "RECEIPT_CHAIN must exceed LOG_ENTRIES");
        const _: () = assert!(RECEIPT_CHAIN > TRAIL_ENTRIES, "RECEIPT_CHAIN must exceed TRAIL_ENTRIES");
        const _: () = assert!(RECEIPT_CHAIN > ACTION_LOG_ENTRIES, "RECEIPT_CHAIN must exceed ACTION_LOG_ENTRIES");

        // Test: standard audit buckets must be identical for cross-component compatibility
        const _: () = assert!(LOG_ENTRIES == TRAIL_ENTRIES, "LOG_ENTRIES and TRAIL_ENTRIES must match");
        const _: () = assert!(TRAIL_ENTRIES == ACTION_LOG_ENTRIES, "TRAIL_ENTRIES and ACTION_LOG_ENTRIES must match");
        const _: () = assert!(RECORDS == LOG_ENTRIES, "RECORDS must match other standard audit capacities");

        // Test: audit capacities sufficient for high-frequency operations
        const _: () = assert!(LOG_ENTRIES >= 1000, "LOG_ENTRIES must handle frequent logging");
        const _: () = assert!(RECEIPT_CHAIN >= 4000, "RECEIPT_CHAIN must handle receipt accumulation");

        // Test: no integer overflow in typical audit operations
        const _: () = assert!(RECEIPT_CHAIN.saturating_add(LOG_ENTRIES) < usize::MAX / 2, "audit operations must not overflow");

        // Test: audit bucket relationships are mathematically consistent
        const _: () = assert!(RECEIPT_CHAIN >= LOG_ENTRIES * 2, "RECEIPT_CHAIN should be at least 2x LOG_ENTRIES");
    };
}

/// Generic bounded collection capacities.
pub mod collections {
    use super::base;

    pub const EVENTS: usize = base::STANDARD;
    pub const ENTRIES: usize = base::STANDARD;
    pub const RECEIPTS: usize = base::STANDARD;
    pub const SHIMS: usize = base::STANDARD;
    pub const PREDICATES: usize = base::STANDARD;
    pub const RESULTS: usize = base::STANDARD;
    pub const RULES: usize = base::STANDARD;
    pub const CONDITIONS: usize = base::STANDARD;
    pub const REPORTS: usize = base::STANDARD;
    pub const FIELDS: usize = base::STANDARD;
    pub const METRICS: usize = base::STANDARD;
    pub const RUNS: usize = base::STANDARD;
    pub const PROJECTS_PER_COHORT: usize = base::STANDARD;
}

/// Security- and crypto-adjacent capacities.
pub mod security {
    use super::base;

    pub const TRUSTED_SIGNERS: usize = base::STANDARD;
    pub const MONITORS: usize = base::STANDARD;
    pub const BLOCKED_SOURCES: usize = base::STANDARD;
    pub const REFERENCE_RUNTIMES: usize = base::STANDARD;
    pub const EVENTS: usize = base::STANDARD;
    pub const SEEN_NONCES: usize = base::LARGE;
    pub const CONSUMED_NONCES: usize = base::DEDUPE;

    // Inline negative-path tests for security capacity validation
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: nonce window hierarchy must prevent replay attacks
        const _: () = assert!(CONSUMED_NONCES > SEEN_NONCES, "CONSUMED_NONCES must exceed SEEN_NONCES");
        const _: () = assert!(CONSUMED_NONCES >= SEEN_NONCES * 4, "CONSUMED_NONCES should be significantly larger");

        // Test: security-critical capacities must not be too small for attack resistance
        const _: () = assert!(TRUSTED_SIGNERS >= 64, "TRUSTED_SIGNERS must support sufficient key rotation");
        const _: () = assert!(BLOCKED_SOURCES >= 1000, "BLOCKED_SOURCES must handle attack source lists");
        const _: () = assert!(SEEN_NONCES >= 4000, "SEEN_NONCES must provide replay protection window");

        // Test: standard security buckets use consistent capacity for interoperability
        const _: () = assert!(TRUSTED_SIGNERS == base::STANDARD, "TRUSTED_SIGNERS must use STANDARD bucket");
        const _: () = assert!(MONITORS == base::STANDARD, "MONITORS must use STANDARD bucket");
        const _: () = assert!(BLOCKED_SOURCES == base::STANDARD, "BLOCKED_SOURCES must use STANDARD bucket");
        const _: () = assert!(REFERENCE_RUNTIMES == base::STANDARD, "REFERENCE_RUNTIMES must use STANDARD bucket");
        const _: () = assert!(EVENTS == base::STANDARD, "security EVENTS must use STANDARD bucket");

        // Test: nonce capacities use appropriate bucket sizes for their threat model
        const _: () = assert!(SEEN_NONCES == base::LARGE, "SEEN_NONCES must use LARGE bucket");
        const _: () = assert!(CONSUMED_NONCES == base::DEDUPE, "CONSUMED_NONCES must use DEDUPE bucket");

        // Test: no overlap between security categories that should remain distinct
        const _: () = assert!(SEEN_NONCES != CONSUMED_NONCES, "nonce windows must have different capacities");
        const _: () = assert!(TRUSTED_SIGNERS == MONITORS, "TRUSTED_SIGNERS and MONITORS should match for symmetry");

        // Test: security capacities must not overflow in cryptographic operations
        const _: () = assert!(CONSUMED_NONCES.saturating_mul(32) < usize::MAX / 8, "nonce operations must not overflow");
        const _: () = assert!(TRUSTED_SIGNERS.saturating_mul(256) < usize::MAX / 16, "signature operations must not overflow");

        // Test: blocked sources capacity sufficient for threat intelligence feeds
        const _: () = assert!(BLOCKED_SOURCES >= base::MEDIUM, "BLOCKED_SOURCES must handle threat feeds");

        // Test: reference runtime capacity appropriate for verification diversity
        const _: () = assert!(REFERENCE_RUNTIMES <= base::LARGE, "REFERENCE_RUNTIMES should remain manageable");
        const _: () = assert!(REFERENCE_RUNTIMES >= base::TRACE, "REFERENCE_RUNTIMES must support multiple implementations");

        // Test: monitor capacity scales with security event volume expectations
        const _: () = assert!(MONITORS == EVENTS, "MONITORS should match security EVENTS capacity");
    };
}

/// Runtime/control-plane capacities.
pub mod runtime {
    use super::base;

    pub const ABORT_EVENTS: usize = base::STANDARD;
    pub const FORCE_EVENTS: usize = base::STANDARD;
    pub const SESSION_EVENTS: usize = base::STANDARD;
    pub const OBLIGATIONS: usize = base::LARGE;
    pub const LEASES: usize = base::LARGE;
    pub const SAGAS: usize = base::STANDARD;
    pub const TOTAL_ARTIFACTS: usize = base::LARGE;
    pub const REGISTERED_TRACES: usize = base::TRACE;
    pub const TRACE_STEPS: usize = base::LARGE;
    pub const BULKHEAD_EVENTS: usize = base::TRACE;
    pub const LATENCY_SAMPLES: usize = base::TRACE;
    pub const BARRIER_HISTORY: usize = base::STANDARD;
    pub const CHECKPOINTS: usize = base::TRACE;
}

/// Governance and verifier-facing capacities.
pub mod verifier {
    use super::base;

    pub const VERIFIERS: usize = base::STANDARD;
    pub const ATTESTATIONS: usize = base::LARGE;
    pub const DISPUTES: usize = base::MEDIUM;
    pub const REPLAY_CAPSULES: usize = base::MEDIUM;
    pub const CHAIN_ENTRIES: usize = base::XL;
    pub const JOBS: usize = base::MEDIUM;
    pub const WINDOWS_SEEN: usize = base::STANDARD;
}

/// Storage- and testing-adjacent capacities.
pub mod support {
    use super::base;

    pub const SCHEMA_VERSIONS: usize = base::TRACE;
    pub const ASSERTIONS: usize = base::STANDARD;
    pub const LINKS: usize = base::STANDARD;
    pub const NODES_CAP: usize = base::STANDARD;
}

/// Exact-name aliases that downstream migration beads can adopt verbatim.
pub mod aliases {
    use super::{audit, collections, runtime, security, support, verifier};

    pub const MAX_AUDIT_LOG_ENTRIES: usize = audit::LOG_ENTRIES;
    pub const MAX_AUDIT_TRAIL_ENTRIES: usize = audit::TRAIL_ENTRIES;
    pub const MAX_ACTION_LOG_ENTRIES: usize = audit::ACTION_LOG_ENTRIES;
    pub const MAX_RECEIPT_CHAIN: usize = audit::RECEIPT_CHAIN;

    // Inline negative-path tests for alias correctness and consistency
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: audit aliases must exactly match their source constants
        const _: () = assert!(MAX_AUDIT_LOG_ENTRIES == audit::LOG_ENTRIES, "audit log alias mismatch");
        const _: () = assert!(MAX_AUDIT_TRAIL_ENTRIES == audit::TRAIL_ENTRIES, "audit trail alias mismatch");
        const _: () = assert!(MAX_ACTION_LOG_ENTRIES == audit::ACTION_LOG_ENTRIES, "action log alias mismatch");
        const _: () = assert!(MAX_RECEIPT_CHAIN == audit::RECEIPT_CHAIN, "receipt chain alias mismatch");

        // Test: no accidental cross-wiring between different capacity domains
        const _: () = assert!(MAX_AUDIT_LOG_ENTRIES != MAX_RECEIPT_CHAIN, "audit log must not equal receipt chain");

        // Test: aliases maintain the same relationships as their source modules
        const _: () = assert!(MAX_RECEIPT_CHAIN > MAX_AUDIT_LOG_ENTRIES, "alias hierarchy must match source hierarchy");

        // Test: all audit aliases use expected underlying bucket sizes
        const _: () = assert!(MAX_AUDIT_LOG_ENTRIES == super::base::STANDARD, "audit log alias must use STANDARD");
        const _: () = assert!(MAX_RECEIPT_CHAIN == super::base::LARGE, "receipt chain alias must use LARGE");
    };

    pub const MAX_EVENTS: usize = collections::EVENTS;
    pub const MAX_ENTRIES: usize = collections::ENTRIES;
    pub const MAX_RECEIPTS: usize = collections::RECEIPTS;
    pub const MAX_SHIMS: usize = collections::SHIMS;
    pub const MAX_PREDICATES: usize = collections::PREDICATES;
    pub const MAX_RESULTS: usize = collections::RESULTS;
    pub const MAX_RULES: usize = collections::RULES;
    pub const MAX_CONDITIONS: usize = collections::CONDITIONS;
    pub const MAX_REPORTS: usize = collections::REPORTS;
    pub const MAX_FIELDS: usize = collections::FIELDS;
    pub const MAX_METRICS: usize = collections::METRICS;
    pub const MAX_RUNS: usize = collections::RUNS;
    pub const MAX_PROJECTS_PER_COHORT: usize = collections::PROJECTS_PER_COHORT;

    pub const MAX_TRUSTED_SIGNERS: usize = security::TRUSTED_SIGNERS;
    pub const MAX_MONITORS: usize = security::MONITORS;
    pub const MAX_BLOCKED_SOURCES: usize = security::BLOCKED_SOURCES;
    pub const MAX_REFERENCE_RUNTIMES: usize = security::REFERENCE_RUNTIMES;
    pub const MAX_SEEN_NONCES: usize = security::SEEN_NONCES;
    pub const MAX_CONSUMED_NONCES: usize = security::CONSUMED_NONCES;

    // Inline negative-path tests for security alias validation
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: security aliases must exactly match their source constants
        const _: () = assert!(MAX_TRUSTED_SIGNERS == security::TRUSTED_SIGNERS, "trusted signers alias mismatch");
        const _: () = assert!(MAX_MONITORS == security::MONITORS, "monitors alias mismatch");
        const _: () = assert!(MAX_BLOCKED_SOURCES == security::BLOCKED_SOURCES, "blocked sources alias mismatch");
        const _: () = assert!(MAX_REFERENCE_RUNTIMES == security::REFERENCE_RUNTIMES, "reference runtimes alias mismatch");
        const _: () = assert!(MAX_SEEN_NONCES == security::SEEN_NONCES, "seen nonces alias mismatch");
        const _: () = assert!(MAX_CONSUMED_NONCES == security::CONSUMED_NONCES, "consumed nonces alias mismatch");

        // Test: critical security alias relationships for attack resistance
        const _: () = assert!(MAX_CONSUMED_NONCES > MAX_SEEN_NONCES, "consumed nonce alias must exceed seen");
        const _: () = assert!(MAX_CONSUMED_NONCES >= MAX_SEEN_NONCES * 8, "nonce window separation must be significant");

        // Test: security aliases must not accidentally cross-wire with non-security capacities
        const _: () = assert!(MAX_TRUSTED_SIGNERS != MAX_AUDIT_LOG_ENTRIES, "security and audit should be independent");
        const _: () = assert!(MAX_BLOCKED_SOURCES != MAX_RECEIPT_CHAIN, "blocked sources should not match receipt chain");

        // Test: symmetric security alias capacities for operational consistency
        const _: () = assert!(MAX_TRUSTED_SIGNERS == MAX_MONITORS, "signers and monitors should match for balance");
        const _: () = assert!(MAX_MONITORS == MAX_BLOCKED_SOURCES, "monitors and blocked sources should match");

        // Test: nonce alias capacities use correct underlying buckets for threat model
        const _: () = assert!(MAX_SEEN_NONCES == super::base::LARGE, "seen nonces alias must use LARGE bucket");
        const _: () = assert!(MAX_CONSUMED_NONCES == super::base::DEDUPE, "consumed nonces alias must use DEDUPE bucket");

        // Test: security alias values are sufficient for production threat landscapes
        const _: () = assert!(MAX_TRUSTED_SIGNERS >= 1000, "trusted signers alias must support key diversity");
        const _: () = assert!(MAX_BLOCKED_SOURCES >= 2000, "blocked sources alias must handle threat intelligence");
        const _: () = assert!(MAX_CONSUMED_NONCES >= 32768, "consumed nonces alias must provide replay protection");
    };

    pub const MAX_ABORT_EVENTS: usize = runtime::ABORT_EVENTS;
    pub const MAX_FORCE_EVENTS: usize = runtime::FORCE_EVENTS;
    pub const MAX_SESSION_EVENTS: usize = runtime::SESSION_EVENTS;
    pub const MAX_OBLIGATIONS: usize = runtime::OBLIGATIONS;
    pub const MAX_LEASES: usize = runtime::LEASES;
    pub const MAX_SAGAS: usize = runtime::SAGAS;
    pub const MAX_TOTAL_ARTIFACTS: usize = runtime::TOTAL_ARTIFACTS;
    pub const MAX_REGISTERED_TRACES: usize = runtime::REGISTERED_TRACES;
    pub const MAX_TRACE_STEPS: usize = runtime::TRACE_STEPS;
    pub const MAX_BULKHEAD_EVENTS: usize = runtime::BULKHEAD_EVENTS;
    pub const MAX_LATENCY_SAMPLES: usize = runtime::LATENCY_SAMPLES;
    pub const MAX_BARRIER_HISTORY: usize = runtime::BARRIER_HISTORY;
    pub const MAX_CHECKPOINTS: usize = runtime::CHECKPOINTS;

    // Inline negative-path tests for runtime alias validation
    #[cfg(test)]
    #[allow(unreachable_code)]
    {
        // Test: runtime aliases must exactly match their source constants
        const _: () = assert!(MAX_OBLIGATIONS == runtime::OBLIGATIONS, "obligations alias mismatch");
        const _: () = assert!(MAX_LEASES == runtime::LEASES, "leases alias mismatch");
        const _: () = assert!(MAX_SAGAS == runtime::SAGAS, "sagas alias mismatch");
        const _: () = assert!(MAX_TOTAL_ARTIFACTS == runtime::TOTAL_ARTIFACTS, "artifacts alias mismatch");

        // Test: trace-related aliases must use consistent TRACE bucket for memory efficiency
        const _: () = assert!(MAX_REGISTERED_TRACES == super::base::TRACE, "registered traces must use TRACE bucket");
        const _: () = assert!(MAX_BULKHEAD_EVENTS == super::base::TRACE, "bulkhead events must use TRACE bucket");
        const _: () = assert!(MAX_LATENCY_SAMPLES == super::base::TRACE, "latency samples must use TRACE bucket");
        const _: () = assert!(MAX_CHECKPOINTS == super::base::TRACE, "checkpoints must use TRACE bucket");

        // Test: large runtime aliases must use appropriate buckets for scale
        const _: () = assert!(MAX_OBLIGATIONS == super::base::LARGE, "obligations must use LARGE bucket");
        const _: () = assert!(MAX_LEASES == super::base::LARGE, "leases must use LARGE bucket");
        const _: () = assert!(MAX_TOTAL_ARTIFACTS == super::base::LARGE, "artifacts must use LARGE bucket");
        const _: () = assert!(MAX_TRACE_STEPS == super::base::LARGE, "trace steps must use LARGE bucket");

        // Test: standard runtime aliases for operational consistency
        const _: () = assert!(MAX_ABORT_EVENTS == super::base::STANDARD, "abort events must use STANDARD");
        const _: () = assert!(MAX_FORCE_EVENTS == super::base::STANDARD, "force events must use STANDARD");
        const _: () = assert!(MAX_SESSION_EVENTS == super::base::STANDARD, "session events must use STANDARD");
        const _: () = assert!(MAX_SAGAS == super::base::STANDARD, "sagas must use STANDARD");
        const _: () = assert!(MAX_BARRIER_HISTORY == super::base::STANDARD, "barrier history must use STANDARD");

        // Test: runtime capacity relationships for operational coherence
        const _: () = assert!(MAX_OBLIGATIONS > MAX_SAGAS, "obligations must exceed sagas for containment");
        const _: () = assert!(MAX_TRACE_STEPS > MAX_REGISTERED_TRACES, "trace steps must exceed registered traces");
        const _: () = assert!(MAX_TOTAL_ARTIFACTS > MAX_LEASES, "artifacts must exceed leases for lifecycle management");

        // Test: trace aliases must not accidentally expand beyond trace boundaries
        const _: () = assert!(MAX_REGISTERED_TRACES <= super::base::MEDIUM, "registered traces must remain trace-sized");
        const _: () = assert!(MAX_CHECKPOINTS <= super::base::MEDIUM, "checkpoints must remain trace-sized");

        // Test: runtime event aliases must handle high-frequency operations
        const _: () = assert!(MAX_SESSION_EVENTS >= 1024, "session events must handle frequent connections");
        const _: () = assert!(MAX_ABORT_EVENTS >= 1024, "abort events must handle error bursts");
        const _: () = assert!(MAX_FORCE_EVENTS >= 1024, "force events must handle emergency operations");

        // Test: no overflow in typical runtime arithmetic operations
        const _: () = assert!(MAX_TOTAL_ARTIFACTS.saturating_add(MAX_OBLIGATIONS) < usize::MAX / 2, "runtime ops must not overflow");
    };
}

    pub const MAX_VERIFIERS: usize = verifier::VERIFIERS;
    pub const MAX_ATTESTATIONS: usize = verifier::ATTESTATIONS;
    pub const MAX_DISPUTES: usize = verifier::DISPUTES;
    pub const MAX_REPLAY_CAPSULES: usize = verifier::REPLAY_CAPSULES;
    pub const MAX_CHAIN_ENTRIES: usize = verifier::CHAIN_ENTRIES;
    pub const MAX_JOBS: usize = verifier::JOBS;
    pub const MAX_WINDOWS_SEEN: usize = verifier::WINDOWS_SEEN;

    pub const MAX_SCHEMA_VERSIONS: usize = support::SCHEMA_VERSIONS;
    pub const MAX_ASSERTIONS: usize = support::ASSERTIONS;
    pub const MAX_LINKS: usize = support::LINKS;
    pub const MAX_NODES_CAP: usize = support::NODES_CAP;
}

#[cfg(test)]
mod tests {
    use super::{aliases, audit, base, collections, runtime, security, support, verifier};

    #[test]
    fn base_buckets_match_documented_sizes() {
        assert_eq!(base::SMALL, 256);
        assert_eq!(base::TRACE, 1_024);
        assert_eq!(base::MEDIUM, 2_048);
        assert_eq!(base::STANDARD, 4_096);
        assert_eq!(base::LARGE, 8_192);
        assert_eq!(base::XL, 16_384);
        assert_eq!(base::DEDUPE, 65_536);
    }

    #[test]
    fn representative_aliases_reuse_semantic_groups() {
        assert_eq!(aliases::MAX_AUDIT_LOG_ENTRIES, audit::LOG_ENTRIES);
        assert_eq!(aliases::MAX_EVENTS, collections::EVENTS);
        assert_eq!(aliases::MAX_TRUSTED_SIGNERS, security::TRUSTED_SIGNERS);
        assert_eq!(aliases::MAX_SESSION_EVENTS, runtime::SESSION_EVENTS);
        assert_eq!(aliases::MAX_VERIFIERS, verifier::VERIFIERS);
        assert_eq!(aliases::MAX_SCHEMA_VERSIONS, support::SCHEMA_VERSIONS);
    }

    #[test]
    fn larger_capacities_use_non_standard_buckets() {
        assert_eq!(aliases::MAX_REGISTERED_TRACES, base::TRACE);
        assert_eq!(aliases::MAX_TRACE_STEPS, base::LARGE);
        assert_eq!(aliases::MAX_ATTESTATIONS, base::LARGE);
        assert_eq!(aliases::MAX_CHAIN_ENTRIES, base::XL);
        assert_eq!(aliases::MAX_CONSUMED_NONCES, base::DEDUPE);
    }

    #[test]
    fn base_buckets_do_not_collapse_to_zero() {
        for capacity in [
            base::SMALL,
            base::TRACE,
            base::MEDIUM,
            base::STANDARD,
            base::LARGE,
            base::XL,
            base::DEDUPE,
        ] {
            assert_ne!(capacity, 0);
        }
    }

    #[test]
    fn ordered_buckets_do_not_regress_or_overlap() {
        assert!(base::SMALL < base::TRACE);
        assert!(base::TRACE < base::MEDIUM);
        assert!(base::MEDIUM < base::STANDARD);
        assert!(base::STANDARD < base::LARGE);
        assert!(base::LARGE < base::XL);
        assert!(base::XL < base::DEDUPE);
    }

    #[test]
    fn trace_sized_runtime_caps_do_not_expand_to_standard_bucket() {
        for capacity in [
            aliases::MAX_REGISTERED_TRACES,
            aliases::MAX_BULKHEAD_EVENTS,
            aliases::MAX_LATENCY_SAMPLES,
            aliases::MAX_CHECKPOINTS,
        ] {
            assert_eq!(capacity, base::TRACE);
            assert_ne!(capacity, base::STANDARD);
        }
    }

    #[test]
    fn security_nonce_windows_do_not_share_the_same_capacity() {
        assert_eq!(aliases::MAX_SEEN_NONCES, base::LARGE);
        assert_eq!(aliases::MAX_CONSUMED_NONCES, base::DEDUPE);
        assert_ne!(aliases::MAX_CONSUMED_NONCES, aliases::MAX_SEEN_NONCES);
        assert!(aliases::MAX_CONSUMED_NONCES > aliases::MAX_SEEN_NONCES);
    }

    #[test]
    fn verifier_medium_queues_do_not_drift_to_standard_audit_caps() {
        assert_eq!(aliases::MAX_DISPUTES, base::MEDIUM);
        assert_eq!(aliases::MAX_REPLAY_CAPSULES, base::MEDIUM);
        assert_eq!(aliases::MAX_JOBS, base::MEDIUM);
        assert_ne!(aliases::MAX_DISPUTES, aliases::MAX_AUDIT_LOG_ENTRIES);
        assert_ne!(aliases::MAX_JOBS, aliases::MAX_EVENTS);
    }

    #[test]
    fn support_schema_versions_do_not_use_large_runtime_bucket() {
        assert_eq!(aliases::MAX_SCHEMA_VERSIONS, base::TRACE);
        assert_ne!(aliases::MAX_SCHEMA_VERSIONS, aliases::MAX_TRACE_STEPS);
        assert_ne!(aliases::MAX_SCHEMA_VERSIONS, aliases::MAX_TOTAL_ARTIFACTS);
    }

    #[test]
    fn aliases_do_not_cross_wire_security_and_runtime_caps() {
        assert_ne!(aliases::MAX_TRUSTED_SIGNERS, aliases::MAX_LEASES);
        assert_ne!(aliases::MAX_CONSUMED_NONCES, aliases::MAX_OBLIGATIONS);
        assert_ne!(
            aliases::MAX_REFERENCE_RUNTIMES,
            aliases::MAX_REGISTERED_TRACES
        );
    }
}

#[cfg(test)]
mod negative_path_tests {
    use super::{aliases, base};

    fn validate_strictly_increasing_buckets(buckets: &[(&str, usize)]) -> Result<(), String> {
        for (name, capacity) in buckets {
            if *capacity == 0 {
                return Err(format!("{name} must not be zero"));
            }
        }

        for pair in buckets.windows(2) {
            let (prev_name, prev_capacity) = pair[0];
            let (next_name, next_capacity) = pair[1];
            if next_capacity <= prev_capacity {
                return Err(format!(
                    "{next_name}={next_capacity} must be greater than {prev_name}={prev_capacity}"
                ));
            }
        }
        Ok(())
    }

    fn canonical_buckets() -> [(&'static str, usize); 7] {
        [
            ("small", base::SMALL),
            ("trace", base::TRACE),
            ("medium", base::MEDIUM),
            ("standard", base::STANDARD),
            ("large", base::LARGE),
            ("xl", base::XL),
            ("dedupe", base::DEDUPE),
        ]
    }

    fn validate_consumed_nonce_window(seen: usize, consumed: usize) -> Result<(), &'static str> {
        if consumed <= seen {
            return Err("consumed nonce window must exceed seen nonce window");
        }
        Ok(())
    }

    fn validate_schema_version_capacity(capacity: usize) -> Result<(), &'static str> {
        if capacity > base::TRACE {
            return Err("schema version capacity must stay trace-sized");
        }
        Ok(())
    }

    fn validate_chain_capacity(receipts: usize, chain_entries: usize) -> Result<(), &'static str> {
        if chain_entries <= receipts {
            return Err("verifier chain capacity must exceed receipt buffer capacity");
        }
        Ok(())
    }

    fn validate_trace_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::TRACE {
            return Err(format!("{name} must stay trace-sized"));
        }
        Ok(())
    }

    fn validate_medium_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::MEDIUM {
            return Err(format!("{name} must stay medium-sized"));
        }
        Ok(())
    }

    fn validate_standard_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::STANDARD {
            return Err(format!("{name} must stay standard-sized"));
        }
        Ok(())
    }

    fn validate_large_sized(name: &str, capacity: usize) -> Result<(), String> {
        if capacity != base::LARGE {
            return Err(format!("{name} must stay large-sized"));
        }
        Ok(())
    }

    #[test]
    fn negative_bucket_validation_rejects_zero_small_bucket() {
        let mut buckets = canonical_buckets();
        buckets[0] = ("small", 0);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("zero capacity bucket must fail closed");

        assert!(err.contains("small"));
        assert!(err.contains("zero"));
    }

    #[test]
    fn negative_bucket_validation_rejects_trace_not_above_small() {
        let mut buckets = canonical_buckets();
        buckets[1] = ("trace", base::SMALL);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("trace bucket must stay above small");

        assert!(err.contains("trace"));
        assert!(err.contains("small"));
    }

    #[test]
    fn negative_bucket_validation_rejects_medium_below_trace() {
        let mut buckets = canonical_buckets();
        buckets[2] = ("medium", base::TRACE.saturating_sub(1));

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("medium bucket must stay above trace");

        assert!(err.contains("medium"));
        assert!(err.contains("trace"));
    }

    #[test]
    fn negative_bucket_validation_rejects_standard_equal_medium() {
        let mut buckets = canonical_buckets();
        buckets[3] = ("standard", base::MEDIUM);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("standard bucket must not collapse to medium");

        assert!(err.contains("standard"));
        assert!(err.contains("medium"));
    }

    #[test]
    fn negative_bucket_validation_rejects_dedupe_not_largest() {
        let mut buckets = canonical_buckets();
        buckets[6] = ("dedupe", base::XL);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("dedupe bucket must remain the largest window");

        assert!(err.contains("dedupe"));
        assert!(err.contains("xl"));
    }

    #[test]
    fn negative_nonce_windows_reject_consumed_not_larger_than_seen() {
        let seen = aliases::MAX_SEEN_NONCES;
        let consumed = aliases::MAX_SEEN_NONCES;

        let err = validate_consumed_nonce_window(seen, consumed)
            .expect_err("consumed nonce window must stay larger than seen window");

        assert!(err.contains("consumed nonce"));
        assert!(validate_consumed_nonce_window(seen, aliases::MAX_CONSUMED_NONCES).is_ok());
    }

    #[test]
    fn negative_schema_version_capacity_rejects_runtime_trace_steps_bucket() {
        let schema_versions = aliases::MAX_TRACE_STEPS;

        let err = validate_schema_version_capacity(schema_versions)
            .expect_err("schema version capacity must not grow to runtime trace steps");

        assert!(err.contains("schema version"));
        assert!(validate_schema_version_capacity(aliases::MAX_SCHEMA_VERSIONS).is_ok());
    }

    #[test]
    fn negative_chain_entries_reject_standard_receipt_capacity() {
        let chain_entries = aliases::MAX_RECEIPTS;

        let err = validate_chain_capacity(aliases::MAX_RECEIPTS, chain_entries)
            .expect_err("chain capacity must not collapse to receipt buffer capacity");

        assert!(err.contains("verifier chain"));
        assert!(validate_chain_capacity(aliases::MAX_RECEIPTS, aliases::MAX_CHAIN_ENTRIES).is_ok());
    }

    #[test]
    fn negative_bucket_validation_rejects_large_equal_standard() {
        let mut buckets = canonical_buckets();
        buckets[4] = ("large", base::STANDARD);

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("large bucket must stay above standard");

        assert!(err.contains("large"));
        assert!(err.contains("standard"));
    }

    #[test]
    fn negative_bucket_validation_rejects_xl_below_large() {
        let mut buckets = canonical_buckets();
        buckets[5] = ("xl", base::LARGE.saturating_sub(1));

        let err = validate_strictly_increasing_buckets(&buckets)
            .expect_err("xl bucket must stay above large");

        assert!(err.contains("xl"));
        assert!(err.contains("large"));
    }

    #[test]
    fn negative_registered_traces_rejects_standard_bucket() {
        let err = validate_trace_sized("registered traces", base::STANDARD)
            .expect_err("registered trace capacity must remain trace-sized");

        assert!(err.contains("registered traces"));
        assert!(validate_trace_sized("registered traces", aliases::MAX_REGISTERED_TRACES).is_ok());
    }

    #[test]
    fn negative_checkpoint_capacity_rejects_large_bucket() {
        let err = validate_trace_sized("checkpoints", aliases::MAX_TRACE_STEPS)
            .expect_err("checkpoint capacity must not inherit trace-step capacity");

        assert!(err.contains("checkpoints"));
        assert!(validate_trace_sized("checkpoints", aliases::MAX_CHECKPOINTS).is_ok());
    }

    #[test]
    fn negative_dispute_capacity_rejects_standard_bucket() {
        let err = validate_medium_sized("disputes", aliases::MAX_EVENTS)
            .expect_err("disputes must not collapse to default event capacity");

        assert!(err.contains("disputes"));
        assert!(validate_medium_sized("disputes", aliases::MAX_DISPUTES).is_ok());
    }

    #[test]
    fn negative_audit_log_capacity_rejects_trace_bucket() {
        let err = validate_standard_sized("audit log entries", aliases::MAX_CHECKPOINTS)
            .expect_err("audit log entries must not shrink to trace-sized capacity");

        assert!(err.contains("audit log entries"));
        assert!(
            validate_standard_sized("audit log entries", aliases::MAX_AUDIT_LOG_ENTRIES).is_ok()
        );
    }

    #[test]
    fn negative_obligation_capacity_rejects_standard_bucket() {
        let err = validate_large_sized("obligations", aliases::MAX_EVENTS)
            .expect_err("obligations must not shrink to default event capacity");

        assert!(err.contains("obligations"));
        assert!(validate_large_sized("obligations", aliases::MAX_OBLIGATIONS).is_ok());
    }
}
