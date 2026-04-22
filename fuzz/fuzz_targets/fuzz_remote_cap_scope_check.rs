#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope,
};
use libfuzzer_sys::fuzz_target;

const SECRET: &str = "remote-cap-scope-fuzz-secret";
const NOW: u64 = 1_700_000_000;
const MAX_STRING_CHARS: usize = 256;
const MAX_SCOPE_ITEMS: usize = 32;

#[derive(Debug, Arbitrary)]
struct RemoteCapScopeCase {
    operations: Vec<FuzzOperation>,
    endpoint_prefixes: Vec<String>,
    requested_operation: FuzzOperation,
    requested_endpoint: String,
    issuer: String,
    trace_id: String,
    ttl_hint: u16,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FuzzOperation {
    NetworkEgress,
    FederationSync,
    RevocationFetch,
    RemoteAttestationVerify,
    TelemetryExport,
    RemoteComputation,
    ArtifactUpload,
}

fuzz_target!(|case: RemoteCapScopeCase| {
    fuzz_remote_cap_scope_check(case);
});

fn fuzz_remote_cap_scope_check(case: RemoteCapScopeCase) {
    let operations: Vec<RemoteOperation> = case
        .operations
        .into_iter()
        .take(MAX_SCOPE_ITEMS)
        .map(FuzzOperation::into_operation)
        .collect();
    let prefixes = bounded_strings(case.endpoint_prefixes);
    let scope = RemoteScope::new(operations, prefixes);
    let requested_operation = case.requested_operation.into_operation();
    let requested_endpoint = bounded_string(case.requested_endpoint);
    let issuer = bounded_string(case.issuer);
    let trace_id = bounded_string(case.trace_id);
    let ttl = u64::from(case.ttl_hint % 3600).saturating_add(2);

    assert_endpoint_delimiter_boundaries(&scope);

    let provider = CapabilityProvider::new(SECRET);
    let Ok((cap, _)) = provider.issue(
        &issuer,
        scope.clone(),
        NOW,
        ttl,
        true,
        false,
        &trace_id,
    ) else {
        return;
    };

    let expected_allowed =
        scope.allows_operation(requested_operation) && scope.allows_endpoint(&requested_endpoint);
    let mut gate = CapabilityGate::new(SECRET);
    let result = gate.authorize_network(
        Some(&cap),
        requested_operation,
        &requested_endpoint,
        NOW.saturating_add(1),
        "trace-scope-check",
    );
    assert_eq!(
        result.is_ok(),
        expected_allowed,
        "scope authorization result diverged from RemoteScope predicate"
    );

    let mut local_gate = CapabilityGate::with_mode(SECRET, ConnectivityMode::LocalOnly);
    let local_result = local_gate.authorize_network(
        Some(&cap),
        requested_operation,
        &requested_endpoint,
        NOW.saturating_add(1),
        "trace-local-only-deny",
    );
    assert!(
        local_result.is_err(),
        "local-only connectivity mode must deny remote capability use"
    );
}

fn assert_endpoint_delimiter_boundaries(scope: &RemoteScope) {
    for prefix in scope.endpoint_prefixes() {
        if prefix.is_empty() || prefix.ends_with('/') || prefix.ends_with(':') {
            continue;
        }
        let shifted = format!("{prefix}evil");
        let singleton_scope = RemoteScope::new(vec![RemoteOperation::NetworkEgress], vec![prefix.clone()]);
        assert!(
            !singleton_scope.allows_endpoint(&shifted),
            "endpoint prefix matched across a non-delimited boundary"
        );
    }
}

impl FuzzOperation {
    fn into_operation(self) -> RemoteOperation {
        match self {
            Self::NetworkEgress => RemoteOperation::NetworkEgress,
            Self::FederationSync => RemoteOperation::FederationSync,
            Self::RevocationFetch => RemoteOperation::RevocationFetch,
            Self::RemoteAttestationVerify => RemoteOperation::RemoteAttestationVerify,
            Self::TelemetryExport => RemoteOperation::TelemetryExport,
            Self::RemoteComputation => RemoteOperation::RemoteComputation,
            Self::ArtifactUpload => RemoteOperation::ArtifactUpload,
        }
    }
}

fn bounded_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .take(MAX_SCOPE_ITEMS)
        .map(bounded_string)
        .filter(|value| !value.trim().is_empty())
        .collect()
}

fn bounded_string(value: String) -> String {
    value.chars().take(MAX_STRING_CHARS).collect()
}
