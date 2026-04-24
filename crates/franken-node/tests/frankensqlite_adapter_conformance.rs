#[path = "../../../tests/integration/frankensqlite_adapter_conformance.rs"]
mod frankensqlite_adapter_conformance;

#[cfg(feature = "advanced-features")]
use frankenengine_node::conformance::fsqlite_inspired_suite::{
    ConformanceDomain, ConformanceFixture, ConformanceId, ConformanceSuiteRunner,
};

#[cfg(feature = "advanced-features")]
fn fixture(number: u16) -> ConformanceFixture {
    ConformanceFixture {
        conformance_id: ConformanceId::new(ConformanceDomain::Determinism, number),
        domain: ConformanceDomain::Determinism,
        description: format!("overflow fixture {number}"),
        input: serde_json::json!({"number": number}),
        expected: serde_json::json!({"accepted": true}),
    }
}

#[cfg(feature = "advanced-features")]
#[test]
fn conformance_suite_fixture_overflow_evicts_oldest_id() {
    let mut runner = ConformanceSuiteRunner::new();

    for number in 1..=4097 {
        runner
            .register_fixture(fixture(number))
            .expect("unique fixture should register");
    }

    assert_eq!(runner.fixture_count(), 4096);
    runner
        .register_fixture(fixture(1))
        .expect("evicted oldest fixture id should be reusable");
    assert_eq!(runner.fixture_count(), 4096);
    assert!(
        runner.register_fixture(fixture(3)).is_err(),
        "non-evicted fixture id should remain registered"
    );
}
