use std::path::Path;

#[test]
fn conformance_fixture_exists() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/vef_receipt_chain_integrity.rs");
    assert!(
        fixture.is_file(),
        "expected conformance fixture at {}",
        fixture.display()
    );
}
