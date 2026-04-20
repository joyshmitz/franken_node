use frankenengine_node::tools::replay_bundle_adversarial_fuzz::replay_bundle_adversarial_fuzz_corpus;

#[test]
fn replay_bundle_adversarial_fuzz_corpus_fails_with_typed_errors() {
    for case in replay_bundle_adversarial_fuzz_corpus() {
        let err = match case.run() {
            Ok(()) => panic!("{} should fail closed", case.name),
            Err(err) => err,
        };
        assert!(
            case.expected_error.matches_error(&err),
            "{} returned unexpected error: {err:?}",
            case.name
        );
    }
}
