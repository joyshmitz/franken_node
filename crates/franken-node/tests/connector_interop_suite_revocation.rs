use frankenengine_node::connector::interop_suite::{run_suite, InteropClass, InteropTestCase};

const REVOKED_STATUS: &str = "revoked";

mod connector {
    pub mod interop_suite {
        use super::super::*;

        fn revocation_case(case_id: &str, input: &str, expected_output: &str) -> InteropTestCase {
            InteropTestCase {
                class: InteropClass::Revocation,
                case_id: case_id.to_string(),
                input: input.to_string(),
                expected_output: expected_output.to_string(),
                implementation: "interop-regression".to_string(),
            }
        }

        #[test]
        fn matching_revocation_marker_is_accepted() {
            let results = run_suite(&[revocation_case(
                "revocation-match",
                REVOKED_STATUS,
                REVOKED_STATUS,
            )]);

            assert_eq!(results.len(), 1);
            assert!(results[0].passed);
            assert_eq!(results[0].details, "implementations agree");
            assert!(results[0].reproducer.is_none());
        }

        #[test]
        fn non_matching_revocation_marker_is_rejected() {
            let results = run_suite(&[revocation_case(
                "revocation-non-match",
                REVOKED_STATUS,
                "active",
            )]);

            assert_eq!(results.len(), 1);
            assert!(!results[0].passed);
            assert_eq!(results[0].class, InteropClass::Revocation);
            assert_eq!(results[0].details, "impl_a=true, impl_b=false");
        }

        #[test]
        fn same_length_revocation_differences_reject_at_all_positions() {
            for (case_id, candidate) in [
                ("revocation-first-byte-diff", "aevoked"),
                ("revocation-middle-byte-diff", "revXked"),
                ("revocation-last-byte-diff", "revokea"),
            ] {
                assert_eq!(candidate.len(), REVOKED_STATUS.len());
                let results = run_suite(&[revocation_case(case_id, candidate, REVOKED_STATUS)]);

                assert_eq!(results.len(), 1);
                assert!(
                    !results[0].passed,
                    "same-length revocation mismatch must reject regardless of differing byte position"
                );
                assert_eq!(results[0].details, "impl_a=false, impl_b=true");
            }
        }
    }
}
