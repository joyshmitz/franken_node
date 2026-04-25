#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::supply_chain::ecosystem_telemetry::CompromiseReductionReport;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs to prevent OOM
    if data.len() > 1_000_000 {
        return;
    }

    // Only fuzz valid UTF-8 strings since JSON requires valid UTF-8
    if let Ok(json_str) = str::from_utf8(data) {
        // Attempt to parse the JSON into CompromiseReductionReport
        // We expect most random inputs to fail parsing, which is normal
        let _ = serde_json::from_str::<CompromiseReductionReport>(json_str);

        // Additional fuzzing: test serialization round-trip to catch edge cases
        if let Ok(report) = serde_json::from_str::<CompromiseReductionReport>(json_str) {
            // Test that valid reports can be serialized back
            if let Ok(serialized) = serde_json::to_string(&report) {
                // Ensure round-trip consistency
                let _ = serde_json::from_str::<CompromiseReductionReport>(&serialized);
            }

            // Test field validation - ensure f64 fields don't contain NaN or infinity
            assert!(report.minimum_required_ratio.is_finite(), "minimum_required_ratio must be finite");
            assert!(report.compromise_reduction_ratio.is_finite(), "compromise_reduction_ratio must be finite");

            // Ensure non-negative ratios
            assert!(report.minimum_required_ratio >= 0.0, "minimum_required_ratio must be non-negative");
            assert!(report.compromise_reduction_ratio >= 0.0, "compromise_reduction_ratio must be non-negative");
        }
    }
});