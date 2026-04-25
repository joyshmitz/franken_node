#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::config::Config;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs to prevent OOM
    if data.len() > 1_000_000 {
        return;
    }

    // Only fuzz valid UTF-8 strings since TOML requires valid UTF-8
    if let Ok(toml_str) = str::from_utf8(data) {
        // Attempt to parse the TOML configuration
        // We expect most random inputs to fail parsing, which is normal
        let _ = toml::from_str::<Config>(toml_str);

        // Additional fuzzing: test the error handling path explicitly
        // by trying to validate malformed configs if they parse
        if let Ok(config) = toml::from_str::<Config>(toml_str) {
            // The validate() method should never panic, even on malformed data
            let _ = config.validate();

            // Test serialization round-trip to catch serialization bugs
            if let Ok(serialized) = toml::to_string(&config) {
                let _ = toml::from_str::<Config>(&serialized);
            }
        }
    }
});