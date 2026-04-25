#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::config::NetworkAllowlistEntry;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs to prevent OOM
    if data.len() > 100_000 {
        return;
    }

    // Only fuzz valid UTF-8 strings since TOML requires valid UTF-8
    if let Ok(toml_str) = str::from_utf8(data) {
        // Attempt to parse the TOML network allowlist entry
        // We expect most random inputs to fail parsing, which is normal
        let _ = toml::from_str::<NetworkAllowlistEntry>(toml_str);

        // Additional fuzzing: test serialization round-trip
        if let Ok(entry) = toml::from_str::<NetworkAllowlistEntry>(toml_str) {
            // Test serialization round-trip to catch serialization bugs
            if let Ok(serialized) = toml::to_string(&entry) {
                let _ = toml::from_str::<NetworkAllowlistEntry>(&serialized);
            }

            // Test that host field is reasonable (no panics on weird strings)
            let _ = entry.host.chars().count();
            let _ = entry.host.is_empty();

            // Test port field validation (should handle any u16 value)
            if let Some(port) = entry.port {
                let _ = port.to_string();
            }

            // Test reason field (no panics on weird strings)
            let _ = entry.reason.chars().count();
            let _ = entry.reason.is_empty();
        }

        // Test parsing as part of a TOML document with surrounding structure
        let wrapped_toml = format!("[network]\nallowlist = [{}]", toml_str);
        if let Ok(table) = toml::from_str::<toml::Table>(&wrapped_toml) {
            if let Some(network) = table.get("network") {
                if let Some(allowlist) = network.get("allowlist") {
                    // Try to deserialize the allowlist array
                    let _ = allowlist.clone().try_into::<Vec<NetworkAllowlistEntry>>();
                }
            }
        }
    }
});