#![forbid(unsafe_code)]
extern crate self as frankenengine_node;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionableError {
    message: String,
    fix_command: String,
    help_urls: Vec<String>,
}

impl ActionableError {
    pub fn new(message: impl Into<String>, fix_command: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fix_command: fix_command.into(),
            help_urls: Vec::new(),
        }
    }

    pub fn with_help_url(mut self, help_url: impl Into<String>) -> Self {
        self.help_urls.push(help_url.into());
        self
    }
}

impl std::fmt::Display for ActionableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\nfix_command={}", self.message, self.fix_command)?;
        for help_url in &self.help_urls {
            write!(f, "\nhelp_url={help_url}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ActionableError {}

#[cfg(feature = "extended-surfaces")]
pub mod api;
pub mod capacity_defaults;
#[cfg(feature = "extended-surfaces")]
pub mod claims;
pub mod config;
#[cfg(feature = "extended-surfaces")]
pub mod conformance;
pub mod connector;
pub mod control_plane;
#[cfg(feature = "extended-surfaces")]
pub mod encoding;
#[cfg(feature = "extended-surfaces")]
pub mod extensions;
#[cfg(feature = "extended-surfaces")]
pub mod federation;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod migration;
pub mod observability;
pub mod ops;
#[cfg(feature = "extended-surfaces")]
pub mod perf;
#[cfg(feature = "extended-surfaces")]
pub mod policy;
#[cfg(feature = "extended-surfaces")]
pub mod registry;
pub mod remote;
#[cfg(feature = "extended-surfaces")]
pub mod repair;
pub mod replay;
#[cfg(feature = "extended-surfaces")]
#[path = "control_plane/root_pointer.rs"]
pub mod root_pointer;
pub mod runtime;
pub mod schema_versions;
#[cfg(feature = "extended-surfaces")]
pub mod sdk;
pub mod security;
pub mod storage;
pub mod supply_chain;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
pub mod tools;
pub mod vef;
#[cfg(feature = "extended-surfaces")]
pub mod verifier_economy;
