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

#[cfg(test)]
mod tests {
    use super::ActionableError;

    #[test]
    fn actionable_error_without_help_urls_omits_help_url_lines() {
        let err = ActionableError::new("missing runtime", "install node");
        let rendered = err.to_string();

        assert_eq!(rendered, "missing runtime\nfix_command=install node");
        assert!(!rendered.contains("help_url="));
        assert!(err.help_urls.is_empty());
    }

    #[test]
    fn empty_message_still_renders_fix_command() {
        let err = ActionableError::new("", "franken-node doctor");
        let rendered = err.to_string();

        assert_eq!(rendered, "\nfix_command=franken-node doctor");
        assert!(rendered.contains("fix_command="));
    }

    #[test]
    fn empty_fix_command_still_renders_explicit_field() {
        let err = ActionableError::new("operator action required", "");
        let rendered = err.to_string();

        assert_eq!(rendered, "operator action required\nfix_command=");
        assert!(rendered.ends_with("fix_command="));
    }

    #[test]
    fn blank_help_url_is_not_silently_dropped() {
        let err = ActionableError::new("needs docs", "open docs").with_help_url("");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 1);
        assert!(rendered.ends_with("\nhelp_url="));
    }

    #[test]
    fn multiple_help_urls_preserve_insertion_order() {
        let err = ActionableError::new("needs runtime", "install runtime")
            .with_help_url("https://example.invalid/node")
            .with_help_url("https://example.invalid/bun");
        let rendered = err.to_string();

        let first = rendered.find("https://example.invalid/node").unwrap();
        let second = rendered.find("https://example.invalid/bun").unwrap();
        assert!(first < second);
        assert_eq!(err.help_urls.len(), 2);
    }

    #[test]
    fn newline_in_message_does_not_remove_fix_command_field() {
        let err = ActionableError::new("line one\nline two", "run doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("line one\nline two\nfix_command="));
        assert!(rendered.contains("fix_command=run doctor"));
    }

    #[test]
    fn newline_in_fix_command_does_not_remove_help_urls() {
        let err = ActionableError::new("needs remediation", "first\nsecond")
            .with_help_url("https://example.invalid/remediation");
        let rendered = err.to_string();

        assert!(rendered.contains("fix_command=first\nsecond"));
        assert!(rendered.contains("\nhelp_url=https://example.invalid/remediation"));
    }

    #[test]
    fn clone_preserves_empty_edge_fields() {
        let err = ActionableError::new("", "").with_help_url("");
        let cloned = err.clone();

        assert_eq!(cloned, err);
        assert_eq!(cloned.to_string(), "\nfix_command=\nhelp_url=");
    }

    #[test]
    fn whitespace_only_message_is_preserved_not_trimmed() {
        let err = ActionableError::new("   ", "run doctor");
        let rendered = err.to_string();

        assert_eq!(rendered, "   \nfix_command=run doctor");
        assert!(rendered.starts_with("   "));
    }

    #[test]
    fn whitespace_only_fix_command_is_preserved_as_explicit_field() {
        let err = ActionableError::new("manual remediation required", "   ");
        let rendered = err.to_string();

        assert_eq!(rendered, "manual remediation required\nfix_command=   ");
        assert!(rendered.ends_with("fix_command=   "));
    }

    #[test]
    fn whitespace_only_help_url_is_not_silently_filtered() {
        let err = ActionableError::new("needs docs", "open docs").with_help_url("   ");
        let rendered = err.to_string();

        assert_eq!(err.help_urls, vec!["   ".to_string()]);
        assert!(rendered.ends_with("\nhelp_url=   "));
    }

    #[test]
    fn message_containing_help_url_literal_does_not_mutate_help_url_list() {
        let err = ActionableError::new("help_url=https://example.invalid/in-message", "fix");
        let rendered = err.to_string();

        assert!(err.help_urls.is_empty());
        assert!(rendered.starts_with("help_url=https://example.invalid/in-message"));
        assert!(rendered.ends_with("\nfix_command=fix"));
    }

    #[test]
    fn fix_command_containing_help_url_literal_stays_in_fix_field() {
        let err = ActionableError::new("operator action", "help_url=https://example.invalid/fix");
        let rendered = err.to_string();

        assert!(err.help_urls.is_empty());
        assert_eq!(
            rendered,
            "operator action\nfix_command=help_url=https://example.invalid/fix"
        );
    }

    #[test]
    fn help_url_with_newline_is_preserved_as_single_help_entry() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/one\nhttps://example.invalid/two");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 1);
        assert!(rendered.contains("\nhelp_url=https://example.invalid/one\n"));
        assert!(rendered.ends_with("https://example.invalid/two"));
    }

    #[test]
    fn repeated_empty_help_urls_are_preserved_in_order() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("")
            .with_help_url("");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 2);
        assert_eq!(rendered.matches("\nhelp_url=").count(), 2);
        assert!(rendered.ends_with("\nhelp_url=\nhelp_url="));
    }

    #[test]
    fn negative_message_containing_fix_command_literal_does_not_override_fix_field() {
        let err = ActionableError::new("bad input\nfix_command=malicious", "franken-node doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("bad input\nfix_command=malicious"));
        assert!(rendered.ends_with("\nfix_command=franken-node doctor"));
        assert_eq!(rendered.matches("fix_command=").count(), 2);
    }

    #[test]
    fn negative_help_url_containing_fix_command_literal_stays_help_url_entry() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/docs\nfix_command=malicious");
        let rendered = err.to_string();

        assert_eq!(
            err.help_urls,
            vec!["https://example.invalid/docs\nfix_command=malicious"]
        );
        assert!(
            rendered.contains("\nhelp_url=https://example.invalid/docs\nfix_command=malicious")
        );
        assert!(rendered.starts_with("needs docs\nfix_command=open docs"));
    }

    #[test]
    fn negative_duplicate_help_urls_are_not_deduplicated() {
        let err = ActionableError::new("needs docs", "open docs")
            .with_help_url("https://example.invalid/same")
            .with_help_url("https://example.invalid/same");
        let rendered = err.to_string();

        assert_eq!(err.help_urls.len(), 2);
        assert_eq!(rendered.matches("https://example.invalid/same").count(), 2);
    }

    #[test]
    fn negative_carriage_return_in_message_is_preserved() {
        let err = ActionableError::new("first\rsecond", "run doctor");
        let rendered = err.to_string();

        assert!(rendered.starts_with("first\rsecond"));
        assert!(rendered.ends_with("\nfix_command=run doctor"));
    }

    #[test]
    fn negative_carriage_return_in_fix_command_is_preserved() {
        let err = ActionableError::new("operator action", "first\rsecond");
        let rendered = err.to_string();

        assert_eq!(rendered, "operator action\nfix_command=first\rsecond");
    }

    #[test]
    fn negative_error_source_is_absent() {
        let err = ActionableError::new("operator action", "run doctor");

        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn negative_debug_output_does_not_replace_display_contract() {
        let err = ActionableError::new("operator action", "run doctor")
            .with_help_url("https://example.invalid/help");
        let rendered = err.to_string();
        let debug = format!("{err:?}");

        assert!(debug.contains("ActionableError"));
        assert!(debug.contains("fix_command"));
        assert_ne!(debug, rendered);
    }
}

#[cfg(feature = "extended-surfaces")]
pub mod api;
#[cfg(any(test, feature = "extended-surfaces"))]
pub mod atc;
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
