pub mod compat_gate;
pub mod error;
pub mod fleet_control_routes;
pub mod fleet_quarantine;
pub mod middleware;
pub mod operator_routes;
pub mod service;
pub mod session_auth;
pub mod trust_card_routes;
pub mod verifier_routes;

/// Return at most `max_chars` Unicode scalar values from `input` without
/// violating UTF-8 boundaries.
pub(crate) fn utf8_prefix(input: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    let end = input
        .char_indices()
        .nth(max_chars)
        .map_or(input.len(), |(idx, _)| idx);
    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::utf8_prefix;

    #[test]
    fn utf8_prefix_ascii() {
        assert_eq!(utf8_prefix("abcdef", 3), "abc");
        assert_eq!(utf8_prefix("abc", 8), "abc");
    }

    #[test]
    fn utf8_prefix_respects_unicode_boundaries() {
        let value = "aß語🙂z";
        assert_eq!(utf8_prefix(value, 4), "aß語🙂");
    }

    #[test]
    fn utf8_prefix_zero_chars() {
        assert_eq!(utf8_prefix("abc", 0), "");
    }
}
