//! Cross-source isolation regression for `AuthFailureLimiter` (bd-2lnpp).
//!
//! Failure mode being guarded against: a single shared token bucket would let
//! one abusive source exhaust the entire instance-wide authentication budget,
//! rate-limiting all other clients alongside the abuser. The fix is to keep a
//! per-source bucket so each `source_ip` consumes only its own tokens.
//!
//! These tests assert the partitioning invariant by construction: source A
//! drains its own bucket; source B (and a third unrelated source) must still
//! be admitted on the same `AuthFailureLimiter` instance.

#![cfg(feature = "control-plane")]

use frankenengine_node::api::middleware::{AuthFailureLimiter, RateLimitConfig};

/// A tight config so a small number of attempts saturates one source's bucket.
fn tight_config() -> RateLimitConfig {
    RateLimitConfig {
        sustained_rps: 1,
        burst_size: 3,
        fail_closed: true,
    }
}

#[test]
fn one_source_rate_limited_does_not_block_other_sources() {
    let mut limiter = AuthFailureLimiter::with_config(tight_config());

    let source_a = "203.0.113.10";
    let source_b = "198.51.100.20";
    let source_c = "192.0.2.30";

    // Drain source A's bucket: burst_size=3 → fourth call must rate-limit.
    for attempt in 0..3 {
        limiter
            .check_auth_attempt("trace-a", source_a)
            .unwrap_or_else(|err| {
                panic!(
                    "source A attempt {attempt} should pass before bucket drains, got {err:?}"
                )
            });
    }
    let blocked = limiter
        .check_auth_attempt("trace-a", source_a)
        .expect_err("source A's 4th attempt must be rate-limited (bucket drained)");
    assert!(
        format!("{blocked:?}").contains("RateLimited"),
        "source A failure must be RateLimited, got {blocked:?}"
    );

    // Cross-source isolation: with the SAME limiter instance, source B and
    // source C must each get a fresh bucket and be admitted. If the bucket
    // were shared, these calls would also fail.
    for attempt in 0..3 {
        limiter
            .check_auth_attempt("trace-b", source_b)
            .unwrap_or_else(|err| {
                panic!("cross-source isolation broken: source B attempt {attempt} blocked: {err:?}")
            });
    }
    for attempt in 0..3 {
        limiter
            .check_auth_attempt("trace-c", source_c)
            .unwrap_or_else(|err| {
                panic!("cross-source isolation broken: source C attempt {attempt} blocked: {err:?}")
            });
    }
}

#[test]
fn rate_limited_source_does_not_consume_other_sources_tokens() {
    // Reverse-direction check: source A is hammered (and rate-limited many
    // times) while source B sits idle. Source B's bucket must still be full
    // when it finally makes a request — proving each source consumes only its
    // own tokens.
    let mut limiter = AuthFailureLimiter::with_config(tight_config());

    let abuser = "203.0.113.99";
    let victim = "198.51.100.42";

    // Abuser saturates and then keeps trying many times — every overflow call
    // would consume tokens from a shared bucket.
    for _ in 0..3 {
        let _ = limiter.check_auth_attempt("trace-abuse", abuser);
    }
    for _ in 0..50 {
        // We expect every one of these to be rate-limited (per-source), which
        // is exactly the behaviour we want under heavy abuse.
        let _ = limiter.check_auth_attempt("trace-abuse", abuser);
    }

    // Victim's bucket must still hold a full burst — three back-to-back
    // attempts must succeed. A shared-bucket implementation would fail here.
    for attempt in 0..3 {
        limiter
            .check_auth_attempt("trace-victim", victim)
            .unwrap_or_else(|err| {
                panic!(
                    "shared-bucket regression: victim attempt {attempt} blocked by abuser's load: {err:?}"
                )
            });
    }
}

#[test]
fn many_distinct_sources_all_admitted_concurrently() {
    // With per-source partitioning, N distinct sources should each be admitted
    // up to their own burst limit even when issued through the same limiter
    // back-to-back. A shared bucket would only admit `burst_size` calls total.
    let mut limiter = AuthFailureLimiter::with_config(tight_config());

    let sources: Vec<String> = (0..32).map(|i| format!("198.51.100.{i}")).collect();

    // First pass: every source should get an admit.
    for (i, ip) in sources.iter().enumerate() {
        limiter
            .check_auth_attempt("trace-multi", ip)
            .unwrap_or_else(|err| panic!("source {i} ({ip}) blocked on first attempt: {err:?}"));
    }

    // Telemetry sanity: stats should reflect 0 failures (no rate-limit
    // events recorded for successful first-attempts).
    let stats = limiter.get_failure_stats();
    assert_eq!(
        stats.global_failure_count, 0,
        "no failures should be recorded for successful per-source admits, got {}",
        stats.global_failure_count
    );
}
