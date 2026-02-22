//! Integration tests for bd-24du: ATC degraded/offline fallback behavior.
//!
//! These tests validate the deterministic fallback contract independent of
//! implementation details:
//! - partition/outage enters degraded mode,
//! - local controls remain available,
//! - federation-bound actions are blocked,
//! - rejoin/reconciliation exits to normal and is audited.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Degraded,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    code: &'static str,
    ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AtcState {
    mode: Mode,
    entered_at: Option<u64>,
    stabilization_started_at: Option<u64>,
    events: Vec<Event>,
}

impl AtcState {
    fn new() -> Self {
        Self {
            mode: Mode::Normal,
            entered_at: None,
            stabilization_started_at: None,
            events: Vec::new(),
        }
    }

    fn activate_partition(&mut self, now: u64) {
        self.mode = Mode::Degraded;
        self.entered_at = Some(now);
        self.stabilization_started_at = None;
        self.events.push(Event {
            code: "TRUST_INPUT_STALE",
            ts: now,
        });
        self.events.push(Event {
            code: "DEGRADED_MODE_ENTERED",
            ts: now,
        });
    }

    fn evaluate_action(&mut self, action: &str, now: u64) -> bool {
        let permitted = match self.mode {
            Mode::Normal => true,
            Mode::Degraded => !matches!(action, "federation.sync" | "federation.publish"),
            Mode::Suspended => matches!(action, "risk.local_assess" | "health.check"),
        };
        self.events.push(Event {
            code: if permitted {
                "DEGRADED_ACTION_ANNOTATED"
            } else {
                "DEGRADED_ACTION_BLOCKED"
            },
            ts: now,
        });
        permitted
    }

    fn maybe_suspend(&mut self, now: u64, max_degraded_secs: u64) {
        if self.mode != Mode::Degraded {
            return;
        }
        if let Some(entered_at) = self.entered_at
            && now.saturating_sub(entered_at) >= max_degraded_secs
        {
            self.mode = Mode::Suspended;
            self.events.push(Event {
                code: "DEGRADED_MODE_SUSPENDED",
                ts: now,
            });
        }
    }

    fn observe_rejoin(
        &mut self,
        now: u64,
        federation_available: bool,
        health_gate_restored: bool,
        error_rate: f64,
        stabilization_secs: u64,
    ) {
        if self.mode == Mode::Normal {
            return;
        }
        let healthy = federation_available && health_gate_restored && error_rate <= 0.05;
        if !healthy {
            self.stabilization_started_at = None;
            return;
        }

        if self.stabilization_started_at.is_none() {
            self.stabilization_started_at = Some(now);
            self.events.push(Event {
                code: "TRUST_INPUT_REFRESHED",
                ts: now,
            });
            return;
        }

        let started_at = self.stabilization_started_at.unwrap_or(now);
        if now.saturating_sub(started_at) >= stabilization_secs {
            self.mode = Mode::Normal;
            self.entered_at = None;
            self.stabilization_started_at = None;
            self.events.push(Event {
                code: "DEGRADED_MODE_EXITED",
                ts: now,
            });
        }
    }
}

#[test]
fn partition_outage_triggers_local_first_fallback() {
    let mut state = AtcState::new();
    state.activate_partition(1_000);

    let remote_allowed = state.evaluate_action("federation.sync", 1_005);
    let local_allowed = state.evaluate_action("risk.local_assess", 1_006);

    assert_eq!(state.mode, Mode::Degraded);
    assert!(!remote_allowed);
    assert!(local_allowed);

    let codes: Vec<&str> = state.events.iter().map(|event| event.code).collect();
    assert!(codes.starts_with(&["TRUST_INPUT_STALE", "DEGRADED_MODE_ENTERED"]));
    assert!(codes.contains(&"DEGRADED_ACTION_BLOCKED"));
    assert!(codes.contains(&"DEGRADED_ACTION_ANNOTATED"));
}

#[test]
fn suspended_mode_still_allows_essential_local_controls() {
    let mut state = AtcState::new();
    state.activate_partition(2_000);
    state.maybe_suspend(2_600, 600);

    assert_eq!(state.mode, Mode::Suspended);
    assert!(state.evaluate_action("health.check", 2_601));
    assert!(!state.evaluate_action("federation.publish", 2_602));

    let codes: Vec<&str> = state.events.iter().map(|event| event.code).collect();
    assert!(codes.contains(&"DEGRADED_MODE_SUSPENDED"));
}

#[test]
fn rejoin_reconciliation_is_audited_and_exits_cleanly() {
    let mut state = AtcState::new();
    state.activate_partition(3_000);

    state.observe_rejoin(3_010, true, true, 0.01, 120);
    assert_eq!(state.mode, Mode::Degraded);

    state.observe_rejoin(3_129, true, true, 0.01, 120);
    assert_eq!(state.mode, Mode::Degraded);

    state.observe_rejoin(3_130, true, true, 0.01, 120);
    assert_eq!(state.mode, Mode::Normal);

    let codes: Vec<&str> = state.events.iter().map(|event| event.code).collect();
    assert!(codes.contains(&"TRUST_INPUT_REFRESHED"));
    assert!(codes.contains(&"DEGRADED_MODE_EXITED"));
}

#[test]
fn identical_inputs_produce_identical_event_streams() {
    fn run() -> Vec<Event> {
        let mut state = AtcState::new();
        state.activate_partition(4_000);
        state.evaluate_action("federation.sync", 4_010);
        state.observe_rejoin(4_020, true, true, 0.01, 120);
        state.observe_rejoin(4_140, true, true, 0.01, 120);
        state.events
    }

    assert_eq!(run(), run());
}
