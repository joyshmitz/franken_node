//! bd-1cs7: Conformance tests for the three-phase cancellation protocol.
//!
//! Validates that every high-impact workflow follows REQUEST -> DRAIN -> FINALIZE
//! with correct phase transitions, budget enforcement, and resource cleanup.

#[cfg(test)]
mod tests {
    use franken_node::control_plane::cancellation_protocol::*;

    // ---- Phase ordering conformance ----

    #[test]
    fn conformance_three_phase_ordering() {
        // INV-CANP-THREE-PHASE: all cancellations must pass through
        // REQUEST, DRAIN, FINALIZE in order.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-lifecycle", 5, 1000, "t1").unwrap();
        proto.start_drain("wf-lifecycle", 1100, "t1").unwrap();
        proto.complete_drain("wf-lifecycle", 1500, "t1").unwrap();
        proto.finalize("wf-lifecycle", &ResourceTracker::empty(), 1600, "t1").unwrap();

        let rec = proto.get_record("wf-lifecycle").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::Finalized);
    }

    #[test]
    fn conformance_skip_drain_rejected() {
        // Cannot skip from REQUEST directly to FINALIZE.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-skip", 0, 1000, "t1").unwrap();
        let err = proto.finalize("wf-skip", &ResourceTracker::empty(), 1100, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_INVALID_PHASE);
    }

    #[test]
    fn conformance_skip_request_rejected() {
        // Cannot start drain without first requesting cancel.
        let mut proto = CancellationProtocol::default();
        let err = proto.start_drain("wf-norequst", 1000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_INVALID_PHASE);
    }

    // ---- Idempotent cancel ----

    #[test]
    fn conformance_idempotent_cancel() {
        // INV-CANP-IDEMPOTENT: duplicate requests are absorbed.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-idem", 5, 1000, "t1").unwrap();
        let rec = proto.request_cancel("wf-idem", 3, 1001, "t1").unwrap();
        assert_eq!(rec.current_phase, CancelPhase::CancelRequested);
    }

    // ---- Drain budget enforcement ----

    #[test]
    fn conformance_drain_within_budget() {
        // INV-CANP-DRAIN-BOUNDED: drain completes within budget.
        let config = DrainConfig::new(5000, true);
        let mut proto = CancellationProtocol::new(config);
        proto.request_cancel("wf-budget", 10, 1000, "t1").unwrap();
        proto.start_drain("wf-budget", 1100, "t1").unwrap();
        let rec = proto.complete_drain("wf-budget", 3000, "t1").unwrap();
        assert!(!rec.drain_timed_out);
        assert_eq!(rec.current_phase, CancelPhase::DrainComplete);
    }

    #[test]
    fn conformance_drain_timeout_force_finalize() {
        // INV-CANP-DRAIN-BOUNDED: exceeded budget triggers CAN-004 and force finalize.
        let config = DrainConfig::new(1000, true);
        let mut proto = CancellationProtocol::new(config);
        proto.request_cancel("wf-timeout", 10, 1000, "t1").unwrap();
        proto.start_drain("wf-timeout", 1100, "t1").unwrap();
        let rec = proto.complete_drain("wf-timeout", 5000, "t1").unwrap();
        assert!(rec.drain_timed_out);
        assert_eq!(rec.current_phase, CancelPhase::DrainComplete);

        // CAN-004 should be in the audit log.
        let can004 = proto.audit_log().iter()
            .filter(|e| e.event_code == event_codes::CAN_004)
            .count();
        assert_eq!(can004, 1);
    }

    #[test]
    fn conformance_drain_timeout_no_force_errors() {
        // When force_on_timeout is false, drain timeout is an error.
        let config = DrainConfig::new(1000, false);
        let mut proto = CancellationProtocol::new(config);
        proto.request_cancel("wf-noforce", 10, 1000, "t1").unwrap();
        proto.start_drain("wf-noforce", 1100, "t1").unwrap();
        let err = proto.complete_drain("wf-noforce", 5000, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_DRAIN_TIMEOUT);
    }

    // ---- Resource leak detection ----

    #[test]
    fn conformance_clean_finalize_no_leaks() {
        // INV-CANP-FINALIZE-CLEAN: no resource leaks after finalize.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-clean", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-clean", 1100, "t1").unwrap();
        proto.complete_drain("wf-clean", 1200, "t1").unwrap();
        proto.finalize("wf-clean", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let rec = proto.get_record("wf-clean").unwrap();
        assert!(rec.resource_leaks.is_empty());

        // CAN-005 should be in the audit log.
        let can005 = proto.audit_log().iter()
            .filter(|e| e.event_code == event_codes::CAN_005)
            .count();
        assert_eq!(can005, 1);
    }

    #[test]
    fn conformance_resource_leak_detected() {
        // INV-CANP-FINALIZE-CLEAN: resource leaks trigger CAN-006.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-leak", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-leak", 1100, "t1").unwrap();
        proto.complete_drain("wf-leak", 1200, "t1").unwrap();

        let mut resources = ResourceTracker::empty();
        resources.held_locks.push("fencing-token-42".to_string());
        resources.open_handles.push("region-handle-7".to_string());

        let err = proto.finalize("wf-leak", &resources, 1300, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_LEAK);

        // CAN-006 should be in the audit log.
        let can006 = proto.audit_log().iter()
            .filter(|e| e.event_code == event_codes::CAN_006)
            .count();
        assert_eq!(can006, 1);
    }

    // ---- Already-finalized rejection ----

    #[test]
    fn conformance_double_cancel_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-dbl", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-dbl", 1100, "t1").unwrap();
        proto.complete_drain("wf-dbl", 1200, "t1").unwrap();
        proto.finalize("wf-dbl", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let err = proto.request_cancel("wf-dbl", 0, 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }

    #[test]
    fn conformance_double_finalize_rejected() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-dblf", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-dblf", 1100, "t1").unwrap();
        proto.complete_drain("wf-dblf", 1200, "t1").unwrap();
        proto.finalize("wf-dblf", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let err = proto.finalize("wf-dblf", &ResourceTracker::empty(), 1400, "t1").unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CANCEL_ALREADY_FINAL);
    }

    // ---- Audit trail completeness ----

    #[test]
    fn conformance_audit_trail_complete() {
        // INV-CANP-AUDIT-COMPLETE: every phase transition emits an audit event.
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-audit", 5, 1000, "t1").unwrap();
        proto.start_drain("wf-audit", 1100, "t1").unwrap();
        proto.complete_drain("wf-audit", 1500, "t1").unwrap();
        proto.finalize("wf-audit", &ResourceTracker::empty(), 1600, "t1").unwrap();

        let log = proto.audit_log();
        assert_eq!(log.len(), 4);
        assert_eq!(log[0].event_code, event_codes::CAN_001);
        assert_eq!(log[1].event_code, event_codes::CAN_002);
        assert_eq!(log[2].event_code, event_codes::CAN_003);
        assert_eq!(log[3].event_code, event_codes::CAN_005);

        // All events have trace_id and workflow_id
        for event in log {
            assert_eq!(event.workflow_id, "wf-audit");
            assert_eq!(event.trace_id, "t1");
            assert_eq!(event.schema_version, SCHEMA_VERSION);
        }
    }

    // ---- Multiple workflows ----

    #[test]
    fn conformance_multiple_workflows_independent() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-a", 3, 1000, "ta").unwrap();
        proto.request_cancel("wf-b", 7, 1000, "tb").unwrap();

        proto.start_drain("wf-a", 1100, "ta").unwrap();
        assert_eq!(proto.current_phase("wf-a"), Some(CancelPhase::Draining));
        assert_eq!(proto.current_phase("wf-b"), Some(CancelPhase::CancelRequested));

        proto.complete_drain("wf-a", 1200, "ta").unwrap();
        proto.finalize("wf-a", &ResourceTracker::empty(), 1300, "ta").unwrap();

        assert_eq!(proto.finalized_count(), 1);
        assert_eq!(proto.active_count(), 1);
    }

    // ---- Timing report ----

    #[test]
    fn conformance_timing_report_format() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-time", 5, 1000, "t1").unwrap();
        proto.start_drain("wf-time", 1100, "t1").unwrap();
        proto.complete_drain("wf-time", 1500, "t1").unwrap();
        proto.finalize("wf-time", &ResourceTracker::empty(), 1600, "t1").unwrap();

        let (header, rows) = generate_timing_report(&proto);
        assert!(header.contains("workflow_id"));
        assert!(header.contains("drain_duration_ms"));
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains("wf-time"));
        assert!(rows[0].contains("finalized"));
    }

    // ---- Cancellation readiness ----

    #[test]
    fn conformance_readiness_check_clean() {
        let proto = CancellationProtocol::default();
        assert!(cancellation_readiness_check(&proto));
    }

    // ---- JSONL export ----

    #[test]
    fn conformance_jsonl_export_valid() {
        let mut proto = CancellationProtocol::default();
        proto.request_cancel("wf-jsonl", 0, 1000, "t1").unwrap();
        proto.start_drain("wf-jsonl", 1100, "t1").unwrap();
        proto.complete_drain("wf-jsonl", 1200, "t1").unwrap();
        proto.finalize("wf-jsonl", &ResourceTracker::empty(), 1300, "t1").unwrap();

        let jsonl = proto.export_audit_log_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 4);
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    // ---- Serde roundtrip ----

    #[test]
    fn conformance_cancel_phase_serde() {
        for phase in &CancelPhase::ALL {
            let json = serde_json::to_string(phase).unwrap();
            let parsed: CancelPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, parsed);
        }
    }

    #[test]
    fn conformance_drain_config_serde() {
        let config = DrainConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DrainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn conformance_audit_event_serde() {
        let event = CancelAuditEvent::new(
            event_codes::CAN_001,
            "wf-serde",
            CancelPhase::Idle,
            CancelPhase::CancelRequested,
            1000,
            "t1",
            "test",
        );
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CancelAuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }
}
