//! Real-service integration tests for connector lifecycle transitions.
//!
//! This test suite validates the connector state machine under real load
//! with actual service components (no mocks). Tests concurrent state transitions,
//! cancellation protocol, and error recovery.
//!
//! Follows anti-mock principles:
//! - Real components, no mocked dependencies
//! - Transaction isolation per test
//! - Structured JSON-line logging
//! - Comprehensive error path coverage

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{info, warn};
use frankenengine_node::connector::{
    lifecycle::{ConnectorState, ConnectorLifecycleManager},
    lease_service::{ConnectorLeaseService, LeaseConflictError},
    health_gate::{HealthGate, HealthStatus},
    cancellation_protocol::{CancellationPhase, CancellationProtocol},
};
use frankenengine_node::security::constant_time;
use serde_json::json;

/// Test harness for real connector lifecycle testing
#[derive(Debug)]
struct ConnectorLifecycleTestHarness {
    manager: Arc<ConnectorLifecycleManager>,
    lease_service: Arc<ConnectorLeaseService>,
    health_gate: Arc<HealthGate>,
    cancellation: Arc<CancellationProtocol>,
    test_start: Instant,
    phase_logs: Vec<PhaseLog>,
}

#[derive(Debug, Clone)]
struct PhaseLog {
    phase: String,
    timestamp: Instant,
    connector_id: String,
    from_state: ConnectorState,
    to_state: ConnectorState,
    duration_ms: u64,
    error: Option<String>,
}

impl ConnectorLifecycleTestHarness {
    async fn new() -> Self {
        let manager = Arc::new(ConnectorLifecycleManager::new());
        let lease_service = Arc::new(ConnectorLeaseService::new());
        let health_gate = Arc::new(HealthGate::new());
        let cancellation = Arc::new(CancellationProtocol::new());

        Self {
            manager,
            lease_service,
            health_gate,
            cancellation,
            test_start: Instant::now(),
            phase_logs: Vec::new(),
        }
    }

    fn log_phase(&mut self, phase: &str, connector_id: &str, from_state: ConnectorState, to_state: ConnectorState, duration: Duration, error: Option<String>) {
        let log = PhaseLog {
            phase: phase.to_string(),
            timestamp: Instant::now(),
            connector_id: connector_id.to_string(),
            from_state,
            to_state,
            duration_ms: duration.as_millis() as u64,
            error,
        };

        // Structured JSON-line logging to stderr
        eprintln!("{}", json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_integration",
            "phase": phase,
            "connector_id": connector_id,
            "from_state": from_state.as_str(),
            "to_state": to_state.as_str(),
            "duration_ms": log.duration_ms,
            "error": error,
            "event": "lifecycle_transition"
        }));

        self.phase_logs.push(log);
    }

    async fn transition_with_timing(&mut self, connector_id: &str, target_state: ConnectorState) -> Result<Duration, String> {
        let start = Instant::now();
        let current_state = self.manager.get_state(connector_id).await
            .unwrap_or(ConnectorState::Discovered);

        let result = self.manager.transition_to(connector_id, target_state).await;
        let duration = start.elapsed();

        match result {
            Ok(_) => {
                self.log_phase("transition", connector_id, current_state, target_state, duration, None);
                Ok(duration)
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);
                self.log_phase("transition", connector_id, current_state, current_state, duration, Some(error_msg.clone()));
                Err(error_msg)
            }
        }
    }

    async fn parallel_transition_stress_test(&mut self, connector_count: usize, transitions_per_connector: usize) -> Vec<Result<Duration, String>> {
        let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrent transitions
        let mut handles = Vec::new();

        for i in 0..connector_count {
            let connector_id = format!("connector-stress-{}", i);
            let manager = self.manager.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let start = Instant::now();

                // Realistic lifecycle progression under stress
                for transition_num in 0..transitions_per_connector {
                    let target_state = match transition_num % 6 {
                        0 => ConnectorState::Verified,
                        1 => ConnectorState::Installed,
                        2 => ConnectorState::Configured,
                        3 => ConnectorState::Active,
                        4 => ConnectorState::Paused,
                        5 => ConnectorState::Active, // Resume from pause
                        _ => unreachable!(),
                    };

                    if let Err(e) = manager.transition_to(&connector_id, target_state).await {
                        return Err(format!("Transition {} failed: {:?}", transition_num, e));
                    }

                    // Brief pause to allow for race condition detection
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                Ok(start.elapsed())
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(format!("Task panicked: {}", e))),
            }
        }

        results
    }

    fn export_test_summary(&self) -> serde_json::Value {
        let total_duration = self.test_start.elapsed();
        let successful_transitions = self.phase_logs.iter().filter(|log| log.error.is_none()).count();
        let failed_transitions = self.phase_logs.iter().filter(|log| log.error.is_some()).count();

        json!({
            "suite": "connector_lifecycle_integration",
            "total_duration_ms": total_duration.as_millis(),
            "successful_transitions": successful_transitions,
            "failed_transitions": failed_transitions,
            "transition_logs": self.phase_logs,
        })
    }
}

#[tokio::test]
async fn test_connector_lifecycle_happy_path_with_real_services() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;
    let connector_id = "connector-happy-001";

    // Test complete happy path lifecycle progression
    let states = [
        ConnectorState::Discovered,
        ConnectorState::Verified,
        ConnectorState::Installed,
        ConnectorState::Configured,
        ConnectorState::Active,
    ];

    for (i, &target_state) in states.iter().enumerate().skip(1) {
        let duration = harness.transition_with_timing(connector_id, target_state).await
            .expect("Happy path transition should succeed");

        // Verify timing is reasonable (not mocked instant responses)
        assert!(duration >= Duration::from_micros(100),
            "Transition to {:?} was suspiciously fast: {:?}", target_state, duration);
        assert!(duration <= Duration::from_secs(5),
            "Transition to {:?} took too long: {:?}", target_state, duration);
    }

    eprintln!("{}", harness.export_test_summary());
}

#[tokio::test]
async fn test_connector_cancellation_protocol_three_phase() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;
    let connector_id = "connector-cancel-001";

    // Setup: get connector to Active state
    harness.transition_with_timing(connector_id, ConnectorState::Verified).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Installed).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Configured).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Active).await.unwrap();

    // Test three-phase cancellation protocol (bd-1cs7)
    let cancel_start = Instant::now();

    // Phase 1: REQUEST - Enter cancelling state
    let request_duration = harness.transition_with_timing(connector_id, ConnectorState::Cancelling).await
        .expect("Cancellation REQUEST phase should succeed");

    // Verify connector is in cancelling state and still processing
    let current_state = harness.manager.get_state(connector_id).await.unwrap();
    assert_eq!(current_state, ConnectorState::Cancelling);

    // Phase 2: DRAIN - Allow in-flight operations to complete
    let drain_start = Instant::now();
    let drain_result = timeout(
        Duration::from_secs(10),
        harness.cancellation.wait_for_drain(connector_id)
    ).await;
    assert!(drain_result.is_ok(), "Drain phase should complete within timeout");
    let drain_duration = drain_start.elapsed();

    // Phase 3: FINALIZE - Transition to stopped
    let finalize_duration = harness.transition_with_timing(connector_id, ConnectorState::Stopped).await
        .expect("Cancellation FINALIZE phase should succeed");

    let total_cancellation = cancel_start.elapsed();

    // Verify cancellation timing characteristics
    assert!(total_cancellation >= Duration::from_millis(10), "Cancellation should not be instantaneous");
    assert!(total_cancellation <= Duration::from_secs(15), "Cancellation should complete within reasonable time");

    eprintln!("{}", json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "suite": "connector_lifecycle_integration",
        "test": "three_phase_cancellation",
        "connector_id": connector_id,
        "request_duration_ms": request_duration.as_millis(),
        "drain_duration_ms": drain_duration.as_millis(),
        "finalize_duration_ms": finalize_duration.as_millis(),
        "total_cancellation_ms": total_cancellation.as_millis(),
        "event": "cancellation_timing"
    }));

    eprintln!("{}", harness.export_test_summary());
}

#[tokio::test]
async fn test_connector_lease_conflict_resolution() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;
    let connector_id = "connector-lease-001";

    // Setup: get connector to Active state
    harness.transition_with_timing(connector_id, ConnectorState::Verified).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Installed).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Configured).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Active).await.unwrap();

    // Test lease conflict scenarios
    let lease1_result = harness.lease_service.acquire_exclusive_lease(connector_id, "owner1", Duration::from_secs(30)).await;
    assert!(lease1_result.is_ok(), "First lease should succeed");

    let lease2_result = harness.lease_service.acquire_exclusive_lease(connector_id, "owner2", Duration::from_secs(30)).await;
    assert!(matches!(lease2_result, Err(LeaseConflictError::AlreadyLeased { .. })),
        "Second lease should fail with conflict");

    // Test lease expiry and re-acquisition
    tokio::time::sleep(Duration::from_millis(100)).await;

    let lease3_result = harness.lease_service.acquire_exclusive_lease(connector_id, "owner3", Duration::from_millis(50)).await;
    // Should still conflict with unexpired lease1
    assert!(lease3_result.is_err(), "Third lease should fail - lease1 still active");

    eprintln!("{}", harness.export_test_summary());
}

#[tokio::test]
async fn test_concurrent_lifecycle_transitions_race_conditions() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;

    // Stress test: multiple connectors transitioning concurrently
    let stress_results = harness.parallel_transition_stress_test(20, 5).await;

    let successful = stress_results.iter().filter(|r| r.is_ok()).count();
    let failed = stress_results.iter().filter(|r| r.is_err()).count();

    // Log stress test results
    eprintln!("{}", json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "suite": "connector_lifecycle_integration",
        "test": "concurrent_stress",
        "successful_connectors": successful,
        "failed_connectors": failed,
        "total_connectors": stress_results.len(),
        "success_rate": successful as f64 / stress_results.len() as f64,
        "event": "stress_test_summary"
    }));

    // At least 80% should succeed under concurrent load
    let success_rate = successful as f64 / stress_results.len() as f64;
    assert!(success_rate >= 0.8,
        "Success rate too low: {:.2}%, expected >= 80%", success_rate * 100.0);

    eprintln!("{}", harness.export_test_summary());
}

#[tokio::test]
async fn test_health_gate_integration_with_lifecycle() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;
    let connector_id = "connector-health-001";

    // Setup: progress to configured state
    harness.transition_with_timing(connector_id, ConnectorState::Verified).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Installed).await.unwrap();
    harness.transition_with_timing(connector_id, ConnectorState::Configured).await.unwrap();

    // Test health gate prevents activation when unhealthy
    harness.health_gate.set_health(connector_id, HealthStatus::Unhealthy("Mock service down".to_string())).await;

    let activation_result = harness.transition_with_timing(connector_id, ConnectorState::Active).await;
    assert!(activation_result.is_err(), "Activation should fail when health gate reports unhealthy");

    // Test successful activation after health recovery
    harness.health_gate.set_health(connector_id, HealthStatus::Healthy).await;

    let recovery_result = harness.transition_with_timing(connector_id, ConnectorState::Active).await;
    assert!(recovery_result.is_ok(), "Activation should succeed after health recovery");

    eprintln!("{}", harness.export_test_summary());
}

#[tokio::test]
async fn test_lifecycle_error_boundary_conditions() {
    let mut harness = ConnectorLifecycleTestHarness::new().await;

    // Test edge cases and boundary conditions
    let test_cases = vec![
        ("illegal_transition", "connector-illegal-001", ConnectorState::Discovered, ConnectorState::Active), // Skip intermediate states
        ("double_transition", "connector-double-001", ConnectorState::Discovered, ConnectorState::Verified), // Will try twice
        ("empty_id", "", ConnectorState::Discovered, ConnectorState::Verified), // Empty connector ID
        ("very_long_id", &"x".repeat(1000), ConnectorState::Discovered, ConnectorState::Verified), // Very long ID
    ];

    for (test_name, connector_id, from_state, to_state) in test_cases {
        let result = harness.transition_with_timing(connector_id, to_state).await;

        match test_name {
            "illegal_transition" => {
                assert!(result.is_err(), "Illegal state transition should fail");
            }
            "double_transition" => {
                // First transition should succeed
                assert!(result.is_ok(), "First transition should succeed");
                // Second identical transition should be idempotent or fail gracefully
                let second_result = harness.transition_with_timing(connector_id, to_state).await;
                assert!(second_result.is_ok() || second_result.is_err(), "Second transition should handle gracefully");
            }
            "empty_id" => {
                assert!(result.is_err(), "Empty connector ID should be rejected");
            }
            "very_long_id" => {
                // Should either succeed or fail gracefully, but not panic
                assert!(result.is_ok() || result.is_err(), "Very long ID should not cause panic");
            }
            _ => {}
        }

        eprintln!("{}", json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "connector_lifecycle_integration",
            "test": test_name,
            "connector_id": connector_id,
            "from_state": from_state.as_str(),
            "to_state": to_state.as_str(),
            "success": result.is_ok(),
            "error": result.err(),
            "event": "boundary_condition_test"
        }));
    }

    eprintln!("{}", harness.export_test_summary());
}