//! Region-owned execution trees for connector lifecycle orchestration.
//!
//! Implements HRI-2 (region-owned lifecycle): every long-running control-plane
//! operation executes within an asupersync region that owns its execution tree.
//! Closing a region implies deterministic quiescence of all child tasks.
//!
//! # Region hierarchy
//!
//! ```text
//! root_region (connector lifecycle)
//! ├── health_gate_region (health-gate evaluation cycles)
//! ├── rollout_region (rollout state transitions)
//! └── fencing_region (fencing token operations)
//! ```
//!
//! # Event codes
//!
//! - `RGN-001`: Region opened
//! - `RGN-002`: Region close initiated
//! - `RGN-003`: Quiescence achieved
//! - `RGN-004`: Child task force-terminated
//! - `RGN-005`: Quiescence timeout

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Stable event codes for region ownership.
pub mod event_codes {
    pub const REGION_OPENED: &str = "RGN-001";
    pub const REGION_CLOSE_INITIATED: &str = "RGN-002";
    pub const QUIESCENCE_ACHIEVED: &str = "RGN-003";
    pub const CHILD_FORCE_TERMINATED: &str = "RGN-004";
    pub const QUIESCENCE_TIMEOUT: &str = "RGN-005";
}

static REGION_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_region_id() -> RegionId {
    RegionId(REGION_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Unique identifier for a region within the execution tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub u64);

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rgn-{}", self.0)
    }
}

/// The kind of region in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// Root region for the connector lifecycle.
    ConnectorLifecycle,
    /// Child region for health-gate evaluation cycles.
    HealthGate,
    /// Child region for rollout state transitions.
    Rollout,
    /// Child region for fencing token operations.
    Fencing,
}

impl RegionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConnectorLifecycle => "connector_lifecycle",
            Self::HealthGate => "health_gate",
            Self::Rollout => "rollout",
            Self::Fencing => "fencing",
        }
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// State of a child task within a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Draining,
    Completed,
    ForceTerminated,
}

/// A child task registered within a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionTask {
    pub task_id: String,
    pub state: TaskState,
    pub registered_at_ms: u64,
}

/// A structured event emitted during region lifecycle operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionEvent {
    pub event_code: String,
    pub region_id: RegionId,
    pub parent_region_id: Option<RegionId>,
    pub region_kind: RegionKind,
    pub child_task_count: usize,
    pub trace_id: String,
    pub detail: String,
}

/// Close result for a region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseResult {
    pub region_id: RegionId,
    pub quiescence_achieved: bool,
    pub tasks_drained: usize,
    pub tasks_force_terminated: usize,
    pub elapsed_ms: u64,
    pub events: Vec<RegionEvent>,
}

/// Errors from region operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum RegionError {
    #[serde(rename = "RGN_ALREADY_CLOSED")]
    AlreadyClosed { region_id: RegionId },
    #[serde(rename = "RGN_CHILD_STILL_OPEN")]
    ChildStillOpen {
        region_id: RegionId,
        child_region_id: RegionId,
    },
    #[serde(rename = "RGN_TASK_NOT_FOUND")]
    TaskNotFound {
        region_id: RegionId,
        task_id: String,
    },
}

impl fmt::Display for RegionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClosed { region_id } => {
                write!(
                    f,
                    "RGN_ALREADY_CLOSED: region {region_id} is already closed"
                )
            }
            Self::ChildStillOpen {
                region_id,
                child_region_id,
            } => write!(
                f,
                "RGN_CHILD_STILL_OPEN: region {region_id} has open child {child_region_id}"
            ),
            Self::TaskNotFound { region_id, task_id } => write!(
                f,
                "RGN_TASK_NOT_FOUND: task {task_id} not found in region {region_id}"
            ),
        }
    }
}

impl std::error::Error for RegionError {}

/// An execution region that owns child tasks and enforces quiescence on close.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: RegionId,
    pub kind: RegionKind,
    pub parent_id: Option<RegionId>,
    pub connector_id: String,
    pub trace_id: String,
    pub tasks: Vec<RegionTask>,
    pub child_region_ids: Vec<RegionId>,
    pub closed: bool,
    pub quiescence_budget_ms: u64,
}

impl Region {
    /// Create a new root region for a connector lifecycle.
    pub fn new_root(connector_id: &str, trace_id: &str, quiescence_budget_ms: u64) -> Self {
        Self {
            id: next_region_id(),
            kind: RegionKind::ConnectorLifecycle,
            parent_id: None,
            connector_id: connector_id.to_string(),
            trace_id: trace_id.to_string(),
            tasks: Vec::new(),
            child_region_ids: Vec::new(),
            closed: false,
            quiescence_budget_ms,
        }
    }

    /// Create a child region nested under this region.
    pub fn open_child(&mut self, kind: RegionKind, quiescence_budget_ms: u64) -> Region {
        let child = Region {
            id: next_region_id(),
            kind,
            parent_id: Some(self.id),
            connector_id: self.connector_id.clone(),
            trace_id: self.trace_id.clone(),
            tasks: Vec::new(),
            child_region_ids: Vec::new(),
            closed: false,
            quiescence_budget_ms,
        };
        self.child_region_ids.push(child.id);
        child
    }

    /// Register a task within this region.
    pub fn register_task(&mut self, task_id: &str) -> Result<(), RegionError> {
        if self.closed {
            return Err(RegionError::AlreadyClosed { region_id: self.id });
        }
        self.tasks.push(RegionTask {
            task_id: task_id.to_string(),
            state: TaskState::Running,
            registered_at_ms: 0,
        });
        Ok(())
    }

    /// Mark a task as completed.
    pub fn complete_task(&mut self, task_id: &str) -> Result<(), RegionError> {
        let task = self
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or_else(|| RegionError::TaskNotFound {
                region_id: self.id,
                task_id: task_id.to_string(),
            })?;
        task.state = TaskState::Completed;
        Ok(())
    }

    /// Open event for this region.
    pub fn open_event(&self) -> RegionEvent {
        RegionEvent {
            event_code: event_codes::REGION_OPENED.to_string(),
            region_id: self.id,
            parent_region_id: self.parent_id,
            region_kind: self.kind,
            child_task_count: self.tasks.len(),
            trace_id: self.trace_id.clone(),
            detail: format!(
                "region {} ({}) opened for connector {}",
                self.id, self.kind, self.connector_id
            ),
        }
    }

    /// Close this region, draining all tasks and enforcing quiescence.
    ///
    /// Tasks that are still running after the drain phase are force-terminated.
    /// Returns a `CloseResult` with the quiescence outcome.
    pub fn close(&mut self) -> Result<CloseResult, RegionError> {
        if self.closed {
            return Err(RegionError::AlreadyClosed { region_id: self.id });
        }

        let start = Instant::now();
        let mut events = Vec::new();

        // Capture counts before mutable iteration
        let total_task_count = self.tasks.len();
        let running_count = self
            .tasks
            .iter()
            .filter(|t| t.state == TaskState::Running)
            .count();

        // Emit close-initiated event
        events.push(RegionEvent {
            event_code: event_codes::REGION_CLOSE_INITIATED.to_string(),
            region_id: self.id,
            parent_region_id: self.parent_id,
            region_kind: self.kind,
            child_task_count: total_task_count,
            trace_id: self.trace_id.clone(),
            detail: format!(
                "region {} close initiated, {} tasks to drain",
                self.id, running_count
            ),
        });

        // Drain phase: signal all running tasks to drain
        for task in &mut self.tasks {
            if task.state == TaskState::Running {
                task.state = TaskState::Draining;
            }
        }

        // Simulate drain completion for tasks that can complete within budget.
        // In a real async runtime, this would await task completion with a timeout.
        let mut tasks_drained = 0;
        let mut tasks_force_terminated = 0;
        let mut force_terminated_ids: Vec<String> = Vec::new();

        for task in &mut self.tasks {
            match task.state {
                TaskState::Draining => {
                    let elapsed = start.elapsed();
                    if elapsed < Duration::from_millis(self.quiescence_budget_ms) {
                        task.state = TaskState::Completed;
                        tasks_drained += 1;
                    } else {
                        task.state = TaskState::ForceTerminated;
                        tasks_force_terminated += 1;
                        force_terminated_ids.push(task.task_id.clone());
                    }
                }
                TaskState::Completed => {
                    tasks_drained += 1;
                }
                _ => {}
            }
        }

        // Emit force-termination events after iteration
        for terminated_id in &force_terminated_ids {
            events.push(RegionEvent {
                event_code: event_codes::CHILD_FORCE_TERMINATED.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                detail: format!(
                    "task {} force-terminated after budget exceeded",
                    terminated_id
                ),
            });
        }

        let elapsed = start.elapsed();
        let quiescence_achieved = tasks_force_terminated == 0;

        // Emit quiescence event
        if quiescence_achieved {
            events.push(RegionEvent {
                event_code: event_codes::QUIESCENCE_ACHIEVED.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                detail: format!(
                    "quiescence achieved for region {} in {}ms",
                    self.id,
                    elapsed.as_millis()
                ),
            });
        } else {
            events.push(RegionEvent {
                event_code: event_codes::QUIESCENCE_TIMEOUT.to_string(),
                region_id: self.id,
                parent_region_id: self.parent_id,
                region_kind: self.kind,
                child_task_count: total_task_count,
                trace_id: self.trace_id.clone(),
                detail: format!(
                    "quiescence timeout for region {}: {} tasks force-terminated",
                    self.id, tasks_force_terminated
                ),
            });
        }

        self.closed = true;

        Ok(CloseResult {
            region_id: self.id,
            quiescence_achieved,
            tasks_drained,
            tasks_force_terminated,
            elapsed_ms: elapsed.as_millis() as u64,
            events,
        })
    }

    /// Returns true if all tasks are in a terminal state (completed or force-terminated).
    pub fn is_quiescent(&self) -> bool {
        self.tasks
            .iter()
            .all(|t| matches!(t.state, TaskState::Completed | TaskState::ForceTerminated))
    }

    /// Returns the number of active (non-terminal) tasks.
    pub fn active_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Running | TaskState::Draining))
            .count()
    }
}

/// Build a complete region hierarchy for a connector lifecycle.
///
/// Returns (root, health_gate, rollout, fencing) regions with proper parent linkage.
pub fn build_lifecycle_hierarchy(
    connector_id: &str,
    trace_id: &str,
    root_budget_ms: u64,
    child_budget_ms: u64,
) -> (Region, Region, Region, Region) {
    let mut root = Region::new_root(connector_id, trace_id, root_budget_ms);
    let health_gate = root.open_child(RegionKind::HealthGate, child_budget_ms);
    let rollout = root.open_child(RegionKind::Rollout, child_budget_ms);
    let fencing = root.open_child(RegionKind::Fencing, child_budget_ms);
    (root, health_gate, rollout, fencing)
}

/// Generate a quiescence trace as a list of JSONL-formatted region events.
pub fn generate_quiescence_trace(
    regions: &[&Region],
    close_results: &[&CloseResult],
) -> Vec<serde_json::Value> {
    let mut trace: Vec<serde_json::Value> = Vec::new();

    // Open events
    for region in regions {
        trace.push(serde_json::to_value(region.open_event()).unwrap_or_default());
    }

    // Close events
    for result in close_results {
        for event in &result.events {
            trace.push(serde_json::to_value(event).unwrap_or_default());
        }
    }

    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_region_creation() {
        let root = Region::new_root("test-conn", "trace-001", 5000);
        assert_eq!(root.kind, RegionKind::ConnectorLifecycle);
        assert!(root.parent_id.is_none());
        assert!(!root.closed);
        assert_eq!(root.connector_id, "test-conn");
    }

    #[test]
    fn child_region_linkage() {
        let mut root = Region::new_root("test-conn", "trace-001", 5000);
        let child = root.open_child(RegionKind::HealthGate, 2000);
        assert_eq!(child.parent_id, Some(root.id));
        assert!(root.child_region_ids.contains(&child.id));
    }

    #[test]
    fn task_registration_and_completion() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        region.register_task("task-1").unwrap();
        region.register_task("task-2").unwrap();
        assert_eq!(region.active_task_count(), 2);

        region.complete_task("task-1").unwrap();
        assert_eq!(region.active_task_count(), 1);

        region.complete_task("task-2").unwrap();
        assert!(region.is_quiescent());
    }

    #[test]
    fn close_drains_all_tasks() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        region.register_task("task-1").unwrap();
        region.register_task("task-2").unwrap();

        let result = region.close().unwrap();
        assert!(result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 2);
        assert_eq!(result.tasks_force_terminated, 0);
        assert!(region.closed);
    }

    #[test]
    fn close_emits_correct_events() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        region.register_task("task-1").unwrap();

        let result = region.close().unwrap();
        let event_codes: Vec<&str> = result
            .events
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(event_codes.contains(&"RGN-002")); // close initiated
        assert!(event_codes.contains(&"RGN-003")); // quiescence achieved
    }

    #[test]
    fn already_closed_region_rejects_operations() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        region.close().unwrap();

        let err = region.close().unwrap_err();
        assert!(matches!(err, RegionError::AlreadyClosed { .. }));

        let err = region.register_task("task-1").unwrap_err();
        assert!(matches!(err, RegionError::AlreadyClosed { .. }));
    }

    #[test]
    fn task_not_found_error() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        let err = region.complete_task("nonexistent").unwrap_err();
        assert!(matches!(err, RegionError::TaskNotFound { .. }));
    }

    #[test]
    fn hierarchy_builder() {
        let (root, health, rollout, fencing) =
            build_lifecycle_hierarchy("test-conn", "trace-001", 5000, 2000);
        assert_eq!(root.child_region_ids.len(), 3);
        assert_eq!(health.parent_id, Some(root.id));
        assert_eq!(rollout.parent_id, Some(root.id));
        assert_eq!(fencing.parent_id, Some(root.id));
    }

    #[test]
    fn quiescence_trace_generation() {
        let mut root = Region::new_root("test-conn", "trace-001", 5000);
        root.register_task("task-1").unwrap();
        let result = root.close().unwrap();

        let trace = generate_quiescence_trace(&[&root], &[&result]);
        assert!(!trace.is_empty());
    }

    #[test]
    fn completed_tasks_counted_as_drained() {
        let mut region = Region::new_root("test-conn", "trace-001", 5000);
        region.register_task("task-1").unwrap();
        region.complete_task("task-1").unwrap();

        let result = region.close().unwrap();
        assert!(result.quiescence_achieved);
        assert_eq!(result.tasks_drained, 1);
    }

    #[test]
    fn region_event_codes_are_stable() {
        assert_eq!(event_codes::REGION_OPENED, "RGN-001");
        assert_eq!(event_codes::REGION_CLOSE_INITIATED, "RGN-002");
        assert_eq!(event_codes::QUIESCENCE_ACHIEVED, "RGN-003");
        assert_eq!(event_codes::CHILD_FORCE_TERMINATED, "RGN-004");
        assert_eq!(event_codes::QUIESCENCE_TIMEOUT, "RGN-005");
    }

    #[test]
    fn serde_roundtrip() {
        let region = Region::new_root("test-conn", "trace-001", 5000);
        let json = serde_json::to_string(&region).unwrap();
        let parsed: Region = serde_json::from_str(&json).unwrap();
        assert_eq!(region.kind, parsed.kind);
        assert_eq!(region.connector_id, parsed.connector_id);
    }
}
