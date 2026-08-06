// crates/balansir-control/src/state.rs

use balansir_common::plan::ReconciliationOperation;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Result of executing a reconciliation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    /// Unique identifier for this execution.
    pub execution_id: Uuid,
    /// Number of steps that succeeded.
    pub succeeded: usize,
    /// Number of steps that failed.
    pub failed: usize,
    /// Total number of steps, including NoOp.
    pub total: usize,
    /// The operations that were executed (the plan).
    pub operations: Vec<ReconciliationOperation>,
    /// Whether the whole plan applied cleanly (no failed steps).
    pub success: bool,
}

impl ExecutionReport {
    pub fn new(
        execution_id: Uuid,
        operations: Vec<ReconciliationOperation>,
        succeeded: usize,
        failed: usize,
    ) -> Self {
        let total = operations.len();
        Self {
            execution_id,
            succeeded,
            failed,
            total,
            success: failed == 0,
            operations,
        }
    }

    /// Build an empty success report (for no-op plans).
    pub fn noop(execution_id: Uuid) -> Self {
        Self {
            execution_id,
            succeeded: 0,
            failed: 0,
            total: 0,
            success: true,
            operations: Vec::new(),
        }
    }
}

/// The deliberative state machine of the coordinator.
///
/// Each variant is a step in the reconcile flow. Transitions are strictly
/// ordered; `Rollback` is reachable from `ExecutePlan` on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileState {
    Idle,
    ReadDesired,
    ReadActual,
    BuildPlan,
    ExecutePlan,
    CommitSnapshot,
    Done,
    Rollback,
    Failed,
}

impl ReconcileState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::ReadDesired => "read_desired",
            Self::ReadActual => "read_actual",
            Self::BuildPlan => "build_plan",
            Self::ExecutePlan => "execute_plan",
            Self::CommitSnapshot => "commit_snapshot",
            Self::Done => "done",
            Self::Rollback => "rollback",
            Self::Failed => "failed",
        }
    }
}
/// A single, tested transition within the reconcile FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileTransition {
    IdleToReadDesired,
    ReadDesiredToReadActual,
    ReadActualToBuildPlan,
    BuildPlanToExecutePlan,
    ExecutePlanToExecutePlan,
    ExecutePlanToCommitSnapshot,
    CommitSnapshotToDone,
    ExecutePlanToRollback,
    RollbackToFailed,
}

/// Verified by the coordinator; exported here so callers can observe progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileProgress {
    pub state: ReconcileState,
    pub step_index: usize,
}

impl Default for ReconcileProgress {
    fn default() -> Self {
        Self {
            state: ReconcileState::Idle,
            step_index: 0,
        }
    }
}
