// crates/balansir-control/src/events.rs

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable contract of control-plane lifecycle events.
///
/// These events are emitted as the coordinator transitions through its FSM.
/// Consumers (HTTP/SSE, CLI `watch`, Prometheus, OpenTelemetry, EventBus) rely
/// on this enum staying backward-compatible: additions are fine, renames/removals
/// are breaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlEvent {
    /// Reconciliation requested via a given reason.
    ReconciliationRequested(ReconcileReason),
    /// FSM entered a given state.
    StateEntered(String),
    /// Started reading desired state.
    DesiredReadStarted,
    /// Finished reading desired state with a revision estimate.
    DesiredReadFinished { revision: u64 },
    /// Started reading actual state.
    ActualReadStarted,
    /// Finished reading actual state with active rule count.
    ActualReadFinished { rule_count: usize },
    /// Started building the plan.
    PlanningStarted,
    /// Finished building the plan (pre-execution). Empty = no-op.
    PlanningFinished {
        generation: u64,
        operation_count: usize,
        empty: bool,
    },
    /// Started executing the plan.
    ExecutionStarted,
    /// A single step completed.
    StepCompleted { index: usize },
    /// A single step failed.
    StepFailed { index: usize, error: String },
    /// Snapshot committed.
    CommitCompleted,
    /// Reconcile finished successfully.
    Reconciled { plan_id: Uuid },
    /// Started rollback.
    RollbackStarted,
    /// Rollback finished.
    RollbackCompleted,
    /// Reconciliation failed.
    Failed { error: String },
}

impl ControlEvent {
    /// Short human-readable label for logging/metrics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReconciliationRequested(_) => "reconciliation_requested",
            Self::StateEntered(_) => "state_entered",
            Self::DesiredReadStarted => "desired_read_started",
            Self::DesiredReadFinished { .. } => "desired_read_finished",
            Self::ActualReadStarted => "actual_read_started",
            Self::ActualReadFinished { .. } => "actual_read_finished",
            Self::PlanningStarted => "planning_started",
            Self::PlanningFinished { .. } => "planning_finished",
            Self::ExecutionStarted => "execution_started",
            Self::StepCompleted { .. } => "step_completed",
            Self::StepFailed { .. } => "step_failed",
            Self::CommitCompleted => "commit_completed",
            Self::Reconciled { .. } => "reconciled",
            Self::RollbackStarted => "rollback_started",
            Self::RollbackCompleted => "rollback_completed",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Why a reconciliation was triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReconcileReason {
    Startup,
    ConfigReload,
    DriverFailure,
    HealthChanged,
    Manual,
    Scheduled,
    ApiRequest,
    Plugin(String),
}

impl ReconcileReason {
    pub fn label(&self) -> String {
        match self {
            Self::Plugin(name) => format!("plugin:{name}"),
            other => format!("{other:?}").to_lowercase(),
        }
    }
}
