// crates/balansir-control/src/error.rs

/// Errors produced by the control plane.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("desired state provider failed: {0}")]
    DesiredProvider(String),

    #[error("state provider failed: {0}")]
    StateProvider(String),

    #[error("planner failed: {0}")]
    Planner(String),

    #[error("executor failed: {0}")]
    Executor(String),

    #[error("snapshot store failed: {0}")]
    SnapshotStore(String),

    #[error("reconciliation already in progress")]
    ReconcileInProgress,

    #[error("rollback failed: {0}")]
    Rollback(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("control plane is in {0} state, cannot {1}")]
    InvalidState(String, String),
}

pub type ControlResult<T> = Result<T, ControlError>;
