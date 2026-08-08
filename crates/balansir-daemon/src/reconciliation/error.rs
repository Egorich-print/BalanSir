//! Typed errors for the daemon's reconciliation layer.
//!
//! Replaces the ad-hoc `Result<_, String>` in the bootstrap/reconciler paths
//! with a structured error type so callers can match on failure classes instead
//! of string-prefix matching.

use thiserror::Error;

/// Errors produced while bootstrapping and reconciling the desired state.
#[derive(Debug, Error)]
pub enum ReconciliationError {
    #[error("failed to load default reconciliation config: {0}")]
    Config(String),

    #[error("failed to read persisted desired state: {0}")]
    StateLoad(String),

    #[error("failed to persist desired state: {0}")]
    StateSave(String),

    #[error("failed to deserialize desired state: {0}")]
    Deserialize(String),

    #[error("failed to serialize desired state: {0}")]
    Serialize(String),

    #[error("reconciliation cycle failed: {0}")]
    Reconcile(String),

    #[error("executor failed to apply a rule: {0}")]
    ApplyRule(String),
}

/// Convenience alias for reconciliation results.
pub type ReconciliationResult<T> = Result<T, ReconciliationError>;
