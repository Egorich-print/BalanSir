// crates/balansir-control/src/executor.rs

use crate::error::{ControlError, ControlResult};
use crate::state::ExecutionReport;
use crate::traits::Executor;
use async_trait::async_trait;
use balansir_common::{ReconciliationOperation, ReconciliationPlan};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Executes plans in-memory. Records the number of executed steps and can be
/// configured to fail after a given number of steps.
///
/// Used in tests and as a simulator; real production execution happens through
/// the daemon's `Reconciler` (see the daemon crate's executor adapter).
#[derive(Debug, Default)]
pub struct MockExecutor {
    executed_steps: AtomicU64,
    fail_after: Option<usize>,
}

impl MockExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the `n`-th step (1-based) to exercise rollback paths.
    pub fn with_failure_after(mut self, n: usize) -> Self {
        self.fail_after = Some(n);
        self
    }

    pub fn executed_steps(&self) -> u64 {
        self.executed_steps.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Executor for MockExecutor {
    async fn execute(&self, plan: &ReconciliationPlan) -> ControlResult<ExecutionReport> {
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for op in &plan.operations {
            if matches!(op, ReconciliationOperation::NoOp) {
                continue;
            }
            self.executed_steps.fetch_add(1, Ordering::Relaxed);
            match self.fail_after {
                Some(n) if n <= self.executed_steps() as usize => {
                    failed += 1;
                }
                _ => succeeded += 1,
            }
        }

        let report =
            ExecutionReport::new(Uuid::new_v4(), plan.operations.clone(), succeeded, failed);

        if report.success {
            Ok(report)
        } else {
            Err(ControlError::Executor(
                "MockExecutor: injected failure".into(),
            ))
        }
    }
}

/// Convenience adapter that owns an `Arc<dyn Executor>` and exposes helper
/// accessors (keeps consumers decoupled from the concrete executor).
#[derive(Clone)]
pub struct ExecutorRef {
    inner: Arc<dyn Executor>,
}

impl ExecutorRef {
    pub fn new(inner: Arc<dyn Executor>) -> Self {
        Self { inner }
    }

    pub fn as_trait(&self) -> &dyn Executor {
        self.inner.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, DesiredRule, DriverId, ReconciliationOperation};

    fn plan_with(ops: Vec<ReconciliationOperation>) -> ReconciliationPlan {
        ReconciliationPlan::new(0, ops)
    }

    #[tokio::test]
    async fn mock_executor_reports_success() {
        let exec = MockExecutor::new();
        let plan = plan_with(vec![
            ReconciliationOperation::UpdatePolicy(DesiredRule {
                id: 1,
                action: Action::Allow,
                priority: 10,
                flow: None,
            }),
            ReconciliationOperation::RemovePolicy(2),
        ]);

        let report = exec.execute(&plan).await.unwrap();
        assert!(report.success);
        assert_eq!(report.succeeded, 2);
        assert_eq!(report.failed, 0);
        assert_eq!(exec.executed_steps(), 2);
    }

    #[tokio::test]
    async fn mock_executor_injects_failure() {
        let exec = MockExecutor::new().with_failure_after(2);
        let plan = plan_with(vec![
            ReconciliationOperation::CreateDriver(DriverId::WireGuard),
            ReconciliationOperation::UpdatePolicy(DesiredRule {
                id: 1,
                action: Action::Allow,
                priority: 10,
                flow: None,
            }),
            ReconciliationOperation::RemovePolicy(3),
        ]);

        let err = exec.execute(&plan).await.unwrap_err();
        assert!(matches!(err, ControlError::Executor(_)));
        // First step succeeded, second failed, third also marked failed
        // (MockExecutor keeps counting after the injected failure).
        assert_eq!(exec.executed_steps(), 3);
    }

    #[tokio::test]
    async fn mock_executor_skips_noop() {
        let exec = MockExecutor::new();
        let plan = plan_with(vec![ReconciliationOperation::NoOp]);
        let report = exec.execute(&plan).await.unwrap();
        assert!(report.success);
        assert_eq!(report.succeeded, 0);
        assert_eq!(exec.executed_steps(), 0);
    }
}
