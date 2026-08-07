//! The reconcile loop and its adapters to the coordinator.

use crate::reconciliation::adapters::{
    DaemonActualStore, DaemonDesiredProvider, DaemonExecutorAdapter, DaemonRollback,
};
use crate::reconciliation::sinks::TracingEventSink;
use balansir_common::plan::ReconciliationPlan;
use balansir_common::{
    ActionRequest, ActionResult, ActualState, DesiredRule, DesiredState, StateDiff,
};
use balansir_control::planner::BasicPlanner;
use balansir_control::snapshot_store::MemorySnapshotStore;
use balansir_control::traits::Executor;
use balansir_control::{Coordinator, CoordinatorConfig, ReconcileReason};
use std::sync::Arc;
use tracing::{error, info};

/// Reconciliation loop for maintaining desired state.
///
/// The actual converge work is delegated to the `balansir-control` coordinator,
/// which drives an FSM: read desired -> read actual -> build plan -> execute ->
/// commit/rollback. This type adapts the daemon's state and executor to the
/// coordinator's provider abstractions and keeps the daemon-facing API stable.
pub struct Reconciler {
    desired_state: Arc<tokio::sync::Mutex<DesiredState>>,
    actual_state: Arc<tokio::sync::Mutex<ActualState>>,
    config: ReconcilerConfig,
    coordinator: Arc<Coordinator>,
    runner: Arc<DaemonExecutorAdapter>,
}

/// Configuration for the reconciliation loop.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    pub check_interval_secs: u64,
    pub max_retries: u32,
    pub retry_delay_secs: u64,
    /// Timeout for watchdog (seconds). Retained for compatibility; the
    /// coordinator owns rollback handling today.
    pub watchdog_timeout_secs: u64,
    /// Enable atomic rollback. When false, decode failures are still rolled back
    /// by the coordinator but no extra commit semantics are applied.
    pub atomic_rollback: bool,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            max_retries: 3,
            retry_delay_secs: 5,
            watchdog_timeout_secs: 30,
            atomic_rollback: true,
        }
    }
}

/// Adapter trait for executor operations.
#[async_trait::async_trait]
pub trait ExecutorAdapter: Send + Sync {
    async fn execute(&self, request: &ActionRequest) -> ActionResult;
    async fn rule_count(&self) -> u32;
    /// Revert a previously applied rule at the kernel/mechanism level.
    async fn remove_rule(&self, rule_id: u32) -> ActionResult;
}

impl Reconciler {
    /// Create a new reconciler.
    pub fn new(
        desired_state: DesiredState,
        executor: Arc<dyn ExecutorAdapter>,
        config: ReconcilerConfig,
    ) -> Self {
        let desired = Arc::new(tokio::sync::Mutex::new(desired_state));
        let actual = Arc::new(tokio::sync::Mutex::new(ActualState::default()));

        let actual_store = Arc::new(DaemonActualStore {
            actual: actual.clone(),
        });
        let rollback = Arc::new(DaemonRollback {
            executor: executor.clone(),
            actual: actual.clone(),
        });
        let executor = Arc::new(DaemonExecutorAdapter {
            executor,
            actual: actual.clone(),
        });

        let coordinator = Arc::new(Coordinator::new(
            CoordinatorConfig::new(
                Arc::new(DaemonDesiredProvider {
                    desired: desired.clone(),
                }),
                actual_store,
                Arc::new(BasicPlanner),
                executor.clone(),
                Arc::new(MemorySnapshotStore::new()),
            )
            .with_rollback(rollback)
            .with_event_sink(Arc::new(TracingEventSink)),
        ));

        Self {
            desired_state: desired,
            actual_state: actual,
            config,
            coordinator,
            runner: executor,
        }
    }

    /// Create reconciler from state store.
    pub async fn from_state_store(
        state_store: &impl balansir_common::state::StateStore,
    ) -> Result<Self, String> {
        let desired = match state_store.load("desired_state").await {
            Ok(Some(data)) => {
                postcard::from_bytes(&data).map_err(|e| format!("Deserialize: {}", e))?
            }
            Ok(None) => DesiredState::default(),
            Err(e) => return Err(format!("Load: {}", e)),
        };

        let executor = Arc::new(crate::reconciliation::dummy::DummyExecutorAdapter::new());
        Ok(Self::new(desired, executor, ReconcilerConfig::default()))
    }

    /// Save desired state to store.
    pub async fn save_to_store(
        &self,
        state_store: &impl balansir_common::state::StateStore,
    ) -> Result<(), String> {
        let state = self.desired_state.lock().await;
        let data = postcard::to_allocvec(&*state).map_err(|e| format!("Serialize: {}", e))?;
        state_store
            .save("desired_state", &data)
            .await
            .map_err(|e| format!("Save: {}", e))?;
        Ok(())
    }

    /// Update desired state.
    pub async fn set_desired(&self, state: DesiredState) {
        *self.desired_state.lock().await = state;
    }

    /// Get current desired state.
    pub async fn get_desired(&self) -> DesiredState {
        self.desired_state.lock().await.clone()
    }

    /// Add a desired rule.
    pub async fn add_rule(&self, rule: DesiredRule) {
        self.desired_state.lock().await.rules.push(rule);
    }

    /// Remove a desired rule.
    pub async fn remove_rule(&self, id: u32) {
        self.desired_state.lock().await.rules.retain(|r| r.id != id);
    }

    /// Get current actual state (for testing and monitoring).
    pub async fn get_actual(&self) -> ActualState {
        self.actual_state.lock().await.clone()
    }

    /// Get current generation (for testing and monitoring).
    pub fn generation(&self) -> u64 {
        self.coordinator.generation()
    }

    /// Apply plan (delegates to the daemon's plan runner).
    pub async fn apply_plan(&self, plan: ReconciliationPlan) -> Result<(), String> {
        let report = self
            .runner
            .execute(&plan)
            .await
            .map_err(|e| e.to_string())?;
        if report.success {
            Ok(())
        } else {
            Err(format!(
                "{} of {} steps failed",
                report.failed, report.total
            ))
        }
    }

    /// Build a reconciliation plan without applying it (for dry-run and testing).
    pub async fn build_plan(&self) -> ReconciliationPlan {
        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let gen = self.generation();
        StateDiff::build(&desired, &actual, gen)
    }

    /// Trigger a single reconciliation cycle.
    pub async fn reconcile(&self) -> Result<(), String> {
        self.coordinator
            .reconcile(ReconcileReason::Scheduled)
            .await
            .map_err(|e| e.to_string())
    }

    /// Trigger an atomic reconciliation (rollback handled by the coordinator).
    pub async fn reconcile_atomic(&self) -> Result<(), String> {
        self.reconcile().await
    }

    /// Run reconciliation loop forever.
    pub async fn run_loop(&self) {
        info!(
            interval = self.config.check_interval_secs,
            "Reconciliation loop started"
        );

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.check_interval_secs,
            ))
            .await;

            if let Err(e) = self.reconcile_atomic().await {
                error!("Reconciliation error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    self.config.retry_delay_secs,
                ))
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciliation::dummy::DummyExecutorAdapter;
    use balansir_common::Action;

    #[tokio::test]
    async fn test_reconciler_basic() {
        let desired = DesiredState {
            rules: vec![
                DesiredRule {
                    id: 1,
                    action: Action::Block,
                    priority: 100,
                },
                DesiredRule {
                    id: 2,
                    action: Action::Allow,
                    priority: 50,
                },
            ],
            drivers: Vec::new(),
        };

        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired.clone(), executor, ReconcilerConfig::default());

        let actual = reconciler.get_actual().await;
        assert!(actual.active_rules.is_empty());

        reconciler.set_desired(desired).await;
        reconciler.reconcile_atomic().await.unwrap();

        let actual = reconciler.get_actual().await;
        assert_eq!(actual.active_rules.len(), 2);

        let gen = reconciler.generation();
        assert_eq!(gen, 2);
    }

    #[tokio::test]
    async fn test_reconciler_add_remove() {
        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 1,
                action: Action::Block,
                priority: 100,
            }],
            drivers: Vec::new(),
        };

        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        reconciler.reconcile_atomic().await.unwrap();

        reconciler
            .add_rule(DesiredRule {
                id: 2,
                action: Action::Allow,
                priority: 50,
            })
            .await;
        let plan = reconciler.build_plan().await;
        assert_eq!(plan.operations.len(), 1);

        reconciler.remove_rule(1).await;
        let plan = reconciler.build_plan().await;
        assert!(!plan.is_empty());
    }

    #[tokio::test]
    async fn test_reconciler_full_cycle() {
        let desired = DesiredState::default();
        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        reconciler
            .add_rule(DesiredRule {
                id: 1,
                action: Action::Block,
                priority: 100,
            })
            .await;
        reconciler
            .add_rule(DesiredRule {
                id: 2,
                action: Action::Allow,
                priority: 50,
            })
            .await;

        reconciler.reconcile_atomic().await.unwrap();

        let plan = reconciler.build_plan().await;
        assert!(plan.is_empty());
    }

    #[tokio::test]
    async fn test_bootstrap_from_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = balansir_common::state::FileStateStore::new(
            &balansir_common::state::StateStoreConfig {
                base_path: dir.path().join("state"),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let reconciler = Reconciler::from_state_store(&store).await.unwrap();
        assert!(reconciler.get_desired().await.rules.is_empty());
    }
}
