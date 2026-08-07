pub mod bootstrap;
pub use balansir_common::diff;
pub use balansir_common::plan;
pub use balansir_common::{ActualRule, ActualState};

use balansir_common::plan::{ReconciliationOperation, ReconciliationPlan};
use balansir_common::{
    ActionRequest, ActionResult, DesiredRule, DesiredState, Snapshot, StateDiff,
};
use balansir_control::coordinator::{Coordinator, Rollback};
use balansir_control::planner::BasicPlanner;
use balansir_control::snapshot_store::MemorySnapshotStore;
use balansir_control::traits::{DesiredProvider, EventSink, Executor, StateProvider};
use balansir_control::{
    ControlEvent, ControlResult, CoordinatorConfig, ExecutionReport, ReconcileReason,
};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

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
    runner: Arc<DaemonRunner>,
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

        let runner = Arc::new(DaemonRunner {
            executor,
            actual: actual.clone(),
        });

        let coordinator = Arc::new(Coordinator::new(
            CoordinatorConfig::new(
                Arc::new(DaemonDesiredProvider {
                    desired: desired.clone(),
                }),
                runner.clone(),
                Arc::new(BasicPlanner),
                runner.clone(),
                Arc::new(MemorySnapshotStore::new()),
            )
            .with_rollback(runner.clone())
            .with_event_sink(Arc::new(TracingEventSink)),
        ));

        Self {
            desired_state: desired,
            actual_state: actual,
            config,
            coordinator,
            runner,
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

        let executor = Arc::new(DummyExecutorAdapter::new());
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
        let plan = StateDiff::build(&desired, &actual, gen);
        drop(desired);
        drop(actual);
        plan
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

/// Reads the mutable desired-state handle for the coordinator.
struct DaemonDesiredProvider {
    desired: Arc<tokio::sync::Mutex<DesiredState>>,
}

#[async_trait::async_trait]
impl DesiredProvider for DaemonDesiredProvider {
    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.desired.lock().await.clone())
    }
}

/// Provides the actual state, executes plans, and restores snapshots on
/// rollback. Wraps the daemon's executor adapter and the actual-state mutex it
/// mutates, so execute/rollback share one source of truth.
struct DaemonRunner {
    executor: Arc<dyn ExecutorAdapter>,
    actual: Arc<tokio::sync::Mutex<ActualState>>,
}

#[async_trait::async_trait]
impl StateProvider for DaemonRunner {
    async fn actual(&self) -> ControlResult<ActualState> {
        Ok(self.actual.lock().await.clone())
    }
}

#[async_trait::async_trait]
impl Executor for DaemonRunner {
    async fn execute(&self, plan: &ReconciliationPlan) -> ControlResult<ExecutionReport> {
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for op in &plan.operations {
            match op {
                ReconciliationOperation::UpdatePolicy(rule) => {
                    let request = ActionRequest {
                        action: rule.action,
                        src_ip: [0; 4],
                        dst_ip: [0; 4],
                        src_port: 0,
                        dst_port: 0,
                        protocol: 0,
                        interface: 0,
                        trace: balansir_common::DecisionTrace {
                            policy_id: 0,
                            steps: smallvec::SmallVec::new(),
                            action: rule.action,
                            execution_time_us: 0,
                            correlation_id: 0,
                        },
                    };

                    let mut ok = true;
                    match self.executor.execute(&request).await {
                        ActionResult::Applied { rule_id, .. } => {
                            let mut actual = self.actual.lock().await;
                            actual.active_rules.retain(|r| r.id != rule.id);
                            actual.active_rules.push(ActualRule {
                                id: rule.id,
                                action: rule.action,
                                rule_id,
                            });
                            info!(rule_id = rule.id, "Rule applied");
                        }
                        ActionResult::AlreadyApplied => {}
                        ActionResult::Failed { message, .. } => {
                            warn!(rule_id = rule.id, message = ?message, "Rule failed");
                            ok = false;
                        }
                        _ => {}
                    }
                    if ok {
                        succeeded += 1;
                    } else {
                        failed += 1;
                    }
                }
                ReconciliationOperation::RemovePolicy(rule_id) => {
                    info!(rule_id, "Removing rule");
                    let mut actual = self.actual.lock().await;
                    actual.active_rules.retain(|r| r.id != *rule_id);
                    succeeded += 1;
                }
                ReconciliationOperation::NoOp => {}
                _ => {}
            }
        }

        Ok(ExecutionReport::new(
            Uuid::new_v4(),
            plan.operations.clone(),
            succeeded,
            failed,
        ))
    }
}

#[async_trait::async_trait]
impl Rollback for DaemonRunner {
    async fn rollback(&self, snapshot: &Snapshot) -> ControlResult<()> {
        warn!("Restoring actual state from pre-execution snapshot");
        let mut actual = self.actual.lock().await;
        *actual = snapshot.actual.clone();
        Ok(())
    }
}

/// Logs control-plane events at trace level.
#[derive(Debug, Clone, Copy, Default)]
struct TracingEventSink;

#[async_trait::async_trait]
impl EventSink for TracingEventSink {
    async fn emit(&self, event: &ControlEvent) -> ControlResult<()> {
        tracing::trace!(event = event.name(), "control event");
        Ok(())
    }
}

/// Dummy executor for testing.
struct DummyExecutorAdapter {
    count: std::sync::atomic::AtomicU32,
}

impl DummyExecutorAdapter {
    fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

#[async_trait::async_trait]
impl ExecutorAdapter for DummyExecutorAdapter {
    async fn execute(&self, _request: &ActionRequest) -> ActionResult {
        let id = self
            .count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ActionResult::Applied {
            execution_time_us: 100,
            rule_id: Some(id + 1),
        }
    }

    async fn rule_count(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        // Verify initial state is empty
        let actual = reconciler.get_actual().await;
        assert!(actual.active_rules.is_empty());

        // Apply desired state
        reconciler.set_desired(desired).await;
        reconciler.reconcile_atomic().await.unwrap();

        // Verify both rules are applied
        let actual = reconciler.get_actual().await;
        assert_eq!(actual.active_rules.len(), 2);

        // Verify generation incremented
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

        // Add rule
        reconciler
            .add_rule(DesiredRule {
                id: 2,
                action: Action::Allow,
                priority: 50,
            })
            .await;
        let plan = reconciler.build_plan().await;
        assert_eq!(plan.operations.len(), 1);

        // Remove rule
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

        // Full reconcile cycle
        reconciler.reconcile_atomic().await.unwrap();

        // Verify consistency
        let plan = reconciler.build_plan().await;
        assert!(plan.is_empty());
    }
}
