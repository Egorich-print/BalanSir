pub mod bootstrap;
pub mod diff;
pub mod plan;

use crate::reconciliation::diff::StateDiff;
use crate::reconciliation::plan::{ReconciliationOperation, ReconciliationPlan};
use balansir_common::{Action, ActionRequest, ActionResult, DesiredRule, DesiredState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Reconciliation loop for maintaining desired state
pub struct Reconciler {
    desired_state: Arc<tokio::sync::Mutex<DesiredState>>,
    actual_state: Arc<tokio::sync::Mutex<ActualState>>,
    executor: Arc<dyn ExecutorAdapter>,
    config: ReconcilerConfig,
    generation: AtomicU64,
}

/// Actual state of the system
#[derive(Debug, Clone, Default)]
pub struct ActualState {
    pub active_rules: Vec<ActualRule>,
}

/// A single active rule in the system
#[derive(Debug, Clone)]
pub struct ActualRule {
    pub id: u32,
    pub action: Action,
    pub rule_id: Option<u32>,
}

/// Snapshot of actual state for rollback
#[derive(Debug, Clone)]
struct StateSnapshot {
    actual: ActualState,
    timestamp: std::time::Instant,
}

/// Configuration for reconciliation loop
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    pub check_interval_secs: u64,
    pub max_retries: u32,
    pub retry_delay_secs: u64,
    /// Timeout for watchdog (seconds)
    pub watchdog_timeout_secs: u64,
    /// Enable atomic rollback
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

/// Adapter trait for executor operations
#[async_trait::async_trait]
pub trait ExecutorAdapter: Send + Sync {
    async fn execute(&self, request: &ActionRequest) -> ActionResult;
    async fn rule_count(&self) -> u32;
}

impl Reconciler {
    /// Create a new reconciler
    pub fn new(
        desired_state: DesiredState,
        executor: Arc<dyn ExecutorAdapter>,
        config: ReconcilerConfig,
    ) -> Self {
        Self {
            desired_state: Arc::new(tokio::sync::Mutex::new(desired_state)),
            actual_state: Arc::new(tokio::sync::Mutex::new(ActualState::default())),
            executor,
            config,
            generation: AtomicU64::new(1),
        }
    }

    /// Create reconciler from state store
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

    /// Save desired state to store
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

    /// Update desired state
    pub async fn set_desired(&self, state: DesiredState) {
        *self.desired_state.lock().await = state;
    }

    /// Get current desired state
    pub async fn get_desired(&self) -> DesiredState {
        self.desired_state.lock().await.clone()
    }

    /// Add a desired rule
    pub async fn add_rule(&self, rule: DesiredRule) {
        self.desired_state.lock().await.rules.push(rule);
    }

    /// Remove a desired rule
    pub async fn remove_rule(&self, id: u32) {
        self.desired_state.lock().await.rules.retain(|r| r.id != id);
    }

    /// Get current actual state (for testing and monitoring)
    pub async fn get_actual(&self) -> ActualState {
        self.actual_state.lock().await.clone()
    }

    /// Get current generation (for testing and monitoring)
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Apply plan
    async fn apply_plan(&self, plan: ReconciliationPlan) -> Result<(), String> {
        for op in plan.operations {
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

                    match self.executor.execute(&request).await {
                        ActionResult::Applied { rule_id, .. } => {
                            let mut actual = self.actual_state.lock().await;
                            actual.active_rules.retain(|r| r.id != rule.id);
                            actual.active_rules.push(ActualRule {
                                id: rule.id,
                                action: rule.action,
                                rule_id,
                            });
                            info!(rule_id = rule.id, "Rule applied");
                        }
                        ActionResult::AlreadyApplied => {}
                        ActionResult::Failed { error: _, message } => {
                            return Err(format!("Rule {} failed: {:?}", rule.id, message));
                        }
                        _ => {}
                    }
                }
                ReconciliationOperation::RemovePolicy(rule_id) => {
                    info!(rule_id, "Removing rule");
                    let mut actual = self.actual_state.lock().await;
                    actual.active_rules.retain(|r| r.id != rule_id);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Build a reconciliation plan without applying it (for dry-run and testing)
    pub async fn build_plan(&self) -> ReconciliationPlan {
        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let gen = self.generation.load(Ordering::Relaxed);
        let plan = StateDiff::build(&desired, &actual, gen);
        drop(desired);
        drop(actual);
        plan
    }

    /// Single reconciliation cycle
    pub async fn reconcile(&self) -> Result<(), String> {
        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let gen = self.generation.load(Ordering::Relaxed);
        let plan = StateDiff::build(&desired, &actual, gen);
        drop(desired);
        drop(actual);

        if plan.is_empty() {
            info!("State is consistent, no drift");
            return Ok(());
        }

        info!(
            op_count = plan.operations.len(),
            "Plan generated, reconciling"
        );

        let res = self.apply_plan(plan).await;
        if res.is_ok() {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    /// Atomic reconciliation with watchdog rollback
    ///
    /// Transactional flow:
    /// 1. Snapshot current state
    /// 2. Generate and apply plan
    /// 3. Health check with timeout
    /// 4. OK → commit snapshot
    /// 5. FAIL → rollback(snapshot)
    pub async fn reconcile_atomic(&self) -> Result<(), String> {
        if !self.config.atomic_rollback {
            return self.reconcile().await;
        }

        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let gen = self.generation.load(Ordering::Relaxed);
        let plan = StateDiff::build(&desired, &actual, gen);
        drop(desired);
        drop(actual);

        if plan.is_empty() {
            info!("State is consistent, no drift");
            return Ok(());
        }

        info!(
            op_count = plan.operations.len(),
            "Drift detected, starting atomic reconcile"
        );

        // 1. Snapshot current state
        let snapshot = {
            let actual = self.actual_state.lock().await;
            StateSnapshot {
                actual: actual.clone(),
                timestamp: std::time::Instant::now(),
            }
        };

        // 2. Apply plan
        if let Err(e) = self.apply_plan(plan).await {
            warn!("Failed to apply plan, rolling back: {}", e);
            self.rollback_to_snapshot(snapshot).await;
            return Err(e);
        }

        // 3. Health check with timeout
        let health_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.watchdog_timeout_secs),
            self.health_check_all(),
        )
        .await;

        match health_result {
            Ok(true) => {
                info!("Atomic reconcile successful, changes committed");
                self.generation.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(false) => {
                warn!("Health check failed, rolling back");
                self.rollback_to_snapshot(snapshot).await;
                Err("Health check failed after applying changes".into())
            }
            Err(_) => {
                warn!("Health check timed out, rolling back");
                self.rollback_to_snapshot(snapshot).await;
                Err("Health check timed out".into())
            }
        }
    }

    /// Rollback to a previous state snapshot
    async fn rollback_to_snapshot(&self, snapshot: StateSnapshot) {
        warn!("Rolling back to snapshot from {:?}", snapshot.timestamp);

        let mut actual = self.actual_state.lock().await;
        *actual = snapshot.actual;
    }

    /// Health check all components
    async fn health_check_all(&self) -> bool {
        // Check if executor is responding
        let rule_count = self.executor.rule_count().await;

        // Basic connectivity check
        if rule_count == 0 && !self.desired_state.lock().await.rules.is_empty() {
            return false;
        }

        // TODO: Add more health checks
        // - DNS resolution
        // - Interface status
        // - Process status

        true
    }

    /// Run reconciliation loop forever
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

/// Dummy executor for testing
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
