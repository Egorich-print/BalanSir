use balansir_common::{Action, ActionRequest, ActionResult, DesiredState, DesiredRule};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Reconciliation loop for maintaining desired state
pub struct Reconciler {
    desired_state: Arc<tokio::sync::Mutex<DesiredState>>,
    actual_state: Arc<tokio::sync::Mutex<ActualState>>,
    executor: Arc<dyn ExecutorAdapter>,
    config: ReconcilerConfig,
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

/// Configuration for reconciliation loop
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    pub check_interval_secs: u64,
    pub max_retries: u32,
    pub retry_delay_secs: u64,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            max_retries: 3,
            retry_delay_secs: 5,
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
        let data =
            postcard::to_allocvec(&*state).map_err(|e| format!("Serialize: {}", e))?;
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

    /// Compare desired vs actual, return drift items
    async fn detect_drift(&self) -> Vec<DriftItem> {
        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let mut drifts = Vec::new();

        for rule in &desired.rules {
            match actual.active_rules.iter().find(|r| r.id == rule.id) {
                Some(ar) if ar.action == rule.action => {}
                Some(_) => {
                    drifts.push(DriftItem::RuleChanged {
                        rule_id: rule.id,
                        expected: rule.action,
                    });
                }
                None => {
                    drifts.push(DriftItem::RuleMissing {
                        rule_id: rule.id,
                        expected: rule.action,
                    });
                }
            }
        }

        for actual_rule in &actual.active_rules {
            if !desired.rules.iter().any(|r| r.id == actual_rule.id) {
                drifts.push(DriftItem::RuleExtra {
                    rule_id: actual_rule.id,
                });
            }
        }

        drifts
    }

    /// Apply desired state
    async fn apply_desired_state(&self) -> Result<(), String> {
        let desired = self.desired_state.lock().await;

        for rule in &desired.rules {
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

            let result = self.executor.execute(&request).await;

            match result {
                ActionResult::Applied { rule_id, .. } => {
                    let mut actual = self.actual_state.lock().await;
                    actual.active_rules.push(ActualRule {
                        id: rule.id,
                        action: rule.action,
                        rule_id,
                    });
                    info!(rule_id = rule.id, "Rule applied");
                }
                ActionResult::AlreadyApplied => {}
                ActionResult::Failed { error, message } => {
                    warn!(rule_id = rule.id, ?error, ?message, "Failed to apply rule");
                    return Err(format!("Rule {} failed: {:?}", rule.id, message));
                }
                ActionResult::Retry { after_ms, reason } => {
                    warn!(rule_id = rule.id, after_ms, reason, "Retry needed");
                }
                ActionResult::Unsupported { .. } => {
                    warn!(rule_id = rule.id, "Unsupported action");
                }
            }
        }

        Ok(())
    }

    /// Single reconciliation cycle
    pub async fn reconcile(&self) -> Result<(), String> {
        let drifts = self.detect_drift().await;

        if drifts.is_empty() {
            info!("State is consistent, no drift");
            return Ok(());
        }

        info!(drift_count = drifts.len(), "Drift detected, reconciling");

        for drift in &drifts {
            match drift {
                DriftItem::RuleMissing { rule_id, expected: _ } => {
                    info!(rule_id, "Adding missing rule");
                }
                DriftItem::RuleExtra { rule_id } => {
                    info!(rule_id, "Removing extra rule");
                }
                DriftItem::RuleChanged {
                    rule_id,
                    expected,
                } => {
                    info!(rule_id, ?expected, "Updating changed rule");
                }
            }
        }

        // Rebuild actual state from desired
        {
            let mut actual = self.actual_state.lock().await;
            actual.active_rules.clear();
        }

        self.apply_desired_state().await
    }

    /// Run reconciliation loop forever
    pub async fn run_loop(&self) {
        info!(interval = self.config.check_interval_secs, "Reconciliation loop started");

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(self.config.check_interval_secs)).await;

            if let Err(e) = self.reconcile().await {
                error!("Reconciliation error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(self.config.retry_delay_secs)).await;
            }
        }
    }
}

/// Types of drift
#[derive(Debug)]
pub enum DriftItem {
    RuleMissing { rule_id: u32, expected: Action },
    RuleExtra { rule_id: u32 },
    RuleChanged { rule_id: u32, expected: Action },
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
        let id = self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                DesiredRule { id: 1, action: Action::Block, priority: 100 },
                DesiredRule { id: 2, action: Action::Allow, priority: 50 },
            ],
            drivers: Vec::new(),
        };

        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        // Detect drift — both rules missing
        let drifts = reconciler.detect_drift().await;
        assert_eq!(drifts.len(), 2);

        // Apply state
        reconciler.apply_desired_state().await.unwrap();

        // Detect drift again — clean
        let drifts = reconciler.detect_drift().await;
        assert!(drifts.is_empty());
    }

    #[tokio::test]
    async fn test_reconciler_add_remove() {
        let desired = DesiredState {
            rules: vec![DesiredRule { id: 1, action: Action::Block, priority: 100 }],
            drivers: Vec::new(),
        };

        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        reconciler.apply_desired_state().await.unwrap();

        // Add rule
        reconciler.add_rule(DesiredRule { id: 2, action: Action::Allow, priority: 50 }).await;
        let drifts = reconciler.detect_drift().await;
        assert_eq!(drifts.len(), 1);

        // Remove rule
        reconciler.remove_rule(1).await;
        let drifts = reconciler.detect_drift().await;
        assert_eq!(drifts.len(), 2); // 1 missing + 1 extra
    }

    #[tokio::test]
    async fn test_reconciler_full_cycle() {
        let desired = DesiredState::default();
        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        reconciler.add_rule(DesiredRule { id: 1, action: Action::Block, priority: 100 }).await;
        reconciler.add_rule(DesiredRule { id: 2, action: Action::Allow, priority: 50 }).await;

        // Full reconcile cycle
        reconciler.reconcile().await.unwrap();

        // Verify consistency
        let drifts = reconciler.detect_drift().await;
        assert!(drifts.is_empty());
    }
}
