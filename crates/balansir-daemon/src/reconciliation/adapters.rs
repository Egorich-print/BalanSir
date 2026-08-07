//! Adapters bridging the daemon's state and executor to the coordinator's
//! control-plane ports (StateProvider / Executor / Rollback).

use balansir_common::plan::{ReconciliationOperation, ReconciliationPlan};
use balansir_common::{
    ActionRequest, ActionResult, ActualRule, ActualState, DecisionTrace, DesiredRule, DesiredState,
    Snapshot,
};
use balansir_control::traits::{DesiredProvider, Executor, Rollback, StateProvider};
use balansir_control::{ControlResult, ExecutionReport};
use smallvec::SmallVec;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::reconciliation::reconciler::ExecutorAdapter;

/// Reads the mutable desired-state handle for the coordinator.
pub struct DaemonDesiredProvider {
    pub desired: Arc<tokio::sync::Mutex<DesiredState>>,
}

#[async_trait::async_trait]
impl DesiredProvider for DaemonDesiredProvider {
    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.desired.lock().await.clone())
    }
}

/// Provides the actual state to the coordinator (StateProvider).
pub struct DaemonActualStore {
    pub actual: Arc<tokio::sync::Mutex<ActualState>>,
}

#[async_trait::async_trait]
impl StateProvider for DaemonActualStore {
    async fn actual(&self) -> ControlResult<ActualState> {
        Ok(self.actual.lock().await.clone())
    }
}

/// Executes reconciliation plans against the daemon's executor adapter and
/// mirrors applied rules into the shared actual-state handle.
pub struct DaemonExecutorAdapter {
    pub executor: Arc<dyn ExecutorAdapter>,
    pub actual: Arc<tokio::sync::Mutex<ActualState>>,
}

#[async_trait::async_trait]
impl Executor for DaemonExecutorAdapter {
    async fn execute(&self, plan: &ReconciliationPlan) -> ControlResult<ExecutionReport> {
        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for op in &plan.operations {
            match op {
                ReconciliationOperation::UpdatePolicy(rule) => {
                    if let Err(e) = self.apply_rule(rule).await {
                        warn!(rule_id = rule.id, error = %e, "Rule failed");
                        failed += 1;
                    } else {
                        succeeded += 1;
                    }
                }
                ReconciliationOperation::RemovePolicy(rule_id) => {
                    info!(rule_id, "Removing rule");
                    let mut actual = self.actual.lock().await;
                    actual.active_rules.retain(|r| r.id != *rule_id);
                    succeeded += 1;
                }
                ReconciliationOperation::CreateDriver(id) => {
                    // Driver lifecycle is owned by the executor process; the
                    // coordinator's executor does not implement it today.
                    warn!(driver = ?id, "CreateDriver not supported by executor adapter");
                }
                ReconciliationOperation::RemoveDriver(id) => {
                    warn!(driver = ?id, "RemoveDriver not supported by executor adapter");
                }
                ReconciliationOperation::RestartDriver(id) => {
                    warn!(driver = ?id, "RestartDriver not supported by executor adapter");
                }
                ReconciliationOperation::NoOp => {}
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

impl DaemonExecutorAdapter {
    async fn apply_rule(&self, rule: &DesiredRule) -> Result<(), String> {
        let request = ActionRequest {
            action: rule.action,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            interface: 0,
            trace: DecisionTrace {
                policy_id: 0,
                steps: SmallVec::new(),
                action: rule.action,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };

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
                Ok(())
            }
            ActionResult::AlreadyApplied => Ok(()),
            ActionResult::Failed { message, .. } => {
                Err(message.unwrap_or_else(|| "rule failed".to_string()))
            }
            other => Err(format!("unexpected result: {:?}", other)),
        }
    }
}

/// Restores the shared actual-state handle to its pre-execution snapshot.
pub struct DaemonRollback {
    pub actual: Arc<tokio::sync::Mutex<ActualState>>,
}

#[async_trait::async_trait]
impl Rollback for DaemonRollback {
    async fn rollback(&self, snapshot: &Snapshot) -> ControlResult<()> {
        warn!("Restoring actual state from pre-execution snapshot");
        let mut actual = self.actual.lock().await;
        *actual = snapshot.actual.clone();
        Ok(())
    }
}
