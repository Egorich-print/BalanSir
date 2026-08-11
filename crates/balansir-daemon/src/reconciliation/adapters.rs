//! Adapters bridging the daemon's state and executor to the coordinator's
//! control-plane ports (StateProvider / Executor / Rollback).

use balansir_common::plan::{ReconciliationOperation, ReconciliationPlan};
use balansir_common::{
    ActionRequest, ActionResult, ActionType, ActualRule, ActualState, DecisionTrace, DesiredRule,
    DesiredState, Snapshot,
};
use balansir_control::traits::{DesiredProvider, Executor, Rollback, StateProvider};
use balansir_control::{ControlResult, ExecutionReport};
use smallvec::SmallVec;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::reconciliation::error::{ReconciliationError, ReconciliationResult};
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
                    // Ask the mechanism to remove the rule by its id (handle-
                    // based, M3.7); a failure is surfaced, not silently
                    // swallowed. ActualState is updated on success only.
                    match self.executor.remove_rule(*rule_id).await {
                        ActionResult::Applied { .. } | ActionResult::AlreadyApplied => {
                            let mut actual = self.actual.lock().await;
                            actual.active_rules.retain(|r| r.id != *rule_id);
                            succeeded += 1;
                        }
                        ActionResult::Failed { message, .. } => {
                            warn!(rule_id, error = ?message, "RemovePolicy failed");
                            failed += 1;
                        }
                        other => {
                            warn!(rule_id, ?other, "RemovePolicy returned unexpected result");
                            failed += 1;
                        }
                    }
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
    async fn apply_rule(&self, rule: &DesiredRule) -> ReconciliationResult<()> {
        // A3: carry the desired rule's optional flow criteria into the
        // request. Unspecified addresses / zero ports / zero protocol mean
        // "any" (no matcher), matching how the executor treats them.
        let request = ActionRequest {
            action: rule.action,
            src_ip: rule
                .flow
                .as_ref()
                .and_then(|f| f.src_ip)
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            dst_ip: rule
                .flow
                .as_ref()
                .and_then(|f| f.dst_ip)
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            src_port: rule.flow.as_ref().and_then(|f| f.src_port).unwrap_or(0),
            dst_port: rule.flow.as_ref().and_then(|f| f.dst_port).unwrap_or(0),
            protocol: rule.flow.as_ref().and_then(|f| f.protocol).unwrap_or(0),
            interface: 0,
            trace: DecisionTrace {
                // Carry the DesiredRule id so the executor can tag the rule and
                // resolve it for precise handle-based removal (M3.7).
                policy_id: rule.id,
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
                    flow: rule.flow.clone(),
                });
                info!(rule_id = rule.id, "Rule applied");
                Ok(())
            }
            ActionResult::AlreadyApplied => Ok(()),
            ActionResult::Failed { message, .. } => Err(ReconciliationError::ApplyRule(
                message.unwrap_or_else(|| "rule failed".to_string()),
            )),
            other => Err(ReconciliationError::ApplyRule(format!(
                "unexpected result: {:?}",
                other
            ))),
        }
    }
}

/// Production executor adapter placeholder until the privileged mechanism is
/// wired (M3.6: nftables/netlink command loop).
///
/// Every action is honestly reported as `Unsupported` — no rule is claimed
/// applied, `ActualState` is never mutated, and any reconcile that needs
/// execution fails and flows through the coordinator's rollback path. This
/// keeps the control plane production-wired without faking enforcement.
#[derive(Debug, Clone, Copy, Default)]
pub struct PendingMechanismAdapter;

#[async_trait::async_trait]
impl ExecutorAdapter for PendingMechanismAdapter {
    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        ActionResult::Unsupported {
            action_type: request.action.action_type(),
        }
    }

    async fn rule_count(&self) -> u32 {
        0
    }

    async fn remove_rule(&self, _rule_id: u32) -> ActionResult {
        ActionResult::Unsupported {
            action_type: ActionType::Block,
        }
    }
}

/// Restores the shared actual-state handle to its pre-execution snapshot and
/// reverts mechanism-level changes by issuing removals for every rule the
/// failed execution added beyond the snapshot, then restoring the in-memory view.
pub struct DaemonRollback {
    pub actual: Arc<tokio::sync::Mutex<ActualState>>,
    pub executor: Arc<dyn ExecutorAdapter>,
}

#[async_trait::async_trait]
impl Rollback for DaemonRollback {
    async fn rollback(&self, snapshot: &Snapshot) -> ControlResult<()> {
        warn!("Reverting kernel and state to pre-execution snapshot");

        // 1. Rules added during the failed execution: present in live actual,
        //    absent from the pre-execution snapshot.
        let live = self.actual.lock().await;
        let snapshot_ids: Vec<u32> = snapshot.actual.active_rules.iter().map(|r| r.id).collect();
        let to_revert: Vec<u32> = live
            .active_rules
            .iter()
            .map(|r| r.id)
            .filter(|id| !snapshot_ids.contains(id))
            .collect();
        drop(live);

        // 2. Mechanism-level undo of each appended rule.
        for rule_id in to_revert {
            if matches!(
                self.executor.remove_rule(rule_id).await,
                ActionResult::Failed { .. }
            ) {
                warn!(rule_id, "failed to revert rule via executor");
            }
        }

        // 3. Restore the in-memory view from the snapshot.
        let mut actual = self.actual.lock().await;
        *actual = snapshot.actual.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::plan::PlanMetadata;
    use std::sync::atomic::AtomicU32;

    #[derive(Default)]
    struct RevertRecorder {
        executed: AtomicU32,
        removals: std::sync::Mutex<Vec<u32>>,
    }

    #[async_trait::async_trait]
    impl ExecutorAdapter for RevertRecorder {
        async fn execute(&self, _request: &ActionRequest) -> ActionResult {
            self.executed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 1,
                rule_id: None,
            }
        }

        async fn rule_count(&self) -> u32 {
            self.executed.load(std::sync::atomic::Ordering::Relaxed)
        }

        async fn remove_rule(&self, rule_id: u32) -> ActionResult {
            if let Ok(mut removals) = self.removals.try_lock() {
                removals.push(rule_id);
            }
            self.executed
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 1,
                rule_id: Some(rule_id),
            }
        }
    }

    fn actual_state_single(id: u32) -> ActualState {
        ActualState {
            active_rules: vec![ActualRule {
                id,
                action: balansir_common::Action::Block,
                rule_id: None,
                flow: None,
            }],
        }
    }

    #[tokio::test]
    async fn rollback_reverts_added_rules_and_restores_snapshot() {
        let actual = Arc::new(tokio::sync::Mutex::new(ActualState {
            active_rules: vec![
                ActualRule {
                    id: 1,
                    action: balansir_common::Action::Block,
                    rule_id: None,
                    flow: None,
                },
                ActualRule {
                    id: 2,
                    action: balansir_common::Action::Allow,
                    rule_id: Some(10),
                    flow: None,
                },
            ],
        }));
        let recorder = Arc::new(RevertRecorder::default());
        let rollback = DaemonRollback {
            executor: recorder.clone(),
            actual: actual.clone(),
        };

        // Snapshot predates rule 2: it was added mid-execution and must be reverted.
        let snapshot = Snapshot::new(
            DesiredState::default(),
            actual_state_single(1),
            PlanMetadata::new(0),
        );

        rollback.rollback(&snapshot).await.unwrap();

        let removals = {
            let guard = recorder.removals.lock().unwrap_or_else(|e| e.into_inner());
            guard.clone()
        };
        assert_eq!(removals.as_slice(), &[2]);

        let restored = actual.lock().await;
        assert_eq!(restored.active_rules.len(), 1);
        assert_eq!(restored.active_rules[0].id, 1);
    }
}
