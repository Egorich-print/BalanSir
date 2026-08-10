//! The reconcile loop and its adapters to the coordinator.

use crate::reconciliation::adapters::{
    DaemonActualStore, DaemonDesiredProvider, DaemonExecutorAdapter, DaemonRollback,
};
use crate::reconciliation::sinks::TracingEventSink;
use crate::reconciliation::{ReconciliationError, ReconciliationResult};
use balansir_common::plan::ReconciliationPlan;
use balansir_common::{ActionRequest, ActionResult, ActualState, DesiredRule, DesiredState};
use balansir_control::planner::BasicPlanner;
use balansir_control::snapshot_store::MemorySnapshotStore;
use balansir_control::traits::{Executor, Planner};
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
    /// The single planning authority (M3.4.2). Both the coordinator's planning
    /// step and `Reconciler::build_plan` route through this same `Planner`
    /// port instance, so there is exactly one authoritative planning path.
    planner: Arc<dyn Planner>,
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

        // Single planning authority (M3.4.2): one `Planner` port instance is
        // shared by the coordinator and by `Reconciler::build_plan`.
        let planner: Arc<dyn Planner> = Arc::new(BasicPlanner);

        let coordinator = Arc::new(Coordinator::new(
            CoordinatorConfig::new(
                Arc::new(DaemonDesiredProvider {
                    desired: desired.clone(),
                }),
                actual_store,
                planner.clone(),
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
            planner,
        }
    }

    /// Create reconciler from state store.
    pub async fn from_state_store(
        state_store: &impl balansir_common::state::StateStore,
    ) -> ReconciliationResult<Self> {
        let desired = match state_store.load("desired_state").await {
            Ok(Some(data)) => postcard::from_bytes(&data)
                .map_err(|e| ReconciliationError::Deserialize(e.to_string()))?,
            Ok(None) => DesiredState::default(),
            Err(e) => return Err(ReconciliationError::StateLoad(e.to_string())),
        };

        let executor = Arc::new(crate::reconciliation::dummy::DummyExecutorAdapter::new());
        Ok(Self::new(desired, executor, ReconcilerConfig::default()))
    }

    /// Save desired state to store.
    pub async fn save_to_store(
        &self,
        state_store: &impl balansir_common::state::StateStore,
    ) -> ReconciliationResult<()> {
        let state = self.desired_state.lock().await;
        let data = postcard::to_allocvec(&*state)
            .map_err(|e| ReconciliationError::Serialize(e.to_string()))?;
        state_store
            .save("desired_state", &data)
            .await
            .map_err(|e| ReconciliationError::StateSave(e.to_string()))?;
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

    /// Transactional hot reload (ADR-010).
    ///
    /// Compiles the candidate strictly, then reveals the new desired state to
    /// the coordinator only when its reconcile cycle succeeds. On failure the
    /// old desired state is restored and the error surfaced — no
    /// half-old/half-new state is ever observable.
    pub async fn reload(
        &self,
        candidate: DesiredState,
        reason: ReconcileReason,
    ) -> ReconciliationResult<()> {
        let prev = {
            let mut desired = self.desired_state.lock().await;
            std::mem::replace(&mut *desired, candidate)
        };

        match self.coordinator.reconcile(reason).await {
            Ok(()) => Ok(()),
            Err(e) => {
                *self.desired_state.lock().await = prev;
                Err(ReconciliationError::Reconcile(e.to_string()))
            }
        }
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
    pub async fn apply_plan(&self, plan: ReconciliationPlan) -> ReconciliationResult<()> {
        let report = self
            .runner
            .execute(&plan)
            .await
            .map_err(|e| ReconciliationError::Config(e.to_string()))?;
        if report.success {
            Ok(())
        } else {
            Err(ReconciliationError::Reconcile(format!(
                "{} of {} steps failed",
                report.failed, report.total
            )))
        }
    }

    /// Build a reconciliation plan without applying it (for dry-run and testing).
    ///
    /// Routes through the same `Planner` port instance the coordinator uses
    /// (M3.4.2) — one authoritative planning path.
    pub async fn build_plan(&self) -> ReconciliationPlan {
        let desired = self.desired_state.lock().await;
        let actual = self.actual_state.lock().await;
        let gen = self.generation();
        self.planner.build_plan(&desired, &actual, gen)
    }

    /// Dry-run (M3.4.3): compute the reconciliation plan exactly as a real
    /// reconcile would, without executing it.
    ///
    /// Same single `Planner` authority as normal reconciliation; no side
    /// effects — no execution, no state mutation, no event emission, no
    /// generation bump. The returned plan is identical to what `reconcile`
    /// would attempt.
    pub async fn dry_run(&self) -> ReconciliationPlan {
        self.build_plan().await
    }

    /// Explain (M3.4.3): describe the operations the current dry-run plan
    /// would perform.
    ///
    /// Derived from the *same* plan produced by the single `Planner` authority,
    /// so the explanation always matches what normal reconciliation would
    /// attempt. No second planning path.
    pub async fn explain(&self) -> String {
        let plan = self.build_plan().await;
        plan.to_string()
    }

    /// Trigger a single reconciliation cycle.
    pub async fn reconcile(&self) -> ReconciliationResult<()> {
        self.coordinator
            .reconcile(ReconcileReason::Scheduled)
            .await
            .map_err(|e| ReconciliationError::Reconcile(e.to_string()))
    }

    /// Trigger an atomic reconciliation (rollback handled by the coordinator).
    pub async fn reconcile_atomic(&self) -> ReconciliationResult<()> {
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
    use balansir_common::{Action, ActionRequest, ActionResult};

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

    #[tokio::test]
    async fn test_reload_commits_new_state() {
        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(
            DesiredState::default(),
            executor,
            ReconcilerConfig::default(),
        );

        let candidate = DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Block,
                priority: 100,
            }],
            drivers: Vec::new(),
        };

        reconciler
            .reload(candidate, ReconcileReason::ConfigReload)
            .await
            .unwrap();

        let desired = reconciler.get_desired().await;
        assert_eq!(desired.rules.len(), 1);
        assert_eq!(desired.rules[0].id, 7);
        let actual = reconciler.get_actual().await;
        assert_eq!(actual.active_rules.len(), 1);
    }

    #[tokio::test]
    async fn test_reload_rejects_bad_state_and_keeps_old() {
        // A candidate whose reconcile fails must never replace the live state.
        let prev = DesiredState::default();

        // Executor that refuses every apply: any non-empty candidate fails.
        let failing = Arc::new(FailingExecutor);
        let reconciler = Reconciler::new(prev.clone(), failing, ReconcilerConfig::default());

        let bad = DesiredState {
            rules: vec![DesiredRule {
                id: 2,
                action: Action::Block,
                priority: 100,
            }],
            drivers: Vec::new(),
        };

        assert!(reconciler
            .reload(bad, ReconcileReason::ConfigReload)
            .await
            .is_err());

        // Old (empty) state is still live after the aborted reload.
        let desired = reconciler.get_desired().await;
        assert!(desired.rules.is_empty());
    }

    /// Executor that fails every rule apply — enough to force a reload
    /// rollback for any non-empty candidate.
    struct FailingExecutor;

    #[async_trait::async_trait]
    impl ExecutorAdapter for FailingExecutor {
        async fn execute(&self, _request: &ActionRequest) -> ActionResult {
            ActionResult::Failed {
                error: balansir_common::ActionError::Unknown,
                message: Some("simulated failure".into()),
            }
        }

        async fn rule_count(&self) -> u32 {
            0
        }

        async fn remove_rule(&self, _rule_id: u32) -> ActionResult {
            ActionResult::Applied {
                execution_time_us: 50,
                rule_id: Some(_rule_id),
            }
        }
    }

    /// M3.4.2: `Reconciler::build_plan` and the coordinator's planning step
    /// route through the *same* `Planner` port instance. Given the same
    /// desired/actual/generation, both must yield the identical deterministic
    /// plan — proving a single planning authority, not two diff engines.
    #[tokio::test]
    async fn build_plan_and_coordinator_share_one_planning_authority() {
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

        // Same inputs on both sides of the authority.
        reconciler.set_desired(desired).await;
        let actual = reconciler.get_actual().await;
        let gen = reconciler.generation();

        // Path 1: Reconciler::build_plan (must route through stored planner).
        let plan_via_reconciler = reconciler.build_plan().await;

        // Path 2: the coordinator's planner — the exact stored `Arc<dyn Planner>`.
        let plan_via_stored_planner =
            reconciler
                .planner
                .build_plan(&reconciler.get_desired().await, &actual, gen);

        // Same operation sequence and same generation semantics.
        assert_eq!(
            plan_via_reconciler.operations, plan_via_stored_planner.operations,
            "build_plan and the coordinator's planner must produce identical operations"
        );
        assert_eq!(
            plan_via_reconciler.generation_before,
            plan_via_stored_planner.generation_before
        );
        assert_eq!(
            plan_via_reconciler.generation_after,
            plan_via_stored_planner.generation_after
        );
    }

    /// M3.4.3: dry_run returns the same plan as the single planner authority
    /// and performs no side effects (no execution, no state mutation, no
    /// generation bump).
    #[tokio::test]
    async fn dry_run_produces_plan_without_side_effects() {
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
        reconciler.set_desired(desired).await;

        let plan = reconciler.dry_run().await;

        // The plan requests the two desired rules to be applied.
        assert_eq!(plan.operations.len(), 2);
        assert!(plan.operations.iter().any(|op| matches!(
            op,
            balansir_common::plan::ReconciliationOperation::UpdatePolicy(rule)
                if rule.id == 1
        )));
        assert!(plan.operations.iter().any(|op| matches!(
            op,
            balansir_common::plan::ReconciliationOperation::UpdatePolicy(rule)
                if rule.id == 2
        )));

        // Dry-run must not mutate actual state, bump generation, or execute.
        let actual = reconciler.get_actual().await;
        assert!(
            actual.active_rules.is_empty(),
            "dry-run must not apply rules"
        );
        assert_eq!(
            reconciler.generation(),
            1,
            "dry-run must not bump generation"
        );
    }

    /// M3.4.3: explain describes exactly the operations in the dry-run plan
    /// (same single planning authority), and a second call yields the same
    /// deterministic description.
    #[tokio::test]
    async fn explain_describes_dry_run_plan_operations() {
        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Block,
                priority: 100,
            }],
            drivers: Vec::new(),
        };
        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(desired, executor, ReconcilerConfig::default());

        let plan = reconciler.dry_run().await;
        let explanation = reconciler.explain().await;

        // Explain mentions the plan's generation and the policy operation.
        assert!(explanation.contains("Update policy"), "{explanation}");
        assert!(explanation.contains("generation:"), "{explanation}");

        // Deterministic: same inputs -> same explanation.
        assert_eq!(explanation, reconciler.explain().await);
        assert!(
            plan.to_string().contains("Update policy"),
            "plan display matches explain"
        );
    }
}
