// crates/balansir-control/src/coordinator.rs

use crate::{
    error::{ControlError, ControlResult},
    events::{ControlEvent, ReconcileReason},
    state::{ReconcileProgress, ReconcileState, ReconcileTransition},
    traits::{
        DesiredProvider, EventSink, Executor, NoopEventSink, Planner, SnapshotStore, StateProvider,
    },
};
use balansir_common::plan::PlanMetadata;
use balansir_common::Snapshot;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Internal state of the coordinator's FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorState {
    Idle,
    ReadDesired,
    ReadActual,
    BuildPlan,
    ExecutePlan,
    CommitSnapshot,
    Done,
    Rollback,
    Failed,
}

impl From<CoordinatorState> for ReconcileState {
    fn from(state: CoordinatorState) -> Self {
        match state {
            CoordinatorState::Idle => Self::Idle,
            CoordinatorState::ReadDesired => Self::ReadDesired,
            CoordinatorState::ReadActual => Self::ReadActual,
            CoordinatorState::BuildPlan => Self::BuildPlan,
            CoordinatorState::ExecutePlan => Self::ExecutePlan,
            CoordinatorState::CommitSnapshot => Self::CommitSnapshot,
            CoordinatorState::Done => Self::Done,
            CoordinatorState::Rollback => Self::Rollback,
            CoordinatorState::Failed => Self::Failed,
        }
    }
}

/// Tick the FSM. Returns `None` when the transition is illegal for the current
/// state (runtime guard against programming errors).
impl CoordinatorState {
    fn transition(self, event: ControlEvent) -> Option<(CoordinatorState, ReconcileTransition)> {
        let (next, tr) = match (self, event) {
            (Self::Idle, ControlEvent::ReconciliationRequested(_reason)) => {
                (Self::ReadDesired, ReconcileTransition::IdleToReadDesired)
            }
            (Self::ReadDesired, ControlEvent::DesiredReadFinished { .. }) => {
                (Self::ReadActual, ReconcileTransition::ReadDesiredToReadActual)
            }
            (Self::ReadActual, ControlEvent::ActualReadFinished { .. }) => {
                (Self::BuildPlan, ReconcileTransition::ReadActualToBuildPlan)
            }
            (Self::BuildPlan, ControlEvent::PlanningFinished { .. }) => {
                (Self::ExecutePlan, ReconcileTransition::BuildPlanToExecutePlan)
            }
            (Self::ExecutePlan, ControlEvent::ExecutionStarted) => {
                (Self::ExecutePlan, ReconcileTransition::ExecutePlanToExecutePlan)
            }
            (Self::ExecutePlan, ControlEvent::StepCompleted { .. }) => {
                (Self::ExecutePlan, ReconcileTransition::ExecutePlanToExecutePlan)
            }
            (Self::ExecutePlan, ControlEvent::StepFailed { .. }) => {
                (Self::Rollback, ReconcileTransition::ExecutePlanToRollback)
            }
            (Self::ExecutePlan, ControlEvent::CommitCompleted) => {
                (Self::CommitSnapshot, ReconcileTransition::ExecutePlanToCommitSnapshot)
            }
            (Self::CommitSnapshot, ControlEvent::Reconciled { .. }) => {
                (Self::Done, ReconcileTransition::CommitSnapshotToDone)
            }
            (Self::Rollback, ControlEvent::RollbackCompleted) => {
                (Self::Failed, ReconcileTransition::RollbackToFailed)
            }
            _ => return None,
        };
        Some((next, tr))
    }
}

/// Attempts to converge the system back to its previous snapshot when a
/// reconcile fails mid-execution.
///
/// The concrete implementation owns whatever state must be mutated to undo a
/// partially applied plan (in-memory store, external driver, etc.).
#[async_trait::async_trait]
pub trait Rollback: Send + Sync {
    async fn rollback(&self, snapshot: &Snapshot) -> ControlResult<()>;
}

/// Default rollback: does nothing. Used when no recovery is actionable.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRollback;

#[async_trait::async_trait]
impl Rollback for NoopRollback {
    async fn rollback(&self, _snapshot: &Snapshot) -> ControlResult<()> {
        Ok(())
    }
}

/// The coordinator's wiring.
#[derive(Clone)]
pub struct Config {
    desired_provider: Arc<dyn DesiredProvider>,
    actual_provider: Arc<dyn StateProvider>,
    planner: Arc<dyn Planner>,
    executor: Arc<dyn Executor>,
    snapshot_store: Arc<dyn SnapshotStore>,
    event_sink: Arc<dyn EventSink>,
    rollback: Arc<dyn Rollback>,
}

impl Config {
    pub fn new(
        desired_provider: Arc<dyn DesiredProvider>,
        actual_provider: Arc<dyn StateProvider>,
        planner: Arc<dyn Planner>,
        executor: Arc<dyn Executor>,
        snapshot_store: Arc<dyn SnapshotStore>,
    ) -> Self {
        Self {
            desired_provider,
            actual_provider,
            planner,
            executor,
            snapshot_store,
            event_sink: Arc::new(NoopEventSink),
            rollback: Arc::new(NoopRollback),
        }
    }

    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = sink;
        self
    }

    pub fn with_rollback(mut self, rollback: Arc<dyn Rollback>) -> Self {
        self.rollback = rollback;
        self
    }
}

/// The reconciler FSM that drives a single reconcile to completion.
pub struct Coordinator {
    state: Mutex<CoordinatorState>,
    progress: Mutex<ReconcileProgress>,
    generation: AtomicU64,
    config: Config,
    /// Serializes concurrent `reconcile` calls (fail-fast with
    /// `ReconcileInProgress` rather than queueing).
    busy: tokio::sync::Mutex<()>,
}

impl Coordinator {
    pub fn new(config: Config) -> Self {
        Self {
            state: Mutex::new(CoordinatorState::Idle),
            progress: Mutex::new(ReconcileProgress::default()),
            generation: AtomicU64::new(1),
            config,
            busy: tokio::sync::Mutex::new(()),
        }
    }

    /// Current generation. Bumped only when a non-empty plan was committed.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Human-observable progress (FSM state).
    pub fn progress(&self) -> ReconcileProgress {
        self.progress.lock().unwrap().clone()
    }

    fn enter(&self, state: CoordinatorState) {
        *self.progress.lock().unwrap() = ReconcileProgress {
            state: state.into(),
            step_index: 0,
        };
        *self.state.lock().unwrap() = state;
    }

    /// Apply a validated FSM transition; ignore illegal ticks (should not
    /// happen in a well-formed flow).
    fn advance(&self, event: ControlEvent) {
        let cur = *self.state.lock().unwrap();
        if let Some((next, _)) = cur.transition(event) {
            self.enter(next);
        }
    }

    async fn emit(&self, event: ControlEvent) {
        if let Err(e) = self.config.event_sink.emit(&event).await {
            tracing::warn!(error = %e, event = %event.name(), "event sink failed");
        }
    }

    async fn fail(&self, err: ControlError) -> ControlResult<()> {
        self.emit(ControlEvent::Failed { error: err.to_string() }).await;
        self.enter(CoordinatorState::Failed);
        Err(err)
    }

    /// Execute the plan. On success, commit and return the report.
    async fn run(&self, plan: &balansir_common::ReconciliationPlan) -> ControlResult<crate::state::ExecutionReport> {
        self.emit(ControlEvent::ExecutionStarted).await;
        self.advance(ControlEvent::ExecutionStarted);
        self.config.executor.execute(plan).await
    }

    /// Roll back to the pre-execution snapshot and fail.
    async fn rollback_and_fail(
        &self,
        snapshot: &Snapshot,
        err: ControlError,
    ) -> ControlResult<()> {
        // Move onto the Rollback edge, then complete it.
        self.advance(ControlEvent::StepFailed { index: 0, error: err.to_string() });
        self.emit(ControlEvent::RollbackStarted).await;
        if let Err(rb_err) = self.config.rollback.rollback(snapshot).await {
            self.emit(ControlEvent::StepFailed { index: 0, error: rb_err.to_string() }).await;
            return self.fail(rb_err).await;
        }
        self.emit(ControlEvent::RollbackCompleted).await;
        self.advance(ControlEvent::RollbackCompleted);
        self.fail(err).await
    }

    /// Run a single reconciliation cycle.
    pub async fn reconcile(&self, reason: ReconcileReason) -> ControlResult<()> {
        let _guard = self
            .busy
            .try_lock()
            .map_err(|_| ControlError::ReconcileInProgress)?;

        // ----- Idle -> ReadDesired -----
        self.emit(ControlEvent::ReconciliationRequested(reason.clone())).await;
        self.advance(ControlEvent::ReconciliationRequested(reason));

        // ----- Read desired state -----
        self.emit(ControlEvent::DesiredReadStarted).await;
        let desired = match self.config.desired_provider.desired().await {
            Ok(v) => v,
            Err(e) => return self.fail(e).await,
        };
        let revision = desired.rules.len() as u64;
        self.emit(ControlEvent::DesiredReadFinished { revision }).await;
        self.advance(ControlEvent::DesiredReadFinished { revision });

        // ----- Read actual state -----
        self.emit(ControlEvent::ActualReadStarted).await;
        let actual = match self.config.actual_provider.actual().await {
            Ok(v) => v,
            Err(e) => return self.fail(e).await,
        };
        let rule_count = actual.active_rules.len();
        self.emit(ControlEvent::ActualReadFinished { rule_count }).await;
        self.advance(ControlEvent::ActualReadFinished { rule_count });

        // ----- Build plan -----
        self.emit(ControlEvent::PlanningStarted).await;
        let gen = self.generation.load(Ordering::Relaxed);
        let plan = self.config.planner.build_plan(&desired, &actual, gen);
        let empty = plan.is_empty();
        let op_count = plan.operations.len();
        self.emit(ControlEvent::PlanningFinished {
            generation: plan.generation_after,
            operation_count: op_count,
            empty,
        })
        .await;
        self.advance(ControlEvent::PlanningFinished {
            generation: plan.generation_after,
            operation_count: op_count,
            empty,
        });

        // ----- No-op: nothing to commit -----
        if empty {
            self.emit(ControlEvent::CommitCompleted).await;
            self.advance(ControlEvent::CommitCompleted);
            let plan_id = Uuid::new_v4();
            self.emit(ControlEvent::Reconciled { plan_id }).await;
            self.advance(ControlEvent::Reconciled { plan_id });
            self.enter(CoordinatorState::Done);
            return Ok(());
        }

        // ----- Pre-execution snapshot for rollback / recovery -----
        let snapshot = Snapshot::new(
            desired.clone(),
            actual,
            PlanMetadata::new(plan.generation_before),
        );
        if let Err(e) = self.config.snapshot_store.save(&snapshot).await {
            return self.fail(e).await;
        }

        // ----- Execute plan -----
        let report = match self.run(&plan).await {
            Ok(r) => r,
            Err(e) => return self.rollback_and_fail(&snapshot, e).await,
        };

        if !report.success {
            let err = ControlError::Executor(format!(
                "execution failed: {}/{} steps failed",
                report.failed, report.total
            ));
            return self.rollback_and_fail(&snapshot, err).await;
        }

        // ----- Commit -----
        self.emit(ControlEvent::CommitCompleted).await;
        self.advance(ControlEvent::CommitCompleted);
        self.generation.store(plan.generation_after, Ordering::Relaxed);
        self.emit(ControlEvent::Reconciled { plan_id: report.execution_id }).await;
        self.advance(ControlEvent::Reconciled { plan_id: report.execution_id });
        self.enter(CoordinatorState::Done);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ControlError;
    use crate::events::ControlEvent;
    use crate::executor::MockExecutor;
    use crate::planner::BasicPlanner;
    use crate::provider::{MemoryDesiredProvider, MemoryStateProvider};
    use crate::snapshot_store::MemorySnapshotStore;
    use balansir_common::{Action, DesiredRule, DesiredState};

    fn desired() -> DesiredState {
        DesiredState {
            rules: vec![
                DesiredRule { id: 1, action: Action::Block, priority: 100 },
                DesiredRule { id: 2, action: Action::Allow, priority: 50 },
            ],
            drivers: vec![],
        }
    }

    fn planner() -> Arc<BasicPlanner> {
        Arc::new(BasicPlanner)
    }

    #[test]
    fn fsm_transitions() {
        let s = CoordinatorState::Idle;
        assert_eq!(
            s.transition(ControlEvent::ReconciliationRequested(ReconcileReason::Manual))
                .map(|(n, _)| n),
            Some(CoordinatorState::ReadDesired)
        );
        assert!(s.transition(ControlEvent::DesiredReadFinished { revision: 0 }).is_none());
    }

    #[tokio::test]
    async fn reconcile_commits_and_bumps_generation() {
        let coord = Coordinator::new(Config::new(
            Arc::new(MemoryDesiredProvider::new(desired())),
            Arc::new(MemoryStateProvider::default()),
            planner(),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
        ));

        coord.reconcile(ReconcileReason::Startup).await.unwrap();
        assert_eq!(coord.generation(), 2);
        assert_eq!(coord.progress().state, ReconcileState::Done);
    }

    #[tokio::test]
    async fn reconcile_empty_plan_is_done_without_execution() {
        let coord = Coordinator::new(Config::new(
            Arc::new(MemoryDesiredProvider::new(DesiredState::default())),
            Arc::new(MemoryStateProvider::default()),
            planner(),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
        ));

        coord.reconcile(ReconcileReason::Scheduled).await.unwrap();
        assert_eq!(coord.generation(), 1);
        assert_eq!(coord.progress().state, ReconcileState::Done);
    }

    #[derive(Default)]
    struct CountingRollback(AtomicU64);

    #[async_trait::async_trait]
    impl Rollback for CountingRollback {
        async fn rollback(&self, _snapshot: &Snapshot) -> ControlResult<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn reconcile_failure_rolls_back() {
        let rollback = Arc::new(CountingRollback::default());
        let failing = Arc::new(MockExecutor::new().with_failure_after(1));
        let coord = Coordinator::new(
            Config::new(
                Arc::new(MemoryDesiredProvider::new(desired())),
                Arc::new(MemoryStateProvider::default()),
                planner(),
                failing,
                Arc::new(MemorySnapshotStore::new()),
            )
            .with_rollback(rollback.clone()),
        );

        let err = coord.reconcile(ReconcileReason::Manual).await.unwrap_err();
        assert!(matches!(err, ControlError::Executor(_)));
        assert_eq!(coord.progress().state, ReconcileState::Failed);
        assert_eq!(coord.generation(), 1);
        assert_eq!(rollback.0.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn provider_error_marks_failed() {
        let coord = Coordinator::new(Config::new(
            Arc::new(crate::provider::MissingDesiredProvider),
            Arc::new(MemoryStateProvider::default()),
            planner(),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
        ));

        let err = coord.reconcile(ReconcileReason::Startup).await.unwrap_err();
        assert!(matches!(err, ControlError::DesiredProvider(_)));
        assert_eq!(coord.progress().state, ReconcileState::Failed);
    }
}
