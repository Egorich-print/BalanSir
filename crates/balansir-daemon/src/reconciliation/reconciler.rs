//! The reconcile loop and its adapters to the coordinator.

use crate::reconciliation::adapters::{
    DaemonActualStore, DaemonDesiredProvider, DaemonExecutorAdapter, DaemonRollback,
};
use crate::reconciliation::sinks::TracingEventSink;
use crate::reconciliation::{ReconciliationError, ReconciliationResult};
use balansir_common::plan::ReconciliationPlan;
use balansir_common::{
    ActionRequest, ActionResult, ActualRule, ActualState, DesiredRule, DesiredState, PathMtu,
};
use balansir_control::planner::BasicPlanner;
use balansir_control::snapshot_store::MemorySnapshotStore;
use balansir_control::traits::{Executor, Planner};
use balansir_control::{Coordinator, CoordinatorConfig, ReconcileReason};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Reconciliation loop for maintaining desired state.
///
/// The actual converge work is delegated to the `balansir-control` coordinator,
/// which drives an FSM: read desired -> read actual -> build plan -> execute ->
/// commit/rollback. This type adapts the daemon's state and executor to the
/// coordinator's provider abstractions and keeps the daemon-facing API stable.
pub struct Reconciler {
    desired_state: Arc<tokio::sync::Mutex<DesiredState>>,
    /// The desired state *as authored* (pre-compilation, domains still
    /// present). P6 (ADR-023): the DNS resync loop re-runs the flow compiler
    /// over this to pick up changed DNS observations. `None` until set.
    desired_raw: Arc<tokio::sync::Mutex<Option<DesiredState>>>,
    actual_state: Arc<tokio::sync::Mutex<ActualState>>,
    config: ReconcilerConfig,
    coordinator: Arc<Coordinator>,
    runner: Arc<DaemonExecutorAdapter>,
    /// Raw mechanism adapter, retained so the daemon can query the executor's
    /// kernel inventory (A2, non-authoritative) and reconcile orphans.
    executor: Arc<dyn ExecutorAdapter>,
    /// DNS/conn metadata → compiled flow rules (A3, ADR-018). When present,
    /// `set_desired`/`reload` expand domain-based rules into concrete per-IP
    /// rules before the planner sees them, and `dns_loop` re-runs them on DNS
    /// changes (P6, ADR-023). Shared behind a lock so the compiler can be
    /// registered after construction (the daemon holds the reconciler in an
    /// `Arc`).
    flow_compiler: tokio::sync::Mutex<Option<crate::reconciliation::dns_flow::FlowCompiler>>,
    /// Fingerprint of the last accepted desired-state config (P4.8, ADR-021).
    /// `None` until a config has been set/reloaded; updated by `set_desired`
    /// and `reload` so the operator can verify what is actually loaded.
    config_fingerprint: tokio::sync::Mutex<Option<u64>>,
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
    /// How often the ownership loop re-seeds `ActualState` from the executor's
    /// kernel inventory (P4.1, ADR-020): every `resync_every_n_cycles`
    /// iterations of `run_loop`. `0` disables periodic resync (only the
    /// explicit startup/`resync` calls). Catches external kernel edits and
    /// executor restarts that a `Desired − Actual` diff on stale accounting
    /// would miss.
    pub resync_every_n_cycles: u32,
    /// How often `dns_loop` re-runs the flow compiler over the *raw* desired
    /// state (P6, ADR-023). When DNS observations change a domain's resolved
    /// IP set, the next pass re-compiles and reconciles — the compiled per-IP
    /// rules track the latest resolution without a manual reload. `0` disables
    /// periodic DNS resync.
    pub dns_resync_interval_secs: u64,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 30,
            max_retries: 3,
            retry_delay_secs: 5,
            watchdog_timeout_secs: 30,
            atomic_rollback: true,
            resync_every_n_cycles: 3,
            dns_resync_interval_secs: 60,
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
    /// Report the ids of rules currently present in the mechanism (A2,
    /// non-authoritative inventory). Default empty.
    async fn actual_rule_ids(&self) -> Vec<u32> {
        Vec::new()
    }
    /// Apply a per-path MTU adjustment (P7.2, ADR-026). The executor owns the
    /// applied state; the daemon decides what should be applied.
    async fn set_path_mtu(&self, path: &str, mtu: u16) -> balansir_common::Result<()> {
        let _ = (path, mtu);
        Err(balansir_common::error::Error::Unsupported(
            "set_path_mtu not implemented by this adapter".into(),
        ))
    }
    /// Remove a per-path MTU adjustment (rollback).
    async fn restore_path_mtu(&self, path: &str) -> balansir_common::Result<()> {
        let _ = path;
        Err(balansir_common::error::Error::Unsupported(
            "restore_path_mtu not implemented by this adapter".into(),
        ))
    }
    /// The executor's currently applied per-path MTU set (non-authority).
    async fn path_mtu_state(&self) -> Vec<PathMtu> {
        Vec::new()
    }
}

impl Reconciler {
    /// Create a new reconciler (events only to tracing).
    pub fn new(
        desired_state: DesiredState,
        executor: Arc<dyn ExecutorAdapter>,
        config: ReconcilerConfig,
    ) -> Self {
        Self::new_inner(desired_state, executor, config, None)
    }

    /// Create a reconciler that also streams control events to a WebUI bridge.
    pub fn new_with_api(
        desired_state: DesiredState,
        executor: Arc<dyn ExecutorAdapter>,
        config: ReconcilerConfig,
        api_bridge: Arc<balansir_api::surface::ApiEventBridge>,
    ) -> Self {
        Self::new_inner(desired_state, executor, config, Some(api_bridge))
    }

    fn new_inner(
        desired_state: DesiredState,
        executor: Arc<dyn ExecutorAdapter>,
        config: ReconcilerConfig,
        api_bridge: Option<Arc<balansir_api::surface::ApiEventBridge>>,
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
        let executor_inner: Arc<dyn ExecutorAdapter> = executor.clone();
        let executor = Arc::new(DaemonExecutorAdapter {
            executor: executor.clone(),
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
            .with_event_sink(Self::build_event_sink(api_bridge)),
        ));

        Self {
            desired_state: desired,
            desired_raw: Arc::new(tokio::sync::Mutex::new(None)),
            actual_state: actual,
            config,
            coordinator,
            runner: executor,
            executor: executor_inner,
            flow_compiler: tokio::sync::Mutex::new(None),
            config_fingerprint: tokio::sync::Mutex::new(None),
            planner,
        }
    }

    /// Build the coordinator's event sink: tracing always, plus the WebUI
    /// bridge when the daemon provides one (fan-out, single authority).
    fn build_event_sink(
        api_bridge: Option<Arc<balansir_api::surface::ApiEventBridge>>,
    ) -> Arc<dyn balansir_control::traits::EventSink> {
        use crate::reconciliation::sinks::{ApiBridgeEventSink, FanoutEventSink};
        match api_bridge {
            Some(bridge) => Arc::new(FanoutEventSink::new(vec![
                Arc::new(TracingEventSink),
                Arc::new(ApiBridgeEventSink::new(bridge)),
            ])),
            None => Arc::new(TracingEventSink),
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

    /// Update desired state. Domain-based rules (A3) are compiled to concrete
    /// per-IP flow rules before being stored, so the planner only ever sees
    /// executor-ready rules. The raw (authored) state is kept so the DNS
    /// resync loop (P6) can re-compile it when observations change. The config
    /// fingerprint (P4.8) is recorded.
    pub async fn set_desired(&self, state: DesiredState) {
        let raw = state.clone();
        let state = match self.flow_compiler.lock().await.as_ref() {
            Some(compiler) => compiler.compile(&state),
            None => state,
        };
        *self.desired_raw.lock().await = Some(raw);
        *self.config_fingerprint.lock().await = Some(balansir_common::config_fingerprint(&state));
        *self.desired_state.lock().await = state;
    }

    /// The executor adapter this reconciler commands (P7.2: the B4 controller
    /// drives the same executor boundary the ownership loop uses, so every B4
    /// change is known to the daemon).
    pub fn executor_adapter(&self) -> Arc<dyn ExecutorAdapter> {
        Arc::clone(&self.executor)
    }

    /// Get the fingerprint of the last accepted config (P4.8, ADR-021), or
    /// `None` if no config has been set yet.
    pub async fn config_fingerprint(&self) -> Option<u64> {
        *self.config_fingerprint.lock().await
    }

    /// Install (or replace) the DNS flow compiler used by `set_desired`/`reload`.
    pub async fn with_flow_compiler(
        &self,
        compiler: crate::reconciliation::dns_flow::FlowCompiler,
    ) {
        *self.flow_compiler.lock().await = Some(compiler);
    }

    /// Get current desired state.
    pub async fn get_desired(&self) -> DesiredState {
        self.desired_state.lock().await.clone()
    }

    /// Get the raw (authored, pre-compilation) desired state, if set.
    pub async fn get_desired_raw(&self) -> Option<DesiredState> {
        self.desired_raw.lock().await.clone()
    }

    /// Transactional hot reload (ADR-010).
    ///
    /// Compiles the candidate strictly (A3: domain rules expanded to concrete
    /// per-IP flow rules), then reveals the new desired state to the
    /// coordinator only when its reconcile cycle succeeds. On failure the
    /// old desired state is restored and the error surfaced — no
    /// half-old/half-new state is ever observable. The config fingerprint
    /// (P4.8) is updated only on success.
    pub async fn reload(
        &self,
        candidate: DesiredState,
        reason: ReconcileReason,
    ) -> ReconciliationResult<()> {
        let raw = candidate.clone();
        let candidate = match self.flow_compiler.lock().await.as_ref() {
            Some(compiler) => compiler.compile(&candidate),
            None => candidate,
        };
        let fp = balansir_common::config_fingerprint(&candidate);
        let prev = {
            let mut desired = self.desired_state.lock().await;
            std::mem::replace(&mut *desired, candidate)
        };

        match self.coordinator.reconcile(reason).await {
            Ok(()) => {
                *self.desired_raw.lock().await = Some(raw);
                *self.config_fingerprint.lock().await = Some(fp);
                Ok(())
            }
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

    /// A2: reconcile kernel orphans after an ack-gap / executor restart.
    ///
    /// Asks the executor what rule ids are actually present in the kernel
    /// (non-authoritative inventory), seeds `ActualState` with them, then runs
    /// a normal reconcile. Rules present in the kernel but absent from desired
    /// are removed; the planner decides what *should* be present. The executor
    /// never decides what should be present.
    ///
    /// The inventory carries only ids, not actions, so seeded rules use a
    /// placeholder action (`Allow`); any desired rule that differs is
    /// re-applied by the planner (A1 makes that idempotent), and orphaned
    /// rules are removed by id.
    pub async fn sync_actual_from_executor(&self) -> ReconciliationResult<()> {
        let ids = self.executor.actual_rule_ids().await;
        let mut actual = self.actual_state.lock().await;
        actual.active_rules = ids
            .into_iter()
            .map(|id| ActualRule {
                id,
                action: balansir_common::Action::Allow,
                rule_id: None,
                flow: None,
            })
            .collect();
        Ok(())
    }

    /// Get current generation (for testing and monitoring).
    pub fn generation(&self) -> u64 {
        self.coordinator.generation()
    }

    /// The reconciliation configuration (intervals, resync policy) — exposed
    /// for the WebUI status page.
    pub fn config(&self) -> ReconcilerConfig {
        self.config.clone()
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
    ///
    /// P4.1 (ADR-020) ownership loop: every cycle reconciles Desired − Actual;
    /// every `resync_every_n_cycles` cycles it re-seeds ActualState from the
    /// executor's kernel inventory first, so external kernel edits and executor
    /// restarts are discovered and converged, not just startup orphans.
    pub async fn run_loop(&self) {
        info!(
            interval = self.config.check_interval_secs,
            resync_every = self.config.resync_every_n_cycles,
            "Reconciliation loop started"
        );

        let mut cycle: u32 = 0;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.check_interval_secs,
            ))
            .await;
            self.step(cycle).await;
            cycle = cycle.wrapping_add(1);
        }
    }

    /// One ownership-loop step (P4.1, ADR-020): optional inventory resync
    /// followed by a reconcile. Split out so the loop logic is testable without
    /// real wall-clock intervals.
    async fn step(&self, cycle: u32) {
        // Periodic ownership re-seed: bring ActualState back to what the
        // kernel actually holds before diffing, so external edits or an
        // executor restart cannot hide behind stale accounting.
        if self.config.resync_every_n_cycles > 0
            && cycle.is_multiple_of(self.config.resync_every_n_cycles)
        {
            if let Err(e) = self.sync_actual_from_executor().await {
                warn!("Periodic kernel-inventory resync failed (will still reconcile): {e}");
            }
        }

        if let Err(e) = self.reconcile_atomic().await {
            error!("Reconciliation error: {}", e);
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.retry_delay_secs,
            ))
            .await;
        }
    }

    /// Run the DNS resync loop forever (P6, ADR-023).
    ///
    /// Every `dns_resync_interval_secs` it re-runs the flow compiler over the
    /// raw desired state; if the compiled per-IP rules differ from what is
    /// loaded (because DNS observations changed a domain's IP set), it swaps
    /// the compiled state in and reconciles — without a manual reload.
    pub async fn dns_loop(&self) {
        if self.config.dns_resync_interval_secs == 0 {
            info!("DNS resync loop disabled (dns_resync_interval_secs = 0)");
            return;
        }
        info!(
            interval = self.config.dns_resync_interval_secs,
            "DNS resync loop started"
        );
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.dns_resync_interval_secs,
            ))
            .await;
            self.dns_resync().await;
        }
    }

    /// Re-compile the raw desired state through the flow compiler and, if the
    /// result differs from what is currently loaded, swap it in and reconcile
    /// (P6, ADR-023). Returns whether the desired state changed.
    pub async fn dns_resync(&self) -> bool {
        let compiler = {
            let guard = self.flow_compiler.lock().await;
            let Some(compiler) = guard.as_ref() else {
                return false;
            };
            compiler.clone()
        };
        let Some(raw) = self.desired_raw.lock().await.clone() else {
            return false;
        };
        let recompiled = compiler.compile(&raw);
        let mut desired = self.desired_state.lock().await;
        if *desired == recompiled {
            return false;
        }
        *desired = recompiled.clone();
        drop(desired);
        *self.config_fingerprint.lock().await =
            Some(balansir_common::config_fingerprint(&recompiled));
        if let Err(e) = self.reconcile_atomic().await {
            warn!("DNS resync reconcile failed: {e}");
        }
        true
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
                    flow: None,
                },
                DesiredRule {
                    id: 2,
                    action: Action::Allow,
                    priority: 50,
                    flow: None,
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
                flow: None,
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
                flow: None,
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
                flow: None,
            })
            .await;
        reconciler
            .add_rule(DesiredRule {
                id: 2,
                action: Action::Allow,
                priority: 50,
                flow: None,
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
                flow: None,
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

    /// P4.8 (ADR-021): the config fingerprint tracks the last *accepted*
    /// config — updated on a successful reload, unchanged on a failed one.
    #[tokio::test]
    async fn config_fingerprint_tracks_last_accepted_reload() {
        let executor = Arc::new(DummyExecutorAdapter::new());
        let reconciler = Reconciler::new(
            DesiredState::default(),
            executor,
            ReconcilerConfig::default(),
        );
        assert_eq!(reconciler.config_fingerprint().await, None);

        let candidate = DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Block,
                priority: 100,
                flow: None,
            }],
            drivers: Vec::new(),
        };
        let fp_expected = balansir_common::config_fingerprint(&candidate);
        reconciler
            .reload(candidate.clone(), ReconcileReason::ConfigReload)
            .await
            .unwrap();
        assert_eq!(reconciler.config_fingerprint().await, Some(fp_expected));

        // A different candidate has a different fingerprint and updates it.
        let changed = DesiredState {
            rules: vec![DesiredRule {
                id: 8,
                action: Action::Allow,
                priority: 10,
                flow: None,
            }],
            drivers: Vec::new(),
        };
        let fp_changed = balansir_common::config_fingerprint(&changed);
        reconciler
            .reload(changed, ReconcileReason::ConfigReload)
            .await
            .unwrap();
        assert_eq!(reconciler.config_fingerprint().await, Some(fp_changed));
        assert_ne!(fp_changed, fp_expected);

        // A failing reload must not change the fingerprint.
        let failing = Arc::new(FailingExecutor);
        let prev_fp = reconciler.config_fingerprint().await;
        let bad = DesiredState {
            rules: vec![DesiredRule {
                id: 99,
                action: Action::Block,
                priority: 100,
                flow: None,
            }],
            drivers: Vec::new(),
        };
        let failing_reconciler = Reconciler::new(
            DesiredState::default(),
            failing,
            ReconcilerConfig::default(),
        );
        assert!(failing_reconciler
            .reload(bad.clone(), ReconcileReason::ConfigReload)
            .await
            .is_err());
        // (The failing reconciler never accepted anything.)
        assert_eq!(failing_reconciler.config_fingerprint().await, None);
        assert_eq!(reconciler.config_fingerprint().await, prev_fp);
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
                flow: None,
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
                    flow: None,
                },
                DesiredRule {
                    id: 2,
                    action: Action::Allow,
                    priority: 50,
                    flow: None,
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
                    flow: None,
                },
                DesiredRule {
                    id: 2,
                    action: Action::Allow,
                    priority: 50,
                    flow: None,
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
                flow: None,
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

    /// A2: sync_actual_from_executor seeds ActualState from the executor's
    /// non-authoritative kernel inventory so orphaned rules are reconcilable.
    #[tokio::test]
    async fn sync_actual_from_executor_imports_kernel_inventory() {
        use std::sync::Arc;

        struct Inventory(Arc<tokio::sync::Mutex<Vec<u32>>>);
        #[async_trait::async_trait]
        impl ExecutorAdapter for Inventory {
            async fn execute(&self, _r: &ActionRequest) -> ActionResult {
                ActionResult::Unsupported {
                    action_type: balansir_common::ActionType::Block,
                }
            }
            async fn rule_count(&self) -> u32 {
                0
            }
            async fn remove_rule(&self, _id: u32) -> ActionResult {
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: None,
                }
            }
            async fn actual_rule_ids(&self) -> Vec<u32> {
                self.0.lock().await.clone()
            }
        }

        let inventory = Arc::new(tokio::sync::Mutex::new(vec![7u32, 42]));
        let executor = Arc::new(Inventory(inventory));
        let reconciler = Reconciler::new(
            DesiredState::default(),
            executor,
            ReconcilerConfig::default(),
        );

        reconciler.sync_actual_from_executor().await.unwrap();
        let actual = reconciler.get_actual().await;
        let mut ids: Vec<u32> = actual.active_rules.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![7, 42]);
    }

    /// P4.1 (ADR-020): the ownership loop converges an *external kernel edit*
    /// back to DesiredState. After a resync step, a rule that was injected into
    /// the kernel outside the daemon is discovered from the inventory and
    /// removed — the daemon's accounting alone could never see it.
    #[tokio::test]
    async fn ownership_loop_converges_external_kernel_edit() {
        use std::collections::HashSet;
        use std::sync::Arc;

        /// Fake executor whose "kernel" is a real set: execute adds, remove
        /// deletes, inventory reflects it — so convergence is observable.
        struct KernelExecutor {
            kernel: Arc<tokio::sync::Mutex<HashSet<u32>>>,
        }
        #[async_trait::async_trait]
        impl ExecutorAdapter for KernelExecutor {
            async fn execute(&self, r: &ActionRequest) -> ActionResult {
                self.kernel.lock().await.insert(r.trace.policy_id);
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: None,
                }
            }
            async fn rule_count(&self) -> u32 {
                self.kernel.lock().await.len() as u32
            }
            async fn remove_rule(&self, id: u32) -> ActionResult {
                self.kernel.lock().await.remove(&id);
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: None,
                }
            }
            async fn actual_rule_ids(&self) -> Vec<u32> {
                self.kernel.lock().await.iter().copied().collect()
            }
        }

        let kernel = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let executor = Arc::new(KernelExecutor {
            kernel: Arc::clone(&kernel),
        });
        let config = ReconcilerConfig {
            check_interval_secs: 0,
            resync_every_n_cycles: 1,
            ..Default::default()
        };
        let reconciler = Reconciler::new(
            DesiredState {
                rules: vec![DesiredRule {
                    id: 7,
                    action: Action::Block,
                    priority: 100,
                    flow: None,
                }],
                drivers: Vec::new(),
            },
            executor,
            config,
        );

        // Converge the desired rule into the kernel.
        reconciler.reconcile_atomic().await.unwrap();
        assert_eq!(kernel.lock().await.len(), 1, "desired rule installed");

        // External actor injects an unknown rule directly into the kernel.
        kernel.lock().await.insert(99);

        // One ownership step (resync + reconcile) must discover and remove it.
        reconciler.step(0).await;
        assert_eq!(
            *kernel.lock().await,
            HashSet::from([7u32]),
            "external kernel edit must be converged back to desired"
        );
        let actual = reconciler.get_actual().await;
        assert_eq!(actual.active_rules.len(), 1);
        assert_eq!(actual.active_rules[0].id, 7);
    }

    /// P6 (ADR-023): a DNS observation change re-compiles the raw desired
    /// state and reconciles — the compiled per-IP rule tracks the new
    /// resolution without a manual reload.
    #[tokio::test]
    async fn dns_resync_tracks_domain_resolution_change() {
        use crate::reconciliation::dns_flow::{DnsRegistry, FlowCompiler};
        use std::collections::HashSet;
        use std::sync::Arc;

        struct KernelExecutor {
            kernel: Arc<tokio::sync::Mutex<HashSet<u32>>>,
        }
        #[async_trait::async_trait]
        impl ExecutorAdapter for KernelExecutor {
            async fn execute(&self, r: &ActionRequest) -> ActionResult {
                self.kernel.lock().await.insert(r.trace.policy_id);
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: None,
                }
            }
            async fn rule_count(&self) -> u32 {
                self.kernel.lock().await.len() as u32
            }
            async fn remove_rule(&self, id: u32) -> ActionResult {
                self.kernel.lock().await.remove(&id);
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: None,
                }
            }
            async fn actual_rule_ids(&self) -> Vec<u32> {
                self.kernel.lock().await.iter().copied().collect()
            }
        }

        let kernel = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let executor = Arc::new(KernelExecutor {
            kernel: Arc::clone(&kernel),
        });

        // Domain rule + registry that resolves to IP A initially.
        let registry = DnsRegistry::new();
        registry.insert("api.example.com", vec!["203.0.113.5".parse().unwrap()]);
        let compiler = FlowCompiler::new(registry.clone());
        let reconciler = Reconciler::new(
            DesiredState::default(),
            executor,
            ReconcilerConfig::default(),
        );
        reconciler.with_flow_compiler(compiler).await;

        let raw = DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Block,
                priority: 100,
                flow: Some(balansir_common::FlowCriteria {
                    dst_domain: Some("api.example.com".to_string()),
                    ..Default::default()
                }),
            }],
            drivers: Vec::new(),
        };
        reconciler.set_desired(raw).await;
        reconciler.reconcile_atomic().await.unwrap();
        let ids_a: Vec<u32> = kernel.lock().await.iter().copied().collect();
        assert_eq!(
            ids_a.len(),
            1,
            "initial domain resolution installed one rule"
        );

        // DNS observation changes the resolution to a different IP.
        registry.insert("api.example.com", vec!["198.51.100.9".parse().unwrap()]);
        let changed = reconciler.dns_resync().await;
        assert!(changed, "dns_resync must detect the resolution change");

        // Kernel now holds the new derived rule id, and the old one is gone.
        let ids_b: Vec<u32> = kernel.lock().await.iter().copied().collect();
        assert_eq!(ids_b.len(), 1);
        assert_ne!(ids_a[0], ids_b[0], "derived id must change with the IP");
        assert!(kernel.lock().await.contains(&ids_b[0]));

        // A second resync with no DNS change is a no-op.
        assert!(!reconciler.dns_resync().await);
    }
}
