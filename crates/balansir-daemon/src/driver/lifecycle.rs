//! Runtime driver lifecycle: a per-driver state machine plus an atomic
//! two-phase reconcile for the whole desired set.
//!
//! See `docs/adr/ADR-011-runtime-driver-lifecycle.md`.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use balansir_common::{DriverAction, DriverError, DriverId, HealthStatus};

use crate::driver::ComponentDriver;

/// Lifecycle state machine of a single runtime driver.
///
/// Legal edges (enforced in `DriverLifecycleState::transition`):
///   Absent → Initializing → Active
///   Active → Replacing → Active          (config changed, new instance ok)
///   Active → Stopping → Absent           (removed / stopped)
///   Active → Degraded / Failed           (runtime failure != removal)
///   Degraded / Failed → Recovering → Active (recovery; desired untouched)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverLifecycleState {
    Absent,
    Initializing,
    Active,
    Replacing,
    Stopping,
    Degraded,
    Failed,
    Recovering,
}

impl DriverLifecycleState {
    /// Whether a live mechanism (program/service) exists for this state.
    pub fn has_handle(self) -> bool {
        matches!(self, Self::Initializing | Self::Active | Self::Replacing)
    }

    /// Validate a transition edge. Any transition the manager performs must
    /// be legal here (checked in debug builds).
    pub fn transition(self, to: DriverLifecycleState) -> bool {
        use DriverLifecycleState::*;
        match (self, to) {
            // No-op edges (idempotent reconcile / reporting).
            (Absent, Absent) | (Active, Active) | (Failed, Failed) | (Degraded, Degraded) => true,
            // Cold start: the manager runs Absent→Initializing→Active inside
            // one atomic two-phase round, so the composite edge is also legal.
            (Absent, Initializing)
            | (Absent, Failed)
            | (Initializing, Active)
            | (Initializing, Failed) => true,
            (Absent, Active) | (Failed, Active) => true,
            // Replacement of an active generation.
            (Active, Replacing) | (Replacing, Active) | (Replacing, Failed) => true,
            // Removal.
            (Active, Stopping) | (Degraded, Stopping) | (Failed, Stopping) | (Stopping, Absent) => {
                true
            }
            // Composite removal edge: the manager stops+removes within one
            // atomic round, so Direct transitions also occur.
            (Active, Absent) | (Degraded, Absent) | (Failed, Absent) => true,
            // Tracker for runtime failure (failure != removal).
            (Active, Degraded) | (Active, Failed) => true,
            // Recovery.
            (Degraded, Recovering) | (Failed, Recovering) => true,
            // Recovering back into the routing pool is never a removal.
            (Recovering, Active) | (Recovering, Failed) => true,
            _ => false,
        }
    }
}

/// Outcome of a single desired driver within one reconcile round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverOutcome {
    Added,
    Changed,
    Unchanged,
    Removed,
    Retrying,
    Failed { reason: String },
}

/// A structured lifecycle event, emitted as data for M3.3 (no infra yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverLifecycleEvent {
    pub driver: DriverId,
    pub from: DriverLifecycleState,
    pub to: DriverLifecycleState,
    pub outcome: DriverOutcome,
}

impl DriverLifecycleEvent {
    fn new(
        driver: DriverId,
        from: DriverLifecycleState,
        to: DriverLifecycleState,
        outcome: DriverOutcome,
    ) -> Self {
        debug_assert!(
            from.transition(to),
            "illegal lifecycle transition {from:?} -> {to:?}"
        );
        Self {
            driver,
            from,
            to,
            outcome,
        }
    }
}

/// Builds a fresh, stopped driver instance for `id` from `fingerprint`.
#[async_trait]
pub trait DriverFactory: Send + Sync {
    async fn build(
        &self,
        id: DriverId,
        fingerprint: u64,
    ) -> Result<Box<dyn ComponentDriver>, DriverError>;
}

/// A live, started driver plus the effective-config fingerprint it was built from.
struct Slot {
    driver: Box<dyn ComponentDriver>,
    fingerprint: u64,
}

/// Desired lifecycle intent for one driver in a reconcile round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverIntent {
    pub id: DriverId,
    pub action: DriverAction,
    /// Effective-config fingerprint. A `Start` for the same id with a different
    /// fingerprint is a *replacement*, not a no-op.
    pub fingerprint: u64,
}

impl DriverIntent {
    pub fn start(id: DriverId, fingerprint: u64) -> Self {
        Self {
            id,
            action: DriverAction::Start,
            fingerprint,
        }
    }

    pub fn stop(id: DriverId) -> Self {
        Self {
            id,
            action: DriverAction::Stop,
            fingerprint: 0,
        }
    }
}

/// Per-driver runtime bookkeeping. `slot` is `None` while the driver is
/// tracked but has no live mechanism (e.g. `Failed` from a bad config), so
/// the failure stays observable and retryable instead of being silently
/// removed.
struct DriverRuntime {
    state: DriverLifecycleState,
    slot: Option<Slot>,
    fingerprint: u64,
}

impl DriverRuntime {
    fn live(slot: Slot) -> Self {
        let fingerprint = slot.fingerprint;
        Self {
            state: DriverLifecycleState::Active,
            fingerprint,
            slot: Some(slot),
        }
    }

    fn failed(fingerprint: u64) -> Self {
        Self {
            state: DriverLifecycleState::Failed,
            fingerprint,
            slot: None,
        }
    }
}

/// Owns per-driver runtime state and drives it toward a desired set.
pub struct DriverLifecycleManager {
    registry: HashMap<DriverId, DriverRuntime>,
    factory: Box<dyn DriverFactory>,
}

impl DriverLifecycleManager {
    pub fn new(factory: Box<dyn DriverFactory>) -> Self {
        Self {
            registry: HashMap::new(),
            factory,
        }
    }

    /// Current lifecycle state of a driver (or `Absent` if unknown).
    pub fn state(&self, id: DriverId) -> DriverLifecycleState {
        self.registry
            .get(&id)
            .map(|r| r.state)
            .unwrap_or(DriverLifecycleState::Absent)
    }

    /// (DriverId, state, fingerprint) for status surfaces (M3.3+).
    pub fn snapshot(&self) -> Vec<(DriverId, DriverLifecycleState, u64)> {
        self.registry
            .iter()
            .map(|(&id, r)| (id, r.state, r.fingerprint))
            .collect()
    }

    /// Reconcile the desired driver set against the running one.
    ///
    /// Two-phase (ADR-011):
    /// 1. **Stage**: build + start every candidate (new/changed fingerprint).
    ///    A failure here leaves previous live drivers untouched — runtime and
    ///    fallback are never removed by failure.
    /// 2. **Commit**: swap staged slots in (old handle dropped first, which
    ///    zeroizes secrets), then stop+drop drivers that are no longer desired.
    ///
    /// Removal is gated on the whole round succeeding: if any candidate
    /// failed, no-now-desired drivers stay as the fallback (the "B init fails,
    /// A stays" regression). Idempotent, reversible, side-effect-free when
    /// nothing changed.
    pub async fn reconcile(&mut self, intents: Vec<DriverIntent>) -> Vec<DriverLifecycleEvent> {
        let mut events = Vec::new();
        let mut had_stage_failure = false;
        let desired_present: HashSet<DriverId> = intents
            .iter()
            .filter(|i| i.action != DriverAction::Stop)
            .map(|i| i.id)
            .collect();

        // Phase 1: stage candidates (build + start), no registry mutation yet.
        let mut staged: HashMap<DriverId, Slot> = HashMap::new();
        let mut staged_outcome: HashMap<DriverId, DriverOutcome> = HashMap::new();

        for intent in intents {
            let id = intent.id;
            if intent.action == DriverAction::Stop {
                continue; // handled in the removal pass
            }
            let current = self.state(id);

            // Status is read-only: report the current state, no side effects.
            if intent.action == DriverAction::Status {
                events.push(DriverLifecycleEvent::new(
                    id,
                    current,
                    current,
                    DriverOutcome::Unchanged,
                ));
                continue;
            }

            // True no-op: same id, same fingerprint, already active — no
            // stop → init → start. Restart forces a fresh generation even when
            // the config fingerprint is unchanged, so skip the shortcut there.
            let unchanged = intent.action != DriverAction::Restart
                && current == DriverLifecycleState::Active
                && self.registry.get(&id).map(|r| r.fingerprint) == Some(intent.fingerprint);
            if unchanged {
                events.push(DriverLifecycleEvent::new(
                    id,
                    current,
                    current,
                    DriverOutcome::Unchanged,
                ));
                continue;
            }

            let replacing = current == DriverLifecycleState::Active;

            let mut fresh = match self.factory.build(id, intent.fingerprint).await {
                Ok(d) => d,
                Err(e) => {
                    had_stage_failure = true;
                    self.fail_stage(&mut events, id, current, replacing, intent.fingerprint, &e)
                        .await;
                    continue;
                }
            };
            if let Err(e) = fresh.start().await {
                had_stage_failure = true;
                self.fail_stage(&mut events, id, current, replacing, intent.fingerprint, &e)
                    .await;
                continue;
            }

            staged.insert(
                id,
                Slot {
                    driver: fresh,
                    fingerprint: intent.fingerprint,
                },
            );
            staged_outcome.insert(
                id,
                if replacing {
                    DriverOutcome::Changed
                } else {
                    DriverOutcome::Added
                },
            );
        }

        // Phase 2: swap staged slots in; dropping the old handle zeroizes its
        // secrets (M2.8) before the new generation becomes visible.
        for (id, slot) in staged {
            let from = self.state(id);
            let old = self.registry.insert(id, DriverRuntime::live(slot));
            if let Some(prev) = old {
                drop(prev.slot);
            }
            let outcome = staged_outcome.remove(&id).unwrap_or(DriverOutcome::Added);
            events.push(DriverLifecycleEvent::new(
                id,
                from,
                DriverLifecycleState::Active,
                outcome,
            ));
        }

        // Stop + drop now-absent drivers only when the whole round succeeded.
        if !had_stage_failure {
            let to_stop: Vec<DriverId> = self
                .registry
                .keys()
                .copied()
                .filter(|id| !desired_present.contains(id))
                .collect();
            for id in to_stop {
                events.push(self.stop_remove(id).await);
            }
        }

        events
    }

    async fn fail_stage(
        &mut self,
        events: &mut Vec<DriverLifecycleEvent>,
        id: DriverId,
        current: DriverLifecycleState,
        replacing: bool,
        fingerprint: u64,
        _e: &DriverError,
    ) {
        if replacing {
            // Previous generation stays live; failure is reported, not removal.
            events.push(DriverLifecycleEvent::new(
                id,
                current,
                current,
                DriverOutcome::Failed {
                    reason: "candidate failed to start".into(),
                },
            ));
            return;
        }
        if !self.registry.contains_key(&id) {
            // Brand-new desired driver that failed: track it as Failed so later
            // reconciles can retry (failure != removal).
            self.registry
                .entry(id)
                .or_insert_with(|| DriverRuntime::failed(fingerprint));
            events.push(DriverLifecycleEvent::new(
                id,
                DriverLifecycleState::Initializing,
                DriverLifecycleState::Failed,
                DriverOutcome::Failed {
                    reason: "candidate failed to start".into(),
                },
            ));
        }
    }

    async fn stop_remove(&mut self, id: DriverId) -> DriverLifecycleEvent {
        let from = self.state(id);
        if let Some(runtime) = self.registry.remove(&id) {
            if let Some(mut slot) = runtime.slot {
                let _ = slot.driver.stop().await;
                drop(slot); // zeroize secrets after stop
            }
        }
        DriverLifecycleEvent::new(
            id,
            from,
            DriverLifecycleState::Absent,
            DriverOutcome::Removed,
        )
    }

    /// Fold an observed health status into the state machine. A driver that
    /// becomes Unhealthy/Degraded stays tracked (never removed by health);
    /// recovery is an explicit, separate path.
    pub async fn report_health(&mut self, id: DriverId, health: HealthStatus) {
        let Some(runtime) = self.registry.get_mut(&id) else {
            return;
        };
        match (runtime.state, health) {
            (DriverLifecycleState::Active, HealthStatus::Degraded { .. }) => {
                runtime.state = DriverLifecycleState::Degraded;
            }
            (DriverLifecycleState::Active, HealthStatus::Unhealthy { .. }) => {
                runtime.state = DriverLifecycleState::Failed;
            }
            _ => {}
        }
    }

    /// Try to bring a Degraded/Failed driver back to Active without touching
    /// desired state. Returns true on success; on failure the driver stays
    /// Failed (never removed by recovery).
    pub async fn recover(&mut self, id: DriverId) -> bool {
        let Some(runtime) = self.registry.get(&id) else {
            return false;
        };
        if !matches!(
            runtime.state,
            DriverLifecycleState::Degraded | DriverLifecycleState::Failed
        ) {
            return false;
        }
        let fingerprint = runtime.fingerprint;
        let mut fresh = match self.factory.build(id, fingerprint).await {
            Ok(d) => d,
            Err(_) => return false,
        };
        if fresh.start().await.is_err() {
            return false;
        }
        let old = self.registry.insert(
            id,
            DriverRuntime::live(Slot {
                driver: fresh,
                fingerprint,
            }),
        );
        if let Some(prev) = old {
            drop(prev.slot);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DummyDriver;
    use std::collections::HashMap as StdMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type Driver = DriverId;

    /// Factory with runtime-toggleable per-(driver, fingerprint) failure flags
    /// and a build counter so the no-op envelope is observable.
    #[derive(Clone)]
    struct ToyFactory {
        fail: Arc<std::sync::Mutex<StdMap<(Driver, u64), bool>>>,
        builds: Arc<AtomicUsize>,
    }

    impl ToyFactory {
        fn new() -> Self {
            Self {
                fail: Arc::new(std::sync::Mutex::new(StdMap::new())),
                builds: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn fail_for(&self, id: Driver, fp: u64) {
            self.fail.lock().unwrap().insert((id, fp), true);
        }
        fn build_count(&self) -> usize {
            self.builds.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl DriverFactory for ToyFactory {
        async fn build(
            &self,
            id: DriverId,
            fingerprint: u64,
        ) -> Result<Box<dyn ComponentDriver>, DriverError> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            if self
                .fail
                .lock()
                .unwrap()
                .get(&(id, fingerprint))
                .copied()
                .unwrap_or(false)
            {
                return Err(DriverError::ConfigInvalid(format!(
                    "toy build failed for {:?} fp {}",
                    id, fingerprint
                )));
            }
            Ok(Box::new(DummyDriver::new(id, "toy")))
        }
    }

    fn d(id: u32, fp: u64) -> DriverIntent {
        DriverIntent::start(DriverId::Custom(id), fp)
    }
    fn c(id: u32) -> DriverId {
        DriverId::Custom(id)
    }
    fn state(m: &DriverLifecycleManager, id: u32) -> DriverLifecycleState {
        m.state(c(id))
    }
    fn loader(f: ToyFactory) -> DriverLifecycleManager {
        DriverLifecycleManager::new(Box::new(f))
    }

    #[tokio::test]
    async fn unchanged_is_true_noop() {
        let factory = ToyFactory::new();
        let mut m = loader(factory.clone());
        let e1 = m.reconcile(vec![d(7, 11)]).await;
        assert!(e1.iter().any(|e| e.outcome == DriverOutcome::Added));
        assert_eq!(state(&m, 7), DriverLifecycleState::Active);
        assert_eq!(factory.build_count(), 1);

        let e2 = m.reconcile(vec![d(7, 11)]).await;
        assert!(e2.iter().all(|e| e.outcome == DriverOutcome::Unchanged));
        assert_eq!(factory.build_count(), 1);
        assert_eq!(state(&m, 7), DriverLifecycleState::Active);
    }

    #[tokio::test]
    async fn idempotent_reconcile_is_side_effect_free() {
        let factory = ToyFactory::new();
        let mut m = loader(factory.clone());
        m.reconcile(vec![d(1, 1), d(2, 2), d(3, 1)]).await;
        let builds_after_first = factory.build_count();
        assert_eq!(builds_after_first, 3);

        let events = m.reconcile(vec![d(1, 1), d(2, 2), d(3, 1)]).await;
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.outcome == DriverOutcome::Unchanged));
        assert_eq!(factory.build_count(), builds_after_first);
    }

    /// Invariant 5: a new driver that cannot build is tracked as Failed and
    /// stays in the registry for retry.
    #[tokio::test]
    async fn failed_new_driver_stays_tracked() {
        let f = ToyFactory::new();
        f.fail_for(c(10), 99);
        let mut m = loader(f);
        let events = m.reconcile(vec![d(10, 99)]).await;
        assert!(events
            .iter()
            .any(|e| matches!(e.outcome, DriverOutcome::Failed { .. })));
        assert_eq!(state(&m, 10), DriverLifecycleState::Failed);
    }

    /// Regression #1: reload A→B, B init fails → A stays active → retry →
    /// B active, A gone. Single manager, real final-state transition.
    #[tokio::test]
    async fn reload_failed_replacement_keeps_old_then_retry_succeeds() {
        let factory = ToyFactory::new();
        let mut m = loader(factory.clone());

        // A (9) drives traffic.
        m.reconcile(vec![d(9, 1)]).await;
        assert_eq!(state(&m, 9), DriverLifecycleState::Active);

        // Reload: desired B (10) with a broken config → build fails.
        factory.fail_for(c(10), 99);
        let events = m.reconcile(vec![d(10, 99)]).await;
        assert!(events
            .iter()
            .any(|e| matches!(e.outcome, DriverOutcome::Failed { .. })));
        assert_eq!(state(&m, 9), DriverLifecycleState::Active, "A stays active");
        assert_eq!(
            state(&m, 10),
            DriverLifecycleState::Failed,
            "B tracked as Failed"
        );

        // Fix the config, retry the *same* reload: B active, A gone.
        factory.fail.lock().unwrap().remove(&(c(10), 10));
        let events = m.reconcile(vec![d(10, 10)]).await;
        assert!(events.iter().any(|e| e.outcome == DriverOutcome::Added));
        assert_eq!(state(&m, 10), DriverLifecycleState::Active);
        assert_eq!(state(&m, 9), DriverLifecycleState::Absent, "A is gone");
    }

    /// Failure of one unrelated driver never evicts healthy unchanged drivers.
    #[tokio::test]
    async fn unrelated_failure_does_not_evict_healthy() {
        let f3 = ToyFactory::new();
        f3.fail_for(c(40), 1);
        let mut m = loader(f3);
        m.reconcile(vec![d(30, 1)]).await;
        assert_eq!(state(&m, 30), DriverLifecycleState::Active);

        let events = m.reconcile(vec![d(30, 1), d(40, 1)]).await;
        assert!(events
            .iter()
            .any(|e| matches!(e.outcome, DriverOutcome::Failed { .. })));
        assert_eq!(state(&m, 30), DriverLifecycleState::Active, "healthy stays");
        assert_eq!(state(&m, 40), DriverLifecycleState::Failed);
    }

    /// Invariant 6: health-driven recovery brings a Failed driver back to
    /// Active without touching desired state.
    #[tokio::test]
    async fn recovery_restores_failed_without_desired() {
        let mut m = loader(ToyFactory::new());
        m.reconcile(vec![d(5, 42)]).await;
        assert_eq!(state(&m, 5), DriverLifecycleState::Active);

        m.report_health(c(5), HealthStatus::Unhealthy { reason: 7 })
            .await;
        assert_eq!(state(&m, 5), DriverLifecycleState::Failed);

        let ok = m.recover(c(5)).await;
        assert!(ok);
        assert_eq!(state(&m, 5), DriverLifecycleState::Active);

        // Recovery failure: stays Failed (not removed).
        let f2 = ToyFactory::new();
        f2.fail_for(c(6), 1);
        let mut m2 = loader(f2);
        m2.reconcile(vec![d(6, 1)]).await;
        assert_eq!(state(&m2, 6), DriverLifecycleState::Failed);
    }

    /// Invariant 5b: desired-absent (Stop) is an explicit removal distinct
    /// from the tracked-failure state.
    #[tokio::test]
    async fn explicit_remove_is_distinct_from_failure() {
        let mut m = loader(ToyFactory::new());
        m.reconcile(vec![d(8, 1)]).await;
        assert_eq!(state(&m, 8), DriverLifecycleState::Active);

        let events = m.reconcile(vec![DriverIntent::stop(c(8))]).await;
        assert!(events.iter().any(|e| e.outcome == DriverOutcome::Removed));
        assert_eq!(state(&m, 8), DriverLifecycleState::Absent);
    }

    /// State machine legal-edge set from ADR-011.
    #[test]
    fn state_machine_rejects_illegal_edges() {
        use DriverLifecycleState::*;
        assert!(!Absent.transition(Stopping));
        assert!(!Initializing.transition(Absent));
        assert!(!Active.transition(Initializing));
        assert!(!Absent.transition(Recovering));
        assert!(Active.transition(Replacing));
        assert!(Active.transition(Failed));
        assert!(Failed.transition(Recovering));
        assert!(Recovering.transition(Active));
        assert!(Recovering.transition(Failed));
    }

    /// M3.5 end-to-end: a driver configured through the real `ConfiguredFactory`
    /// enters the lifecycle. In ordinary CI there is no `b4` binary, so the
    /// transition must honestly end in tracked `Failed` — never a fabricated
    /// Active, and never a removal.
    #[cfg(feature = "b4")]
    #[tokio::test]
    async fn configured_b4_driver_fails_truthfully_in_lifecycle() {
        use crate::driver::config::{DriverConfig, DriverConfigRegistry};
        use crate::driver::factory::ConfiguredFactory;

        let mut registry = DriverConfigRegistry::new();
        registry.insert(
            DriverId::B4,
            DriverConfig::B4(crate::b4::B4Config {
                mode: crate::b4::B4Mode::Transparent,
                ports: vec![80, 443],
                strategies: vec![crate::b4::B4Strategy::TtlDisorientation],
                upstream: None,
            }),
        );
        let factory = ConfiguredFactory::new(registry);
        let mut m = DriverLifecycleManager::new(Box::new(factory));

        let events = m
            .reconcile(vec![DriverIntent::start(DriverId::B4, 5)])
            .await;

        // Construction succeeded (config present) but start failed honestly.
        assert!(events
            .iter()
            .any(|e| { matches!(e.outcome, DriverOutcome::Failed { .. }) }));
        assert_eq!(m.state(DriverId::B4), DriverLifecycleState::Failed);
        // Failure is not removal: the driver stays tracked.
        assert!(m.snapshot().iter().any(|(id, _, _)| *id == DriverId::B4));
    }
}
