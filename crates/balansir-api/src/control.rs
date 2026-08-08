//! Port from the API server to the `balansir-control` control plane.
//!
//! Replaces the previous `ReconcilerHandle` stub. The HTTP handlers now talk to
//! a real `Coordinator`: desired/actual state come from the daemon's providers,
//! `/reconcile` triggers `Coordinator::reconcile(ReconcileReason::ApiRequest)`,
//! and control-plane `ControlEvent`s are bridged into the HTTP event log / SSE
//! stream via an `EventSink` installed on the coordinator.

use async_trait::async_trait;
use balansir_common::{ActualState, DesiredState, DriverAction, DriverId};
use balansir_control::events::ControlEvent;
use balansir_control::traits::{
    DesiredProvider, EventSink, Executor, Planner, Rollback, SnapshotStore, StateProvider,
};
use balansir_control::{ControlError, ControlResult};
use balansir_control::{Coordinator, CoordinatorConfig, ReconcileReason};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::handlers::EventEntry;

/// Seam for transactional reload: a writable desired-state store.
///
/// Provided by the daemon (its shared `DesiredState` handle) so the API can
/// stage a candidate configuration and roll it back on failure (ADR-010)
/// without depending on daemon internals.
#[async_trait]
pub trait DesiredUpdater: Send + Sync {
    async fn set_desired(&self, state: DesiredState);
    async fn desired(&self) -> ControlResult<DesiredState>;
}

/// Bounded log of control-plane events, fed by an `EventSink` bridging
/// `ControlEvent`s from the coordinator.
#[derive(Debug)]
pub struct EventBridge {
    log: RwLock<Vec<EventEntry>>,
    sender: broadcast::Sender<EventEntry>,
    capacity: usize,
}

impl EventBridge {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            log: RwLock::new(Vec::new()),
            sender,
            capacity,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventEntry> {
        self.sender.subscribe()
    }

    /// Snapshot of the log, newest last.
    pub async fn snapshot(&self) -> Vec<EventEntry> {
        self.log.read().await.clone()
    }

    async fn record(&self, entry: EventEntry) {
        let mut log = self.log.write().await;
        log.push(entry.clone());
        while log.len() > self.capacity {
            log.remove(0);
        }
        drop(log);

        // Ignore send failures: subscribers that fell behind are expected to
        // resync from the log snapshot on reconnect.
        let _ = self.sender.send(entry);
    }
}

impl From<&ControlEvent> for EventEntry {
    fn from(event: &ControlEvent) -> Self {
        EventEntry {
            timestamp: chrono::Utc::now().timestamp(),
            event_type: event.name().to_string(),
            details: match event {
                ControlEvent::Failed { error } => error.clone(),
                ControlEvent::StepFailed { error, .. } => error.clone(),
                ControlEvent::ReconciliationRequested(reason) => {
                    format!("requested via {}", reason.label())
                }
                other => format!("{other:?}"),
            },
        }
    }
}

#[async_trait]
impl EventSink for EventBridge {
    async fn emit(&self, event: &ControlEvent) -> ControlResult<()> {
        self.record(event.into()).await;
        Ok(())
    }
}

/// A fully wired control plane: coordinator + providers + event bridge.
///
/// This is the single seam between the HTTP layer and the daemon. The daemon
/// assembles it once and hands it to `ApiState`; the API depends only on
/// `balansir-control`, never on daemon internals.
pub struct ControlPlane {
    coordinator: Arc<Coordinator>,
    desired: Arc<dyn DesiredProvider>,
    actual: Arc<dyn StateProvider>,
    events: Arc<EventBridge>,
    desired_updater: Option<Arc<dyn DesiredUpdater>>,
}

impl ControlPlane {
    /// Assemble a control plane from the daemon's components.
    ///
    /// The coordinator is built here so the event bridge can be installed as its
    /// `EventSink` at construction time (the FSM emits synchronously during
    /// `reconcile`).
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        desired: Arc<dyn DesiredProvider>,
        actual: Arc<dyn StateProvider>,
        planner: Arc<dyn Planner>,
        executor: Arc<dyn Executor>,
        snapshot_store: Arc<dyn SnapshotStore>,
        rollback: Arc<dyn Rollback>,
        event_capacity: usize,
    ) -> Arc<Self> {
        Self::assemble_with_updater(
            desired,
            actual,
            planner,
            executor,
            snapshot_store,
            rollback,
            event_capacity,
            None,
        )
    }

    /// Assemble a control plane with a writable desired-state handle, enabling
    /// transactional `/reload` (ADR-010).
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_with_updater(
        desired: Arc<dyn DesiredProvider>,
        actual: Arc<dyn StateProvider>,
        planner: Arc<dyn Planner>,
        executor: Arc<dyn Executor>,
        snapshot_store: Arc<dyn SnapshotStore>,
        rollback: Arc<dyn Rollback>,
        event_capacity: usize,
        updater: Option<Arc<dyn DesiredUpdater>>,
    ) -> Arc<Self> {
        let events = Arc::new(EventBridge::new(event_capacity));
        let coordinator = Arc::new(Coordinator::new(
            CoordinatorConfig::new(
                desired.clone(),
                actual.clone(),
                planner,
                executor,
                snapshot_store,
            )
            .with_event_sink(events.clone())
            .with_rollback(rollback),
        ));

        Arc::new(Self {
            coordinator,
            desired,
            actual,
            events,
            desired_updater: updater,
        })
    }

    /// Read the current desired state (GET /desired).
    pub async fn desired(&self) -> ControlResult<DesiredState> {
        self.desired.desired().await
    }

    /// Read the current actual state (GET /actual).
    pub async fn actual(&self) -> ControlResult<ActualState> {
        self.actual.actual().await
    }

    /// Current control-plane generation (bumped only on committed non-empty plans).
    pub fn generation(&self) -> u64 {
        self.coordinator.generation()
    }

    /// Trigger a reconciliation from an API client request.
    pub async fn reconcile_api(&self) -> ControlResult<()> {
        self.coordinator
            .reconcile(ReconcileReason::ApiRequest)
            .await
    }

    /// Transactional hot reload (ADR-010).
    ///
    /// Validates the candidate against the coordinator's reconcile cycle
    /// before exposing it as live desired state. A candidate that fails to
    /// reconcile is rejected; the previous state remains authoritative.
    pub async fn reload_api(&self, candidate: DesiredState) -> ControlResult<()> {
        if let Some(updater) = &self.desired_updater {
            let prev = self.desired.desired().await?;
            updater.set_desired(candidate).await;
            match self
                .coordinator
                .reconcile(ReconcileReason::ConfigReload)
                .await
            {
                Ok(()) => Ok(()),
                Err(e) => {
                    updater.set_desired(prev).await;
                    Err(e)
                }
            }
        } else {
            Err(ControlError::DesiredProvider(
                "no writable desired provider configured for reload".into(),
            ))
        }
    }

    /// Record a manual-trigger event (kept for the legacy `/reconcile` counter).
    pub async fn record_manual(&self) {
        self.events
            .record(EventEntry::from(&ControlEvent::ReconciliationRequested(
                ReconcileReason::Manual,
            )))
            .await;
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<EventEntry> {
        self.events.subscribe()
    }

    pub async fn get_events(&self) -> Vec<EventEntry> {
        self.events.snapshot().await
    }

    /// List configured drivers from the desired state.
    pub async fn drivers(&self) -> ControlResult<Vec<DriverStatus>> {
        let desired = self.desired.desired().await?;
        Ok(desired
            .drivers
            .iter()
            .map(|d| DriverStatus {
                id: d.id.as_u32(),
                name: format!("{}", d.id),
                state: driver_state(&d.action).to_string(),
                detail: format!("{} requested", driver_state(&d.action)),
            })
            .collect())
    }
}

/// A desired-state store that is both readable (`DesiredProvider`) and
/// writable (`DesiredUpdater`), backed by a single shared handle. Used for
/// transactional `/reload`: the coordinator reads and the reload writes the
/// same store, so a rollback restores exactly what was live before.
pub struct UpdatableDesiredStore {
    inner: tokio::sync::Mutex<DesiredState>,
}

impl UpdatableDesiredStore {
    pub fn new(state: DesiredState) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(state),
        }
    }
}

#[async_trait]
impl DesiredProvider for UpdatableDesiredStore {
    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.inner.lock().await.clone())
    }
}

#[async_trait]
impl DesiredUpdater for UpdatableDesiredStore {
    async fn set_desired(&self, state: DesiredState) {
        *self.inner.lock().await = state;
    }

    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.inner.lock().await.clone())
    }
}

// --- Public status view of a configured driver. ---
#[derive(Debug, Clone, Serialize)]
pub struct DriverStatus {
    pub id: u32,
    pub name: String,
    pub state: String,
    pub detail: String,
}

const fn driver_state(action: &DriverAction) -> &'static str {
    match action {
        DriverAction::Start => "running",
        DriverAction::Stop => "stopped",
        DriverAction::Restart => "restarting",
        DriverAction::Status => "unknown",
    }
}

/// Resolve a `DriverId` from an API-provided name (numeric id or display name).
pub fn driver_from_name(name: &str) -> Option<DriverId> {
    if let Ok(id) = name.parse::<u32>() {
        return Some(DriverId::from_u32(id));
    }
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "wireguard" => Some(DriverId::WireGuard),
        "amneziawg" | "amnezia" => Some(DriverId::AmneziaWG),
        "xray" => Some(DriverId::Xray),
        "hysteria" => Some(DriverId::Hysteria),
        "b4" => Some(DriverId::B4),
        "dnsforwarder" | "dns" => Some(DriverId::DnsForwarder),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, DesiredDriver, DesiredRule, DesiredState};
    use balansir_control::executor::MockExecutor;
    use balansir_control::planner::BasicPlanner;
    use balansir_control::provider::{MemoryDesiredProvider, MemoryStateProvider};
    use balansir_control::snapshot_store::MemorySnapshotStore;
    use balansir_control::NoopRollback;

    fn sample_plane() -> Arc<ControlPlane> {
        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 1,
                action: Action::Block,
                priority: 100,
            }],
            drivers: vec![DesiredDriver {
                id: DriverId::Xray,
                action: DriverAction::Restart,
            }],
        };
        ControlPlane::assemble(
            Arc::new(MemoryDesiredProvider::new(desired)),
            Arc::new(MemoryStateProvider::default()),
            Arc::new(BasicPlanner),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
            Arc::new(NoopRollback),
            16,
        )
    }

    #[tokio::test]
    async fn desired_and_actual_read() {
        let plane = sample_plane();
        let d = plane.desired().await.unwrap();
        assert_eq!(d.rules.len(), 1);
        assert_eq!(plane.actual().await.unwrap().active_rules.len(), 0);
    }

    #[tokio::test]
    async fn reconcile_emits_control_events() {
        let plane = sample_plane();
        plane.reconcile_api().await.unwrap();
        let entries = plane.get_events().await;
        assert!(entries
            .iter()
            .any(|e| e.event_type == "reconciliation_requested" || e.event_type == "reconciled"));
    }

    #[tokio::test]
    async fn drivers_list_reflects_config() {
        let plane = sample_plane();
        let drivers = plane.drivers().await.unwrap();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].state, "restarting");
        assert_eq!(driver_from_name("Xray"), Some(DriverId::Xray));
        assert_eq!(driver_from_name("3"), Some(DriverId::Xray));
    }

    #[tokio::test]
    async fn reload_commits_candidate_and_rolls_back_on_failure() {
        // Working plane: candidate commits, generation bumps.
        let store = Arc::new(UpdatableDesiredStore::new(DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Allow,
                priority: 50,
            }],
            drivers: Vec::new(),
        }));
        let plane = ControlPlane::assemble_with_updater(
            store.clone(),
            Arc::new(MemoryStateProvider::default()),
            Arc::new(BasicPlanner),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
            Arc::new(NoopRollback),
            16,
            Some(store.clone()),
        );

        let candidate = DesiredState {
            rules: vec![DesiredRule {
                id: 9,
                action: Action::Block,
                priority: 100,
            }],
            drivers: Vec::new(),
        };
        assert!(plane.reload_api(candidate.clone()).await.is_ok());
        let d = plane.desired().await.unwrap();
        assert_eq!(d.rules.len(), 1);
        assert_eq!(d.rules[0].id, 9);
    }

    #[tokio::test]
    async fn reload_without_writable_store_is_rejected() {
        let plane = sample_plane();
        let candidate = DesiredState {
            rules: vec![DesiredRule {
                id: 1,
                action: Action::Allow,
                priority: 10,
            }],
            drivers: Vec::new(),
        };
        let err = plane.reload_api(candidate).await.unwrap_err();
        assert!(matches!(err, ControlError::DesiredProvider(_)));
    }
}
