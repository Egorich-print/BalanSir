// crates/balansir-control/src/traits.rs

use crate::error::ControlResult;
use crate::state::ExecutionReport;
use async_trait::async_trait;
use balansir_common::{ActualState, DesiredState, ReconciliationPlan, Snapshot};
use std::sync::Arc;

/// Provides the desired (target) state of the system.
///
/// Concrete sources: config files, profiles, API overrides, plugins.
#[async_trait]
pub trait DesiredProvider: Send + Sync {
    async fn desired(&self) -> ControlResult<DesiredState>;
}

/// Provides the current (actual) state of the system.
///
/// Sources: local daemon, remote node, Kubernetes, SSH, simulator.
#[async_trait]
pub trait StateProvider: Send + Sync {
    async fn actual(&self) -> ControlResult<ActualState>;
}

/// Builds a reconciliation plan by diffing desired vs actual state.
///
/// Must be a pure/deterministic function: no side effects, no knowledge of
/// why the plan is built or what happens after execution.
pub trait Planner: Send + Sync {
    fn build_plan(
        &self,
        desired: &DesiredState,
        actual: &ActualState,
        generation: u64,
    ) -> ReconciliationPlan;
}

/// Executes a reconciliation plan. Only responsible for applying changes.
#[async_trait]
pub trait Executor: Send + Sync {
    async fn execute(&self, plan: &ReconciliationPlan) -> ControlResult<ExecutionReport>;
}

/// Persists and retrieves consistent snapshots for rollback/recovery.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    async fn load(&self, generation: u64) -> ControlResult<Option<Snapshot>>;
    async fn save(&self, snapshot: &Snapshot) -> ControlResult<()>;
}

/// Optional sink for control-plane events (for EventBus, HTTP/SSE, CLI watch,
/// metrics, tracing). Implementers are free to ignore events they don't care
/// about.
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, event: &crate::events::ControlEvent) -> ControlResult<()>;
}

/// Fans `emit` out to a set of attached sinks. Lets the daemon bridge
/// coordinator events into the API event bus after construction, without
/// rebuilding the coordinator with a different sink (one coordinator, one
/// event path — background loop and API-triggered reconciles both emit).
#[derive(Default)]
pub struct DynamicEventSink {
    inner: std::sync::Mutex<Vec<Arc<dyn EventSink>>>,
}

impl DynamicEventSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an additional sink (e.g. the API `EventBridge`).
    pub fn attach(&self, sink: Arc<dyn EventSink>) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).push(sink);
    }
}

#[async_trait]
impl EventSink for DynamicEventSink {
    async fn emit(&self, event: &crate::events::ControlEvent) -> ControlResult<()> {
        // Clone under the lock, emit outside it: a slow/failed sink must not
        // block other attaches, and the lock is never held across an await.
        let sinks = self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for sink in sinks {
            sink.emit(event).await?;
        }
        Ok(())
    }
}

/// No-op event sink for when no observability is wired in.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventSink;

#[async_trait]
impl EventSink for NoopEventSink {
    async fn emit(&self, _event: &crate::events::ControlEvent) -> ControlResult<()> {
        Ok(())
    }
}

/// Attempts to converge the system back to its previous snapshot when a
/// reconcile fails mid-execution.
///
/// The concrete implementation owns whatever state must be mutated to undo a
/// partially applied plan (in-memory store, external driver, etc.).
#[async_trait]
pub trait Rollback: Send + Sync {
    async fn rollback(&self, snapshot: &Snapshot) -> ControlResult<()>;
}

/// Default rollback: does nothing. Used when no recovery is actionable.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRollback;

#[async_trait]
impl Rollback for NoopRollback {
    async fn rollback(&self, _snapshot: &Snapshot) -> ControlResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::ControlEvent;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct CountingSink(Arc<AtomicUsize>);

    #[async_trait]
    impl EventSink for CountingSink {
        async fn emit(&self, _event: &ControlEvent) -> ControlResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A dynamic sink fans every event out to all attached sinks, including
    /// ones attached after construction (the daemon's API-bridge wiring).
    #[tokio::test]
    async fn dynamic_sink_fans_out_to_attached_sinks() {
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let sink = DynamicEventSink::new();
        sink.attach(Arc::new(CountingSink(Arc::clone(&first))));

        let event = ControlEvent::ReconciliationRequested(crate::ReconcileReason::Scheduled);
        sink.emit(&event).await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 1);

        // Attach after construction; the next emit reaches both.
        sink.attach(Arc::new(CountingSink(Arc::clone(&second))));
        sink.emit(&event).await.unwrap();
        assert_eq!(first.load(Ordering::SeqCst), 2);
        assert_eq!(second.load(Ordering::SeqCst), 1);
    }
}
