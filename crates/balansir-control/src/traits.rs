// crates/balansir-control/src/traits.rs

use crate::error::ControlResult;
use crate::state::ExecutionReport;
use async_trait::async_trait;
use balansir_common::{ActualState, DesiredState, ReconciliationPlan, Snapshot};

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

/// No-op event sink for when no observability is wired in.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventSink;

#[async_trait]
impl EventSink for NoopEventSink {
    async fn emit(&self, _event: &crate::events::ControlEvent) -> ControlResult<()> {
        Ok(())
    }
}
